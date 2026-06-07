from __future__ import annotations

import re
import posixpath
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class PolicyDecision:
    allowed: bool
    policy: Optional[str]
    reason: str


# ---------------------------------------------------------------------
# Policy helpers: paths
# ---------------------------------------------------------------------

def normalize_policy_path(path: str) -> str:
    """
    Нормализуем путь для проверки политик.

    Примеры:
      /tmp/../root -> /root
      /tmp//a      -> /tmp/a
      ./abc        -> abc

    Важно:
    Это НЕ resolve symlinks на удалённом сервере.
    Для MVP нормально, но для строгой безопасности symlink bypass надо учитывать отдельно.
    """
    return posixpath.normpath(path)


def path_is_under(path: str, prefix: str) -> bool:
    path_norm = normalize_policy_path(path)
    prefix_norm = normalize_policy_path(prefix)

    if prefix_norm == "/":
        return path_norm.startswith("/")

    return path_norm == prefix_norm or path_norm.startswith(prefix_norm.rstrip("/") + "/")


def contains_parent_traversal(path: str) -> bool:
    parts = [p for p in path.split("/") if p not in ("", ".")]
    return ".." in parts


def validate_path_arg(path: str, path_cfg: Dict[str, Any]) -> tuple[bool, str]:
    if path == "":
        return False, "empty path is not allowed"

    if "\x00" in path or "\n" in path or "\r" in path:
        return False, "path contains forbidden control characters"

    # Чтобы путь не был случайно интерпретирован командой как опция.
    # Например:
    #   ls -- -file
    # технически возможно, но для MVP запрещаем path-аргументы, начинающиеся с "-".
    if path.startswith("-"):
        return False, "path starting with '-' is not allowed"

    allow_parent_traversal = bool(path_cfg.get("allowParentTraversal", False))

    if not allow_parent_traversal and contains_parent_traversal(path):
        return False, "parent traversal '..' is not allowed"

    allow_globs = bool(path_cfg.get("allowGlobs", False))

    if not allow_globs:
        for ch in ["*", "?", "[", "]", "{", "}"]:
            if ch in path:
                return False, "glob characters are not allowed in path"

    is_absolute = path.startswith("/")

    allow_absolute = bool(path_cfg.get("allowAbsolute", False))
    allow_relative = bool(path_cfg.get("allowRelative", True))

    if is_absolute and not allow_absolute:
        return False, "absolute paths are not allowed"

    if not is_absolute and not allow_relative:
        return False, "relative paths are not allowed"

    path_norm = normalize_policy_path(path)

    # 1. denyPrefixes имеют высокий приоритет
    deny_prefixes = path_cfg.get("denyPrefixes") or []

    for prefix in deny_prefixes:
        if path_is_under(path_norm, prefix):
            return False, f"path '{path}' is denied by prefix '{prefix}'"

    # 2. denyRegex тоже имеет высокий приоритет
    deny_regex = path_cfg.get("denyRegex") or []

    for pattern in deny_regex:
        if re.fullmatch(pattern, path_norm):
            return False, f"path '{path}' is denied by denyRegex '{pattern}'"

    # 3. allowPrefixes, если заданы, требуют попадания хотя бы в один prefix
    allow_prefixes = path_cfg.get("allowPrefixes") or []

    if allow_prefixes:
        matched = any(path_is_under(path_norm, prefix) for prefix in allow_prefixes)

        if not matched:
            return False, f"path '{path}' is not under allowed prefixes"

    # 4. allowRegex, если заданы, требуют совпадения хотя бы с одним pattern
    allow_regex = path_cfg.get("allowRegex") or []

    if allow_regex:
        matched = any(re.fullmatch(pattern, path_norm) for pattern in allow_regex)

        if not matched:
            return False, f"path '{path}' does not match allowRegex"

    return True, "path is allowed"


# ---------------------------------------------------------------------
# Policy helpers: linux args
# ---------------------------------------------------------------------

def match_linux_args_policy(rule: Dict[str, Any], args: List[str]) -> tuple[bool, str]:
    """
    Универсальная MVP-политика для простых Linux-команд.

    Пример:

      - name: allow-ls-paths
        command: ls
        allowedFlags:
          - "-la"
          - "-lh"
        flagsPosition: anywhere
        pathArgs:
          min: 0
          max: 2
          allowAbsolute: true
          allowRelative: true
          allowGlobs: false
          allowRegex:
            - "^/tmp(/.*)?$"
          denyRegex:
            - "^/root(/.*)?$"

    flagsPosition:
      anywhere     - флаги можно до и после путей: ls /tmp -la
      beforePaths  - флаги только до первого path arg: ls -la /tmp
    """

    allowed_flags = set(rule.get("allowedFlags") or [])
    flags_position = rule.get("flagsPosition", "anywhere")

    if flags_position not in ("anywhere", "beforePaths"):
        return False, f"invalid flagsPosition: {flags_position}"

    path_cfg = rule.get("pathArgs") or {}

    min_paths = int(path_cfg.get("min", 0))
    max_paths = int(path_cfg.get("max", 0))

    flags: List[str] = []
    paths: List[str] = []

    end_of_options = False
    seen_path = False

    for arg in args:
        if arg == "--":
            end_of_options = True
            continue

        is_option_like = arg.startswith("-")

        if not end_of_options and is_option_like:
            if flags_position == "beforePaths" and seen_path:
                return False, f"flag '{arg}' after path is not allowed"

            if arg not in allowed_flags:
                return False, f"flag '{arg}' is not allowed"

            flags.append(arg)
            continue

        paths.append(arg)
        seen_path = True

    if len(paths) < min_paths:
        return False, f"too few path arguments: min={min_paths}"

    if len(paths) > max_paths:
        return False, f"too many path arguments: max={max_paths}"

    for path in paths:
        ok, reason = validate_path_arg(path, path_cfg)

        if not ok:
            return False, reason

    return True, "matched linux args policy"


# ---------------------------------------------------------------------
# Policy helpers: kubectl
# ---------------------------------------------------------------------

def normalize_resource(resource: str) -> str:
    """
    kubectl resource может быть:
      pods
      pod
      pod/my-pod
      deployments.apps

    Для MVP делаем простую нормализацию:
      pod/my-pod -> pod
      deployments.apps -> deployments
    """
    resource = resource.strip().lower()

    if "/" in resource:
        resource = resource.split("/", 1)[0]

    if "." in resource:
        resource = resource.split(".", 1)[0]

    return resource


def parse_kubectl_namespace(args: List[str]) -> tuple[Optional[str], bool]:
    namespace = None
    all_namespaces = False

    i = 0

    while i < len(args):
        arg = args[i]

        if arg in ("-A", "--all-namespaces"):
            all_namespaces = True

        elif arg in ("-n", "--namespace"):
            if i + 1 < len(args):
                namespace = args[i + 1]
                i += 1

        elif arg.startswith("--namespace="):
            namespace = arg.split("=", 1)[1]

        i += 1

    return namespace, all_namespaces


def match_kubectl_policy(rule: Dict[str, Any], argv: List[str]) -> tuple[bool, str]:
    """
    MVP-парсер kubectl.

    Поддерживаем простой формат:

      kubectl get pods
      kubectl get pods -n default
      kubectl get pods -A
      kubectl get services

    Пока НЕ поддерживаем формат:

      kubectl -n default get pods

    Это можно добавить позже.
    """

    if len(argv) < 2:
        return False, "kubectl subcommand is required"

    subcommand = argv[1]

    allowed_subcommands = rule.get("subcommands")

    if allowed_subcommands and subcommand not in allowed_subcommands:
        return False, f"kubectl subcommand '{subcommand}' is not allowed by this rule"

    allowed_resources = rule.get("resources")

    if allowed_resources:
        if len(argv) < 3:
            return False, "kubectl resource is required"

        resource = normalize_resource(argv[2])
        allowed_resources_normalized = [
            normalize_resource(r) for r in allowed_resources
        ]

        if resource not in allowed_resources_normalized:
            return False, f"kubectl resource '{resource}' is not allowed"

    allowed_namespaces = rule.get("allowNamespaces")

    if allowed_namespaces:
        namespace, all_namespaces = parse_kubectl_namespace(argv[3:])

        if "*" not in allowed_namespaces:
            if all_namespaces:
                return False, "all namespaces are not allowed"

            if namespace and namespace not in allowed_namespaces:
                return False, f"namespace '{namespace}' is not allowed"

    return True, "matched kubectl policy"


# ---------------------------------------------------------------------
# Effective policies
# ---------------------------------------------------------------------

def get_effective_policies(
    server_cfg: Dict[str, Any],
    global_policies: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Возвращает политики, применимые к серверу.

    Порядок:
      1. globalPolicies
      2. server-specific policies

    Сервер может отключить глобальные политики:

      disableGlobalPolicies: true

    Или отключить отдельные глобальные политики:

      disabledGlobalPolicies:
        - allow-df-h
    """

    result: List[Dict[str, Any]] = []

    disable_global = bool(server_cfg.get("disableGlobalPolicies", False))
    disabled_global_names = set(server_cfg.get("disabledGlobalPolicies") or [])

    if not disable_global:
        for policy in global_policies:
            name = policy.get("name")

            if name in disabled_global_names:
                continue

            result.append(policy)

    result.extend(server_cfg.get("policies", []) or [])

    return result


# ---------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------

def evaluate_policy(
    server_cfg: Dict[str, Any],
    global_policies: List[Dict[str, Any]],
    argv: List[str],
) -> PolicyDecision:
    """
    Главная функция проверки политики.

    Возвращает:
      PolicyDecision(allowed=True/False, policy=..., reason=...)

    Принцип:
      deny by default
    """

    if not argv:
        return PolicyDecision(
            allowed=False,
            policy=None,
            reason="empty command",
        )

    command = argv[0]
    args = argv[1:]

    policies = get_effective_policies(server_cfg, global_policies)

    command_policy_seen = False
    last_denial_reason = "command is not allowed by policy"

    for rule in policies:
        rule_name = rule.get("name", "<unnamed-policy>")
        rule_command = rule.get("command")

        if rule_command != command:
            continue

        command_policy_seen = True

        # 1. Exact argv policy
        #
        # Пример:
        #
        # command: df
        # allowedArgv:
        #   - ["-h"]
        #
        # Разрешит только:
        #   df -h
        #
        if "allowedArgv" in rule:
            allowed_argv_variants = rule.get("allowedArgv") or []

            for allowed_args in allowed_argv_variants:
                if args == allowed_args:
                    return PolicyDecision(
                        allowed=True,
                        policy=rule_name,
                        reason="matched exact argv policy",
                    )

            last_denial_reason = f"argv is not allowed by policy '{rule_name}'"
            continue

        # 2. Linux args policy: allowedFlags + pathArgs
        if "allowedFlags" in rule or "pathArgs" in rule:
            matched, reason = match_linux_args_policy(rule, args)

            if matched:
                return PolicyDecision(
                    allowed=True,
                    policy=rule_name,
                    reason=reason,
                )

            last_denial_reason = reason
            continue

        # 3. kubectl policy
        if command == "kubectl":
            matched, reason = match_kubectl_policy(rule, argv)

            if matched:
                return PolicyDecision(
                    allowed=True,
                    policy=rule_name,
                    reason=reason,
                )

            last_denial_reason = reason
            continue

        last_denial_reason = f"policy '{rule_name}' has unsupported policy format"

    if command_policy_seen:
        return PolicyDecision(
            allowed=False,
            policy=None,
            reason=last_denial_reason,
        )

    return PolicyDecision(
        allowed=False,
        policy=None,
        reason="command is not allowed by policy",
    )