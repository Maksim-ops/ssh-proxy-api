import os
import yaml
import pytest

from app.policy import evaluate_policy


CONFIG_PATH = os.getenv("PCTL_CONFIG", "config/config.dev.yml")
TEST_SERVER = os.getenv("PCTL_TEST_SERVER", "lifeorient")


def load_test_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@pytest.fixture(scope="session")
def config():
    return load_test_config()


@pytest.fixture(scope="session")
def server_cfg(config):
    servers = config.get("servers", {})

    assert TEST_SERVER in servers, (
        f"Test server '{TEST_SERVER}' not found in config '{CONFIG_PATH}'. "
        f"Available servers: {list(servers.keys())}"
    )

    return servers[TEST_SERVER]


@pytest.fixture(scope="session")
def global_policies(config):
    return config.get("globalPolicies", []) or []


def check(server_cfg, global_policies, argv):
    return evaluate_policy(
        server_cfg=server_cfg,
        global_policies=global_policies,
        argv=argv,
    )


ALWAYS_FORBIDDEN = [
    ["rm", "-rf", "/"],
    ["rm", "-f", "test.txt"],
    ["kill", "-9", "1"],
    ["pkill", "-f", "python"],
    ["killall", "python"],
    ["sudo", "whoami"],
    ["su", "-"],
    ["bash", "-c", "id"],
    ["sh", "-c", "id"],
    ["python", "-c", "print(1)"],
    ["python3", "-c", "print(1)"],
    ["perl", "-e", "print 1"],
    ["nc", "-l", "1234"],
    ["socat", "-", "-"],
    ["curl", "http://example.com"],
    ["wget", "http://example.com"],
    ["chmod", "777", "/tmp/x"],
    ["chown", "root", "/tmp/x"],
    ["systemctl", "restart", "ssh"],
    ["service", "ssh", "restart"],
    ["reboot"],
    ["shutdown", "-h", "now"],

    # kubectl dangerous
    ["kubectl", "delete", "pod", "abc"],
    ["kubectl", "delete", "ns", "default"],
    ["kubectl", "apply", "-f", "x.yaml"],
    ["kubectl", "patch", "deployment", "x"],
    ["kubectl", "edit", "deployment", "x"],
    ["kubectl", "exec", "pod-1", "--", "sh"],
    ["kubectl", "exec", "pod-1", "--", "bash"],
    ["kubectl", "cp", "pod:/etc/passwd", "/tmp/passwd"],
    ["kubectl", "port-forward", "pod/x", "8080:80"],
    ["kubectl", "proxy"],
    ["kubectl", "get", "secret"],
    ["kubectl", "get", "secrets"],
    ["kubectl", "describe", "secret", "x"],
]


@pytest.mark.parametrize("argv", ALWAYS_FORBIDDEN)
def test_always_forbidden_commands_are_denied(server_cfg, global_policies, argv):
    decision = check(server_cfg, global_policies, argv)

    assert decision.allowed is False, (
        f"Command must stay forbidden but was allowed: {argv}. "
        f"Matched policy: {decision.policy}. Reason: {decision.reason}"
    )


EXPECTED_ALLOWED = [
    ["df", "-h"],
    ["uptime"],
    ["whoami"],
    ["ls"],
    ["ls", "-la"],
    ["ls", "-la", "/tmp"],
]


@pytest.mark.parametrize("argv", EXPECTED_ALLOWED)
def test_expected_allowed_commands_are_allowed(server_cfg, global_policies, argv):
    decision = check(server_cfg, global_policies, argv)

    assert decision.allowed is True, (
        f"Command expected to be allowed but was denied: {argv}. "
        f"Reason: {decision.reason}"
    )


def test_ls_recursive_root_is_denied(server_cfg, global_policies):
    decision = check(server_cfg, global_policies, ["ls", "-R", "/"])
    assert decision.allowed is False


def test_ls_root_ssh_is_denied(server_cfg, global_policies):
    decision = check(server_cfg, global_policies, ["ls", "-la", "/root/.ssh"])
    assert decision.allowed is False


def test_ls_proc_is_denied(server_cfg, global_policies):
    decision = check(server_cfg, global_policies, ["ls", "/proc"])
    assert decision.allowed is False


def test_ls_glob_is_denied(server_cfg, global_policies):
    decision = check(server_cfg, global_policies, ["ls", "/*"])
    assert decision.allowed is False


def test_ls_parent_traversal_is_denied(server_cfg, global_policies):
    decision = check(server_cfg, global_policies, ["ls", "/tmp/../root"])
    assert decision.allowed is False