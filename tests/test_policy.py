from app.policy import evaluate_policy


GLOBAL_POLICIES = [
    {
        "name": "allow-df-h",
        "command": "df",
        "allowedArgv": [["-h"]],
    },
    {
        "name": "allow-uptime",
        "command": "uptime",
        "allowedArgv": [[]],
    },
]


SERVER_CFG = {
    "sshHost": "lifeorient",
    "policies": [
        {
            "name": "allow-ls-paths",
            "command": "ls",
            "allowedFlags": [
                "-l",
                "-a",
                "-h",
                "-la",
                "-al",
                "-lh",
                "-hl",
                "-lah",
                "-lha",
                "-alh",
                "-ahl",
            ],
            "flagsPosition": "anywhere",
            "pathArgs": {
                "min": 0,
                "max": 2,
                "allowAbsolute": True,
                "allowRelative": True,
                "allowGlobs": False,
                "allowParentTraversal": False,
                "denyPrefixes": [
                    "/root/.ssh",
                    "/proc",
                    "/sys",
                    "/dev",
                ],
                "denyRegex": [
                    "^/etc/shadow$",
                ],
            },
        },
        {
            "name": "allow-kubectl-get-basic",
            "command": "kubectl",
            "subcommands": ["get"],
            "resources": [
                "pods",
                "pod",
                "deployments",
                "deployment",
                "services",
                "service",
                "nodes",
                "node",
                "events",
                "namespaces",
                "namespace",
            ],
            "allowNamespaces": ["*"],
        },
    ],
}


def check(argv):
    return evaluate_policy(
        server_cfg=SERVER_CFG,
        global_policies=GLOBAL_POLICIES,
        argv=argv,
    )


def test_allowed_df_h():
    decision = check(["df", "-h"])
    assert decision.allowed is True
    assert decision.policy == "allow-df-h"


def test_denied_df_i():
    decision = check(["df", "-i"])
    assert decision.allowed is False


def test_allowed_uptime():
    decision = check(["uptime"])
    assert decision.allowed is True


def test_denied_rm():
    decision = check(["rm", "-rf", "/"])
    assert decision.allowed is False


def test_allowed_ls_tmp():
    decision = check(["ls", "-la", "/tmp"])
    assert decision.allowed is True


def test_allowed_ls_tmp_flag_after_path():
    decision = check(["ls", "/tmp", "-la"])
    assert decision.allowed is True


def test_denied_ls_recursive_root():
    decision = check(["ls", "-R", "/"])
    assert decision.allowed is False


def test_denied_ls_root_ssh():
    decision = check(["ls", "-la", "/root/.ssh"])
    assert decision.allowed is False


def test_denied_ls_proc():
    decision = check(["ls", "/proc"])
    assert decision.allowed is False


def test_denied_ls_glob():
    decision = check(["ls", "/*"])
    assert decision.allowed is False


def test_denied_ls_parent_traversal():
    decision = check(["ls", "/tmp/../root"])
    assert decision.allowed is False


def test_allowed_kubectl_get_pods():
    decision = check(["kubectl", "get", "pods"])
    assert decision.allowed is True


def test_allowed_kubectl_get_pods_namespace():
    decision = check(["kubectl", "get", "pods", "-n", "default"])
    assert decision.allowed is True


def test_denied_kubectl_delete_pod():
    decision = check(["kubectl", "delete", "pod", "abc"])
    assert decision.allowed is False


def test_denied_kubectl_exec():
    decision = check(["kubectl", "exec", "pod-1", "--", "sh"])
    assert decision.allowed is False


def test_denied_kubectl_get_secret():
    decision = check(["kubectl", "get", "secret"])
    assert decision.allowed is False


def test_denied_shell():
    decision = check(["bash", "-c", "rm -rf /"])
    assert decision.allowed is False


def test_denied_sudo():
    decision = check(["sudo", "whoami"])
    assert decision.allowed is False
def test_forbidden_commands_are_denied():
    forbidden = [
        ["rm", "-rf", "/"],
        ["kill", "-9", "1"],
        ["sudo", "whoami"],
        ["bash", "-c", "id"],
        ["sh", "-c", "id"],
        ["kubectl", "delete", "pod", "abc"],
        ["kubectl", "exec", "pod-1", "--", "sh"],
        ["kubectl", "get", "secret"],
    ]

    for argv in forbidden:
        decision = check(argv)
        assert decision.allowed is False, f"must be denied: {argv}"