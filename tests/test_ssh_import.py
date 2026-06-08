from app.bootstrap.ssh_import import _parse_ssh_config


def test_parse_ssh_config_after_marker_with_proxy_command_and_proxy_jump():
    content = """
Host before.marker
    Hostname 10.0.0.1

### START FLINT ###
Host team-alfa.demo-gitlab-runner
    Hostname 10.10.10.10
    User ubuntu
    ProxyCommand ssh team-alfa.demo-master-0 -W %h:%p -l %r

Host omnidesk.gitlab
    Hostname 172.21.22.47
    ProxyJump user@omnidesk.sel-hv-03
"""

    records = _parse_ssh_config(content, marker="### START FLINT ###")

    assert records == [
        {
            "alias": "team-alfa.demo-gitlab-runner",
            "hostname": "10.10.10.10",
            "user": "ubuntu",
            "proxy_alias": "team-alfa.demo-master-0",
        },
        {
            "alias": "omnidesk.gitlab",
            "hostname": "172.21.22.47",
            "user": None,
            "proxy_alias": "omnidesk.sel-hv-03",
        },
    ]
