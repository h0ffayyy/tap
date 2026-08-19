from tap import ssh
from tap.config import TapConfig


def _cfg(**kw):
    base = {
        "ipaddr": "203.0.113.5",
        "port": "2222",
        "username": "tap",
        "local_port": "10003",
        "socks_proxy_port": "10004",
    }
    base.update(kw)
    return TapConfig(**base)


def test_tunnel_command_is_key_only_batchmode():
    cmd = ssh.tunnel_command(_cfg())
    assert cmd[0] == "ssh"
    assert "-N" in cmd
    # never prompts: batch mode + identity file, no password anywhere
    assert "BatchMode=yes" in cmd
    assert "-i" in cmd and str(ssh.PRIVATE_KEY) in cmd
    assert "StrictHostKeyChecking=accept-new" in cmd


def test_tunnel_command_reverse_and_socks():
    cmd = ssh.tunnel_command(_cfg())
    assert "-R" in cmd
    assert "127.0.0.1:10003:127.0.0.1:22" in cmd
    assert "-D" in cmd
    assert "127.0.0.1:10004" in cmd
    assert "tap@203.0.113.5" in cmd
    assert cmd[-2:] == ["-p", "2222"]


def test_tunnel_command_omits_socks_when_unset():
    cmd = ssh.tunnel_command(_cfg(socks_proxy_port=""))
    assert "-D" not in cmd
    assert "-R" in cmd


def test_tunnel_command_is_arg_list_not_shell_string():
    # list form => no shell => nothing to inject into
    cmd = ssh.tunnel_command(_cfg())
    assert isinstance(cmd, list)
    assert all(isinstance(part, str) for part in cmd)
