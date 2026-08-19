from tap import install


def test_set_sshd_option_replaces_commented():
    text = "# PermitRootLogin without-password\nPort 22\n"
    out = install.set_sshd_option(text, "PermitRootLogin", "no")
    assert "PermitRootLogin no" in out
    assert "without-password" not in out


def test_set_sshd_option_replaces_active():
    text = "PermitRootLogin yes\n"
    out = install.set_sshd_option(text, "PermitRootLogin", "no")
    assert out.count("PermitRootLogin") == 1
    assert "PermitRootLogin no" in out


def test_set_sshd_option_appends_when_absent():
    out = install.set_sshd_option("Port 22\n", "PermitTunnel", "point-to-point")
    assert "PermitTunnel point-to-point" in out


def test_render_service_substitutes_binary():
    out = install.render_service("/usr/local/bin/tap")
    assert "__TAP_BIN__" not in out
    assert "ExecStart=/usr/local/bin/tap run" in out


def test_proxychains_conf_has_socks_line():
    out = install.proxychains_conf("10004")
    assert "socks5 127.0.0.1 10004" in out
    assert "strict_chain" in out
