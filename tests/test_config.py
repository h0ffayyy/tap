from tap.config import TapConfig, _parse_lines


def test_parse_lines_ignores_comments_and_blanks():
    text = "# comment\n\nUSERNAME=alice\nPORT=2222\n"
    assert _parse_lines(text) == {"USERNAME": "alice", "PORT": "2222"}


def test_parse_strips_quotes_and_whitespace():
    assert _parse_lines('IPADDR="1.2.3.4" \n')["IPADDR"] == "1.2.3.4"


def test_roundtrip_load_save(tmp_path):
    cfg = TapConfig(
        username="tapuser",
        ipaddr="10.0.0.5",
        port="2222",
        local_port="10003",
        ssh_keys="OFF",
        password="ENCRYPTEDBLOB==",
    )
    path = tmp_path / "config"
    cfg.save(path)
    loaded = TapConfig.load(path)
    assert loaded.username == "tapuser"
    assert loaded.ipaddr == "10.0.0.5"
    assert loaded.port == "2222"
    assert loaded.ssh_keys == "OFF"
    assert loaded.password == "ENCRYPTEDBLOB=="


def test_typed_accessors():
    cfg = TapConfig(ssh_keys="on", ssh_check_interval="90", auto_update="ON")
    assert cfg.use_ssh_keys is True
    assert cfg.check_interval == 90
    assert cfg.auto_update_enabled is True


def test_check_interval_falls_back_on_bad_value():
    assert TapConfig(ssh_check_interval="not-a-number").check_interval == 60


def test_saved_file_is_root_only(tmp_path):
    path = tmp_path / "config"
    TapConfig().save(path)
    assert (path.stat().st_mode & 0o777) == 0o600
