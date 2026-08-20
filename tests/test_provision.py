from __future__ import annotations

import json
from pathlib import Path

import pytest

from tap import cli, install, provision


def _write_spec(tmp_path: Path, *, key_mode: str = "existing", start_service: str = "true") -> Path:
    private = tmp_path / "tap-key"
    public = tmp_path / "tap-key.pub"
    if key_mode == "existing":
        private.write_text("private")
        public.write_text("public")
    path = tmp_path / "tap.toml"
    path.write_text(
        f"""schema_version = 1

[connection]
host = "gateway.example"
username = "tap"
remote_port = 10003
socks_port = 10004

[ssh]
key_mode = "{key_mode}"
private_key = "{private}"
public_key = "{public}"
public_key_preinstalled = {str(key_mode == "existing").lower()}

[installation]
start_service = {start_service}
"""
    )
    return path


def test_loads_existing_key_spec(tmp_path):
    spec = provision.load(_write_spec(tmp_path))
    assert spec.config.ipaddr == "gateway.example"
    assert spec.config.identity_file == str(tmp_path / "tap-key")
    assert provision.validate(spec) == []
    rendered = provision.render(spec)
    assert rendered["ssh"]["private_key"] == str(tmp_path / "tap-key")
    assert "command_hmac_key" not in json.dumps(rendered)


def test_rejects_unknown_key(tmp_path):
    path = _write_spec(tmp_path)
    path.write_text(path.read_text() + "\n[unexpected]\nvalue = true\n")
    with pytest.raises(provision.ProvisionError, match="unknown key"):
        provision.load(path)


def test_command_url_requires_hmac_key(tmp_path):
    path = _write_spec(tmp_path)
    path.write_text(path.read_text() + '\n[commands]\nurl = "https://control.example/commands"\n')
    spec = provision.load(path)
    assert "commands.url requires hmac_key_file or hmac_key_env" in provision.validate(spec)


def test_generate_key_requires_no_service_start(tmp_path):
    spec = provision.load(_write_spec(tmp_path, key_mode="generate", start_service="true"))
    assert "generated keys require installation.start_service=false" in provision.validate(spec)


def test_dry_run_makes_no_system_changes(tmp_path):
    spec = provision.load(_write_spec(tmp_path))
    results = install.install_noninteractive(spec, dry_run=True)
    assert all(result.status in {"planned", "skipped", "unchanged"} for result in results)
    assert (tmp_path / "tap-key").read_text() == "private"


def test_cli_install_dry_run_json(tmp_path, capsys):
    path = _write_spec(tmp_path)
    assert (
        cli.main(["install", "--config", str(path), "--non-interactive", "--dry-run", "--json"])
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["result"] == "planned"
    assert payload["operations"][0]["operation"] == "packages"


def test_cli_config_validate_json(tmp_path, capsys):
    path = _write_spec(tmp_path)
    assert cli.main(["config", "validate", str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["result"] == "valid"
