from __future__ import annotations

import subprocess

from tap import diagnostics
from tap.config import TapConfig


def _completed(
    stdout: str = "", returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_report_severity_and_json():
    report = diagnostics.DiagnosticReport(
        "status",
        [diagnostics.CheckResult("one", "One", diagnostics.Severity.PASS, "good")],
    )
    assert report.exit_code == 0
    assert '"overall": "pass"' in diagnostics.render_json(report)
    assert "TAP status: HEALTHY" in diagnostics.render_human(report)


def test_report_failure_takes_precedence():
    report = diagnostics.DiagnosticReport(
        "doctor",
        [
            diagnostics.CheckResult("one", "One", diagnostics.Severity.WARN, "warning"),
            diagnostics.CheckResult("two", "Two", diagnostics.Severity.FAIL, "broken"),
        ],
    )
    assert report.severity is diagnostics.Severity.FAIL
    assert report.exit_code == 2


def test_config_checks_reject_invalid_port(tmp_path, monkeypatch):
    path = tmp_path / "config"
    TapConfig(ipaddr="gateway", port="not-a-port").save(path)
    monkeypatch.setattr(diagnostics, "CONFIG_PATH", path)
    checks, cfg = diagnostics._config_checks()
    assert cfg is not None
    assert (
        next(check for check in checks if check.check_id == "config.values").severity
        is diagnostics.Severity.FAIL
    )


def test_service_check_parses_active_service(monkeypatch):
    monkeypatch.setattr(
        diagnostics,
        "_run",
        lambda *_args, **_kwargs: _completed(
            "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n"
            "MainPID=42\nExecMainStatus=0\nNRestarts=1\n"
        ),
    )
    check, values = diagnostics._service_check(1)
    assert check.severity is diagnostics.Severity.PASS
    assert values is not None and values["MainPID"] == "42"


def test_gateway_dns_failure(monkeypatch):
    def fail(*_args, **_kwargs):
        raise OSError("no dns")

    monkeypatch.setattr(diagnostics.socket, "getaddrinfo", fail)
    check = diagnostics._gateway_dns_check(TapConfig(ipaddr="missing.example"), 1)
    assert check.severity is diagnostics.Severity.FAIL
    assert check.check_id == "gateway.dns"


def test_known_host_uses_nonstandard_port(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("entry")
    monkeypatch.setattr(diagnostics, "KNOWN_HOSTS", known_hosts)
    calls: list[list[str]] = []

    def run(command, **_kwargs):
        calls.append(command)
        return _completed("entry")

    monkeypatch.setattr(diagnostics, "_run", run)
    check = diagnostics._known_host_check(TapConfig(ipaddr="gateway", port="2222"), 1)
    assert check.severity is diagnostics.Severity.PASS
    assert "[gateway]:2222" in calls[0]
