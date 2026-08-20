"""Read-only operational diagnostics for TAP.

``tap status`` is intentionally local and fast. ``tap doctor`` builds on it
with bounded network and SSH checks.  The implementation has no installer or
daemon side effects and keeps all command execution behind small helpers so it
can be tested without a running systemd host.
"""

from __future__ import annotations

import errno
import json
import os
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from tap import __version__
from tap.config import CONFIG_PATH, TapConfig
from tap.runtime import STATE_PATH, load_state
from tap.ssh import PRIVATE_KEY, private_key

SERVICE_NAME = "tap.service"
KNOWN_HOSTS = Path("/root/.ssh/known_hosts")


class Severity(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class CheckResult:
    """One stable, safe-to-serialize diagnostic result."""

    check_id: str
    label: str
    severity: Severity
    summary: str
    remediation: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


@dataclass(frozen=True)
class DiagnosticReport:
    command: str
    checks: list[CheckResult]

    @property
    def severity(self) -> Severity:
        severities = {check.severity for check in self.checks}
        if Severity.FAIL in severities:
            return Severity.FAIL
        if Severity.WARN in severities or Severity.SKIP in severities:
            return Severity.WARN
        return Severity.PASS

    @property
    def exit_code(self) -> int:
        return {Severity.PASS: 0, Severity.WARN: 1, Severity.FAIL: 2}[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "tap_version": __version__,
            "command": self.command,
            "overall": self.severity.value,
            "exit_code": self.exit_code,
            "checks": [
                {**asdict(check), "severity": check.severity.value} for check in self.checks
            ],
        }


def _result(
    check_id: str,
    label: str,
    severity: Severity,
    summary: str,
    *,
    remediation: str | None = None,
    details: dict[str, Any] | None = None,
    started: float | None = None,
) -> CheckResult:
    duration = int((time.monotonic() - started) * 1000) if started is not None else 0
    return CheckResult(check_id, label, severity, summary, remediation, details or {}, duration)


def _run(command: list[str], timeout: float = 5) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)


def _service_properties(timeout: float) -> tuple[dict[str, str] | None, str | None]:
    try:
        result = _run(
            [
                "systemctl",
                "show",
                SERVICE_NAME,
                "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStatus,NRestarts",
            ],
            timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if result.returncode != 0:
        return None, (result.stderr.strip() or "systemctl could not inspect tap.service")
    return dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line), None


def _valid_port(value: str) -> bool:
    try:
        return 1 <= int(value) <= 65535
    except ValueError:
        return False


def _pid_running(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _permission_limited(exc: BaseException | str) -> bool:
    """Whether a diagnostic could not run under the caller's privileges."""
    if isinstance(exc, OSError) and exc.errno in {errno.EACCES, errno.EPERM}:
        return True
    return "operation not permitted" in str(exc).lower() or "permission denied" in str(exc).lower()


def _config_checks() -> tuple[list[CheckResult], TapConfig | None]:
    checks: list[CheckResult] = []
    started = time.monotonic()
    try:
        stat = CONFIG_PATH.stat()
        cfg = TapConfig.load(CONFIG_PATH)
    except PermissionError as exc:
        checks.append(
            _result(
                "config.load",
                "Configuration",
                Severity.SKIP,
                f"cannot read {CONFIG_PATH}: {exc}",
                remediation="Rerun diagnostics as root to inspect TAP configuration.",
                started=started,
            )
        )
        return checks, None
    except (OSError, ValueError) as exc:
        checks.append(
            _result(
                "config.load",
                "Configuration",
                Severity.FAIL,
                f"could not load {CONFIG_PATH}: {exc}",
                remediation="Run 'tap install' or restore a valid TAP configuration.",
                started=started,
            )
        )
        return checks, None

    mode = stat.st_mode & 0o777
    if mode != 0o600 or stat.st_uid != 0:
        ownership = "root-owned" if stat.st_uid == 0 else f"owned by UID {stat.st_uid}"
        checks.append(
            _result(
                "config.permissions",
                "Configuration permissions",
                Severity.WARN,
                f"mode is {mode:04o}; {ownership}; expected root-owned 0600",
                remediation=f"Run 'chown root:root {CONFIG_PATH}' and 'chmod 600 {CONFIG_PATH}'.",
                started=started,
            )
        )
    else:
        checks.append(
            _result(
                "config.permissions",
                "Configuration permissions",
                Severity.PASS,
                "root-owned with mode 0600",
                started=started,
            )
        )

    invalid = [
        name
        for name, value in (("PORT", cfg.port), ("LOCAL_PORT", cfg.local_port))
        if not _valid_port(value)
    ]
    if cfg.socks_proxy_port and not _valid_port(cfg.socks_proxy_port):
        invalid.append("SOCKS_PROXY_PORT")
    issues: list[str] = []
    if not cfg.ipaddr:
        issues.append("IPADDR is empty")
    if not cfg.username:
        issues.append("USERNAME is empty")
    if invalid:
        issues.append(f"invalid {', '.join(invalid)}")
    if issues:
        checks.append(
            _result(
                "config.values",
                "Configuration values",
                Severity.FAIL,
                "; ".join(issues),
                remediation="Correct the connection settings in the TAP configuration.",
                started=started,
            )
        )
    else:
        checks.append(
            _result(
                "config.values",
                "Configuration values",
                Severity.PASS,
                f"{cfg.username}@{cfg.ipaddr}:{cfg.port}",
                details={"local_port": cfg.local_port, "socks_proxy_port": cfg.socks_proxy_port},
                started=started,
            )
        )

    if cfg.command_updates and not cfg.command_updates.lower().startswith("https://"):
        checks.append(
            _result(
                "commands.security",
                "Command channel",
                Severity.WARN,
                "configured URL is not HTTPS",
                remediation="Use an HTTPS command URL and configure COMMAND_HMAC_KEY.",
                started=started,
            )
        )
    elif cfg.command_updates and not cfg.command_hmac_key:
        checks.append(
            _result(
                "commands.security",
                "Command channel",
                Severity.WARN,
                "enabled without HMAC authentication",
                remediation="Set COMMAND_HMAC_KEY and sign command files.",
                started=started,
            )
        )
    elif cfg.command_updates:
        checks.append(
            _result(
                "commands.security",
                "Command channel",
                Severity.PASS,
                "HTTPS and HMAC enabled",
                started=started,
            )
        )
    else:
        checks.append(
            _result(
                "commands.security",
                "Command channel",
                Severity.SKIP,
                "not configured",
                started=started,
            )
        )

    if cfg.permit_root_login.strip().lower() == "yes":
        checks.append(
            _result(
                "sshd.root_login",
                "Root SSH login",
                Severity.WARN,
                "enabled by TAP configuration",
                remediation="Set PERMIT_ROOT_LOGIN=no unless root access is required.",
                started=started,
            )
        )
    return checks, cfg


def _service_check(timeout: float) -> tuple[CheckResult, dict[str, str] | None]:
    started = time.monotonic()
    properties, error = _service_properties(timeout)
    if properties is None:
        limited = _permission_limited(error or "")
        return (
            _result(
                "service.active",
                "TAP service",
                Severity.SKIP if limited else Severity.FAIL,
                error or "could not inspect tap.service",
                remediation=(
                    "Rerun diagnostics as root to inspect the system service."
                    if limited
                    else "Install or start tap.service, then rerun diagnostics."
                ),
                started=started,
            ),
            None,
        )
    active = properties.get("ActiveState") == "active"
    enabled = properties.get("UnitFileState") in {"enabled", "enabled-runtime"}
    severity = (
        Severity.PASS if active and enabled else Severity.FAIL if not active else Severity.WARN
    )
    summary = f"{properties.get('ActiveState', 'unknown')}/{properties.get('SubState', 'unknown')}"
    if active and not enabled:
        summary += "; not enabled at boot"
    return (
        _result(
            "service.active",
            "TAP service",
            severity,
            summary,
            remediation="Run 'systemctl enable --now tap.service'."
            if severity is not Severity.PASS
            else None,
            details={
                "main_pid": properties.get("MainPID", "0"),
                "restart_count": properties.get("NRestarts", "0"),
                "exit_status": properties.get("ExecMainStatus", "0"),
            },
            started=started,
        ),
        properties,
    )


def _runtime_check(service: dict[str, str] | None) -> CheckResult:
    started = time.monotonic()
    state = load_state()
    if state is None:
        return _result(
            "runtime.state",
            "Runtime state",
            Severity.WARN,
            "no runtime state published",
            remediation="Restart tap.service after upgrading TAP.",
            started=started,
        )
    ssh_pid = state.get("ssh_pid")
    daemon_pid = state.get("supervisor_pid")
    state_name = str(state.get("state", "unknown"))
    if state_name == "connected" and _pid_running(ssh_pid):
        severity = Severity.PASS
        summary = f"connected (ssh PID {ssh_pid})"
    elif state_name == "backoff":
        severity = Severity.WARN
        summary = f"reconnecting; next retry {state.get('retry_at', 'unknown')}"
    else:
        severity = Severity.FAIL
        summary = f"{state_name}; SSH process is not running"
    if service and str(daemon_pid) != service.get("MainPID", ""):
        severity = Severity.WARN if severity is Severity.PASS else severity
        summary += "; supervisor PID differs from systemd"
    return _result(
        "runtime.state",
        "Tunnel runtime",
        severity,
        summary,
        remediation="Inspect 'journalctl -u tap.service' for tunnel errors."
        if severity is not Severity.PASS
        else None,
        details={"state_file": str(STATE_PATH), "state": state_name},
        started=started,
    )


def _key_check(key_path: Path, timeout: float) -> CheckResult:
    started = time.monotonic()
    public = key_path.with_suffix(".pub")
    if not key_path.is_file() or not public.is_file():
        return _result(
            "ssh.key",
            "SSH key",
            Severity.FAIL,
            "private or public key is missing",
            remediation="Generate a key with 'tap install' or restore the TAP key pair.",
            started=started,
        )
    private_mode = key_path.stat().st_mode & 0o777
    public_mode = public.stat().st_mode & 0o777
    if private_mode != 0o600 or public_mode != 0o644:
        return _result(
            "ssh.key",
            "SSH key",
            Severity.WARN,
            f"modes are private={private_mode:04o}, public={public_mode:04o}; expected 0600/0644",
            remediation=f"Run 'chmod 600 {key_path}; chmod 644 {public}'.",
            started=started,
        )
    try:
        result = _run(["ssh-keygen", "-lf", str(public)], timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return _result(
            "ssh.key", "SSH key", Severity.WARN, "ssh-keygen is unavailable", started=started
        )
    if result.returncode != 0:
        return _result(
            "ssh.key",
            "SSH key",
            Severity.FAIL,
            "public key is unreadable",
            remediation="Regenerate or restore the TAP SSH key pair.",
            started=started,
        )
    try:
        derived = _run(["ssh-keygen", "-y", "-f", str(key_path)], timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return _result(
            "ssh.key", "SSH key", Severity.WARN, "could not verify key pair", started=started
        )
    public_parts = public.read_text().split()
    derived_parts = derived.stdout.split()
    if derived.returncode != 0 or public_parts[:2] != derived_parts[:2]:
        return _result(
            "ssh.key",
            "SSH key",
            Severity.FAIL,
            "private and public keys do not match",
            remediation="Regenerate or restore the TAP SSH key pair.",
            started=started,
        )
    return _result("ssh.key", "SSH key", Severity.PASS, result.stdout.strip(), started=started)


def _local_sshd_check(timeout: float) -> CheckResult:
    started = time.monotonic()
    try:
        with socket.create_connection(("127.0.0.1", 22), timeout=timeout):
            pass
    except OSError as exc:
        if _permission_limited(exc):
            return _result(
                "local.sshd",
                "Local SSH server",
                Severity.SKIP,
                f"could not probe 127.0.0.1:22 ({exc})",
                remediation="Rerun diagnostics outside a restricted sandbox or as root.",
                started=started,
            )
        return _result(
            "local.sshd",
            "Local SSH server",
            Severity.FAIL,
            f"not reachable on 127.0.0.1:22 ({exc})",
            remediation="Start ssh.service and verify it listens on port 22.",
            started=started,
        )
    return _result(
        "local.sshd",
        "Local SSH server",
        Severity.PASS,
        "listening on 127.0.0.1:22",
        started=started,
    )


def collect_status(timeout: float = 3) -> DiagnosticReport:
    """Collect fast, local-only operational checks."""
    checks, cfg = _config_checks()
    service_check, service = _service_check(timeout)
    checks.append(service_check)
    checks.append(_runtime_check(service))
    checks.append(_key_check(private_key(cfg) if cfg is not None else PRIVATE_KEY, timeout))
    checks.append(_local_sshd_check(timeout))
    for executable in ("ssh", "ss", "systemctl"):
        severity = Severity.PASS if shutil.which(executable) else Severity.FAIL
        checks.append(
            _result(
                f"dependency.{executable}",
                f"Dependency: {executable}",
                severity,
                "available" if severity is Severity.PASS else "not found on PATH",
                remediation=f"Install {executable}." if severity is Severity.FAIL else None,
            )
        )
    if cfg is None:
        checks.append(
            _result(
                "tunnel.configuration", "Tunnel configuration", Severity.SKIP, "config unavailable"
            )
        )
    return DiagnosticReport("status", checks)


def _gateway_dns_check(cfg: TapConfig, timeout: float) -> CheckResult:
    started = time.monotonic()
    try:
        addresses = socket.getaddrinfo(cfg.ipaddr, cfg.port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return _result(
            "gateway.dns",
            "Gateway resolution",
            Severity.FAIL,
            str(exc),
            remediation="Verify IPADDR and local DNS connectivity.",
            started=started,
        )
    resolved = sorted({str(item[4][0]) for item in addresses})
    return _result(
        "gateway.dns", "Gateway resolution", Severity.PASS, ", ".join(resolved), started=started
    )


def _gateway_tcp_check(cfg: TapConfig, timeout: float) -> CheckResult:
    started = time.monotonic()
    try:
        with socket.create_connection((cfg.ipaddr, int(cfg.port)), timeout=timeout):
            pass
    except OSError as exc:
        return _result(
            "gateway.tcp",
            "Gateway TCP",
            Severity.FAIL,
            f"{cfg.ipaddr}:{cfg.port} is unreachable ({exc})",
            remediation="Check routing, firewall rules, and the gateway SSH service.",
            started=started,
        )
    return _result(
        "gateway.tcp",
        "Gateway TCP",
        Severity.PASS,
        f"connected to {cfg.ipaddr}:{cfg.port}",
        started=started,
    )


def _known_host_check(cfg: TapConfig, timeout: float) -> CheckResult:
    started = time.monotonic()
    if not KNOWN_HOSTS.is_file():
        return _result(
            "ssh.host_key",
            "Gateway host key",
            Severity.WARN,
            "known_hosts file is absent",
            remediation="Connect once under operator supervision to record the gateway host key.",
            started=started,
        )
    lookup = cfg.ipaddr if cfg.port == "22" else f"[{cfg.ipaddr}]:{cfg.port}"
    try:
        result = _run(["ssh-keygen", "-F", lookup, "-f", str(KNOWN_HOSTS)], timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return _result(
            "ssh.host_key",
            "Gateway host key",
            Severity.WARN,
            "could not query known_hosts",
            started=started,
        )
    if result.returncode != 0:
        return _result(
            "ssh.host_key",
            "Gateway host key",
            Severity.WARN,
            "no matching host key is recorded",
            remediation="Verify the gateway fingerprint, then record it before relying on TAP.",
            started=started,
        )
    return _result(
        "ssh.host_key",
        "Gateway host key",
        Severity.PASS,
        "verified entry is recorded",
        started=started,
    )


def _sshd_policy_check(timeout: float) -> CheckResult:
    started = time.monotonic()
    try:
        result = _run(["sshd", "-T"], timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return _result(
            "sshd.policy",
            "sshd policy",
            Severity.SKIP,
            "could not inspect effective sshd configuration",
            started=started,
        )
    if result.returncode != 0:
        return _result(
            "sshd.policy",
            "sshd policy",
            Severity.WARN,
            result.stderr.strip() or "sshd -T failed",
            started=started,
        )
    values = dict(line.split(None, 1) for line in result.stdout.splitlines() if " " in line)
    if values.get("permittunnel") != "point-to-point":
        return _result(
            "sshd.policy",
            "sshd policy",
            Severity.WARN,
            "PermitTunnel is not point-to-point",
            remediation="Set PermitTunnel point-to-point if TAP VPN support is required.",
            started=started,
        )
    return _result(
        "sshd.policy", "sshd policy", Severity.PASS, "PermitTunnel point-to-point", started=started
    )


def _ssh_config_check(cfg: TapConfig, timeout: float) -> CheckResult:
    """Validate the local SSH client's effective configuration without connecting."""
    started = time.monotonic()
    command = [
        "ssh",
        "-G",
        "-F",
        "/dev/null",
        "-i",
        str(private_key(cfg)),
        "-p",
        cfg.port,
        f"{cfg.username}@{cfg.ipaddr}",
    ]
    try:
        result = _run(command, timeout=timeout)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return _result(
            "ssh.client_config",
            "SSH client configuration",
            Severity.FAIL,
            str(exc),
            started=started,
        )
    if result.returncode != 0:
        return _result(
            "ssh.client_config",
            "SSH client configuration",
            Severity.FAIL,
            result.stderr.strip() or "ssh could not build its effective configuration",
            remediation="Correct the TAP SSH host, port, username, or key path.",
            started=started,
        )
    return _result(
        "ssh.client_config",
        "SSH client configuration",
        Severity.PASS,
        "effective configuration is valid",
        started=started,
    )


def _ssh_auth_check(cfg: TapConfig, timeout: float) -> CheckResult:
    """Make a short key-only connection without forwards or remote commands.

    ``-N`` keeps an authenticated session open.  If it remains alive for a
    short grace period, authentication and host-key verification succeeded.
    ``StrictHostKeyChecking=yes`` prevents a diagnostic from changing
    ``known_hosts``.
    """
    started = time.monotonic()
    key_path = private_key(cfg)
    if not key_path.is_file():
        return _result(
            "ssh.authentication",
            "SSH authentication",
            Severity.SKIP,
            "private key is unavailable",
            started=started,
        )
    command = [
        "ssh",
        "-N",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"ConnectTimeout={max(1, int(timeout))}",
        "-i",
        str(key_path),
        "-p",
        cfg.port,
        f"{cfg.username}@{cfg.ipaddr}",
    ]
    try:
        proc = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
        )
    except OSError as exc:
        return _result(
            "ssh.authentication", "SSH authentication", Severity.FAIL, str(exc), started=started
        )
    try:
        _, stderr = proc.communicate(timeout=min(max(timeout, 0.1), 2))
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
        return _result(
            "ssh.authentication",
            "SSH authentication",
            Severity.PASS,
            "key-only authentication succeeded",
            started=started,
        )
    return _result(
        "ssh.authentication",
        "SSH authentication",
        Severity.FAIL,
        (stderr or "SSH exited before authentication completed").strip(),
        remediation="Verify the gateway host key and that the TAP public key is authorized remotely.",
        started=started,
    )


def collect_doctor(timeout: float = 5) -> DiagnosticReport:
    """Collect status plus bounded gateway and host-key diagnostics."""
    report = collect_status(timeout=min(timeout, 3))
    checks = list(report.checks)
    try:
        cfg = TapConfig.load(CONFIG_PATH)
    except (OSError, ValueError):
        checks.extend(
            [
                _result("gateway.dns", "Gateway resolution", Severity.SKIP, "config unavailable"),
                _result("gateway.tcp", "Gateway TCP", Severity.SKIP, "config unavailable"),
                _result("ssh.host_key", "Gateway host key", Severity.SKIP, "config unavailable"),
                _result(
                    "ssh.client_config",
                    "SSH client configuration",
                    Severity.SKIP,
                    "config unavailable",
                ),
                _result(
                    "ssh.authentication", "SSH authentication", Severity.SKIP, "config unavailable"
                ),
            ]
        )
    else:
        if cfg.ipaddr and _valid_port(cfg.port):
            checks.extend(
                [
                    _gateway_dns_check(cfg, timeout),
                    _gateway_tcp_check(cfg, timeout),
                    _known_host_check(cfg, timeout),
                    _ssh_config_check(cfg, timeout),
                    _ssh_auth_check(cfg, timeout),
                ]
            )
        else:
            checks.extend(
                [
                    _result(
                        "gateway.dns",
                        "Gateway resolution",
                        Severity.SKIP,
                        "invalid gateway configuration",
                    ),
                    _result(
                        "gateway.tcp", "Gateway TCP", Severity.SKIP, "invalid gateway configuration"
                    ),
                    _result(
                        "ssh.host_key",
                        "Gateway host key",
                        Severity.SKIP,
                        "invalid gateway configuration",
                    ),
                    _result(
                        "ssh.client_config",
                        "SSH client configuration",
                        Severity.SKIP,
                        "invalid gateway configuration",
                    ),
                    _result(
                        "ssh.authentication",
                        "SSH authentication",
                        Severity.SKIP,
                        "invalid gateway configuration",
                    ),
                ]
            )
    checks.append(_sshd_policy_check(timeout))
    return DiagnosticReport("doctor", checks)


def render_human(report: DiagnosticReport) -> str:
    """Render a compact, dependency-free table for terminal output."""
    heading = (
        "HEALTHY"
        if report.severity is Severity.PASS
        else "DEGRADED"
        if report.severity is Severity.WARN
        else "UNHEALTHY"
    )
    width = max((len(check.label) for check in report.checks), default=0)
    lines = [f"TAP {report.command}: {heading}", ""]
    for check in report.checks:
        lines.append(
            f"{check.label.ljust(width)}  {check.severity.value.upper():4}  {check.summary}"
        )
        if check.remediation and check.severity in {Severity.WARN, Severity.FAIL}:
            lines.append(f"{' '.ljust(width)}        Fix: {check.remediation}")
    return "\n".join(lines)


def render_json(report: DiagnosticReport) -> str:
    return json.dumps(report.to_dict(), sort_keys=True)
