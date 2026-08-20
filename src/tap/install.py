"""Host installation, configuration, and removal for TAP.

Replaces the imperative top-level ``setup.py``. Exposes :func:`install` and
:func:`uninstall`, invoked via the ``tap`` CLI. Authentication is key-only, so
there is no password handling here. System-level side effects (apt, sshd,
systemd) live here; the pure transformations are factored out so they can be
unit-tested.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tap import INSTALL_DIR, data_path, ui
from tap.config import CONFIG_PATH, TapConfig
from tap.provision import ProvisionSpec, validate
from tap.ssh import PRIVATE_KEY

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SERVICE_PATH = Path("/etc/systemd/system/tap.service")
PROXYCHAINS_CONF = Path("/etc/proxychains4.conf")

APT_PACKAGES = ["git", "openssh-server", "net-tools", "iproute2", "proxychains4"]


# --------------------------------------------------------------------------
# Pure, testable helpers
# --------------------------------------------------------------------------


def set_sshd_option(text: str, key: str, value: str) -> str:
    """Return ``text`` with ``key`` set to ``value`` (replacing any existing,
    commented or not, occurrence; appending if absent)."""
    pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\b.*$", re.MULTILINE)
    replacement = f"{key} {value}"
    if pattern.search(text):
        return pattern.sub(replacement, text)
    sep = "" if text.endswith("\n") else "\n"
    return f"{text}{sep}{replacement}\n"


def render_service(tap_bin: str) -> str:
    return data_path("tap.service").read_text().replace("__TAP_BIN__", tap_bin)


def proxychains_conf(socks_port: str) -> str:
    return (
        "strict_chain\n"
        "proxy_dns\n"
        "tcp_read_time_out 15000\n"
        "tcp_connect_time_out 8000\n"
        "[ProxyList]\n"
        f"socks5 127.0.0.1 {socks_port}\n"
    )


# --------------------------------------------------------------------------
# System steps
# --------------------------------------------------------------------------


def install_system_packages() -> None:
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    ui.run_step("Refreshing apt package index", ["apt-get", "update"], env=env)
    result = ui.run_step(
        f"Installing packages ({', '.join(APT_PACKAGES)})",
        ["apt-get", "-y", "install", *APT_PACKAGES],
        env=env,
    )
    if result.returncode != 0:
        ui.warn("Package installation reported an error; continuing.")


def configure_sshd(cfg: TapConfig) -> None:
    if not SSHD_CONFIG.is_file():
        ui.warn(f"{SSHD_CONFIG} not found; skipping sshd configuration.")
        return
    backup = SSHD_CONFIG.with_suffix(".tap.bak")
    if not backup.exists():
        shutil.copy2(SSHD_CONFIG, backup)
    text = SSHD_CONFIG.read_text()
    text = set_sshd_option(text, "PermitRootLogin", cfg.permit_root_login)
    text = set_sshd_option(text, "PermitTunnel", "point-to-point")
    SSHD_CONFIG.write_text(text)
    ui.success(f"Wrote sshd config (PermitRootLogin={cfg.permit_root_login}, PermitTunnel=on)")
    ui.run_step("Restarting ssh", ["systemctl", "restart", "ssh"])


def write_proxychains(cfg: TapConfig) -> None:
    if not cfg.socks_proxy_port:
        return
    PROXYCHAINS_CONF.write_text(proxychains_conf(cfg.socks_proxy_port))
    ui.success(f"Wrote {PROXYCHAINS_CONF} (socks5 127.0.0.1 {cfg.socks_proxy_port})")


def install_service() -> None:
    # Use the interpreter that is running the installer (its site-packages has
    # `tap`), so the unit works whatever the install method: a /opt venv, pipx,
    # or a --break-system-packages system install. This avoids a PATH lookup
    # that fails when `tap` lives in a venv that isn't on root's PATH.
    tap_bin = f"{sys.executable} -m tap.cli"
    SERVICE_PATH.write_text(render_service(tap_bin))
    ui.success(f"Wrote {SERVICE_PATH}")
    ui.run_step("Reloading systemd", ["systemctl", "daemon-reload"])
    ui.run_step("Enabling tap.service", ["systemctl", "enable", "tap.service"])
    ui.run_step("Enabling ssh", ["systemctl", "enable", "ssh"])


def install_motd(client: str) -> None:
    if not client:
        return
    text = data_path("motd.txt").read_text()
    Path("/etc/motd").write_text(f"{text}\nTAP Client Name: {client}\n")


def set_background() -> None:
    """Best-effort desktop background (no-op on headless boxes)."""
    image = INSTALL_DIR / "tap.png"
    try:
        shutil.copy2(data_path("tap.png"), image)
        subprocess.run(
            ["gsettings", "set", "org.gnome.desktop.background", "picture-uri", f"file://{image}"],
            check=False,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, FileNotFoundError):
        pass


# --------------------------------------------------------------------------
# SSH key handling
# --------------------------------------------------------------------------


def generate_ssh_key(
    key_path: Path = PRIVATE_KEY, *, overwrite: bool = True, announce: bool = True
) -> None:
    """Generate a TAP key pair, refusing implicit replacement when requested."""
    public_key = key_path.with_suffix(".pub")
    if not overwrite and (key_path.exists() or public_key.exists()):
        raise FileExistsError(f"refusing to overwrite existing key at {key_path}")
    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if overwrite:
        for key in (key_path, public_key):
            key.unlink(missing_ok=True)
    if announce:
        ui.info(f"Generating a 4096-bit RSA SSH key pair at {key_path}…")
    # Run directly (no spinner/capture): ssh-keygen writes progress to the tty.
    subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-b", "4096", "-N", "", "-f", str(key_path)],
        check=True,
        capture_output=not announce,
        text=True,
    )
    if announce:
        ui.success("Generated SSH key pair")


def upload_public_key(cfg: TapConfig) -> None:
    """Install the public key on the remote server via ``ssh-copy-id``.

    ``ssh-copy-id`` prompts the operator for the remote password directly on the
    terminal (one time), so no password is captured or stored by TAP.
    """
    target = f"{cfg.username}@{cfg.ipaddr}"
    pub = Path(cfg.identity_file).with_suffix(".pub")
    ui.info(f"Uploading public key to {target} via ssh-copy-id (you'll be prompted once)…")
    # Run directly (no spinner/capture): ssh-copy-id prompts for the remote
    # password on the terminal, which a Live display would swallow.
    result = subprocess.run(
        [
            "ssh-copy-id",
            "-i",
            str(pub),
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-p",
            cfg.port,
            target,
        ],
        check=False,
    )
    if result.returncode == 0:
        ui.success(f"Installed public key on {target}")
    else:
        ui.warn(
            f"ssh-copy-id exited with status {result.returncode}; "
            "install the key manually if needed."
        )


# --------------------------------------------------------------------------
# Interactive configuration
# --------------------------------------------------------------------------


def collect_config() -> TapConfig:
    cfg = TapConfig()
    cfg.ipaddr = ui.ask("Remote SSH host/IP to call back to")
    cfg.port = ui.ask("Remote SSH port", "22")
    cfg.username = ui.ask("Username on the REMOTE server (root not recommended)", "tap")
    cfg.local_port = ui.ask("LOCAL port to expose on the remote server", "10003")
    cfg.socks_proxy_port = ui.ask("SOCKS proxy port on the remote server", "10004")
    cfg.command_updates = ui.ask("Remote command URL (optional, HTTPS)", "")
    if cfg.command_updates:
        cfg.command_hmac_key = ui.ask_secret(
            "Optional HMAC key to authenticate command files (blank to skip)"
        ).strip()
    cfg.permit_root_login = "no"
    if ui.confirm("Allow root login over SSH on THIS box? (not recommended)", default=False):
        cfg.permit_root_login = "yes"

    # Key-only authentication.
    if ui.confirm("Generate a new SSH key pair?", default=True):
        generate_ssh_key(overwrite=True)
    elif not PRIVATE_KEY.is_file():
        ui.warn(f"No key found at {PRIVATE_KEY}; generating one.")
        generate_ssh_key(overwrite=True)
    if not ui.confirm("Is the public key already installed on the remote server?", default=False):
        upload_public_key(cfg)

    return cfg


# --------------------------------------------------------------------------
# Top-level entry points
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class OperationResult:
    """One safe-to-render non-interactive installation operation."""

    operation: str
    status: str
    summary: str


class InstallationError(RuntimeError):
    """Raised when an unattended installation operation cannot complete."""


def _write_if_changed(path: Path, text: str, mode: int | None = None) -> bool:
    """Write a file only when its content or requested mode differs."""
    before = path.read_text() if path.is_file() else None
    changed = before != text
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    if mode is not None and (not path.exists() or (path.stat().st_mode & 0o777) != mode):
        path.chmod(mode)
        changed = True
    return changed


def _run_unattended(
    operation: str, command: list[str], *, env: dict[str, str] | None = None
) -> None:
    result = subprocess.run(command, check=False, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise InstallationError(f"{operation} failed with exit status {result.returncode}{suffix}")


def _apply_packages() -> bool:
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    _run_unattended("apt package index refresh", ["apt-get", "update"], env=env)
    _run_unattended("package installation", ["apt-get", "-y", "install", *APT_PACKAGES], env=env)
    return True


def _apply_sshd(cfg: TapConfig) -> bool:
    if not SSHD_CONFIG.is_file():
        raise InstallationError(f"{SSHD_CONFIG} does not exist")
    backup = SSHD_CONFIG.with_suffix(".tap.bak")
    if not backup.exists():
        shutil.copy2(SSHD_CONFIG, backup)
    text = SSHD_CONFIG.read_text()
    desired = set_sshd_option(
        set_sshd_option(text, "PermitRootLogin", cfg.permit_root_login),
        "PermitTunnel",
        "point-to-point",
    )
    changed = _write_if_changed(SSHD_CONFIG, desired)
    if changed:
        _run_unattended("sshd restart", ["systemctl", "restart", "ssh"])
    return changed


def _apply_proxychains(cfg: TapConfig) -> bool:
    if not cfg.socks_proxy_port:
        return False
    return _write_if_changed(PROXYCHAINS_CONF, proxychains_conf(cfg.socks_proxy_port))


def _apply_service() -> bool:
    tap_bin = f"{sys.executable} -m tap.cli"
    changed = _write_if_changed(SERVICE_PATH, render_service(tap_bin))
    if changed:
        _run_unattended("systemd daemon reload", ["systemctl", "daemon-reload"])
    _run_unattended("enable tap.service", ["systemctl", "enable", "tap.service"])
    _run_unattended("enable ssh.service", ["systemctl", "enable", "ssh"])
    return changed


def _apply_motd(client_name: str) -> bool:
    if not client_name:
        return False
    text = f"{data_path('motd.txt').read_text()}\nTAP Client Name: {client_name}\n"
    return _write_if_changed(Path("/etc/motd"), text)


def _generate_key(key_path: Path) -> bool:
    generate_ssh_key(key_path, overwrite=False, announce=False)
    return True


def _start_service() -> bool:
    _run_unattended("start tap.service", ["systemctl", "start", "tap.service"])
    return True


def _operation(
    results: list[OperationResult], operation: str, summary: str, action: Any, dry_run: bool
) -> None:
    if dry_run:
        results.append(OperationResult(operation, "planned", summary))
        return
    changed = bool(action())
    results.append(OperationResult(operation, "changed" if changed else "unchanged", summary))


def install_noninteractive(spec: ProvisionSpec, *, dry_run: bool = False) -> list[OperationResult]:
    """Apply one validated provisioning specification without terminal prompts.

    Validation is deliberately completed before the first system change.  The
    result list is safe to serialize: it contains neither the command HMAC nor
    private-key contents.
    """
    errors = validate(spec)
    if errors:
        raise InstallationError("invalid provisioning specification: " + "; ".join(errors))

    cfg = spec.config
    settings = spec.installation
    results: list[OperationResult] = []
    if settings.install_packages:
        _operation(
            results, "packages", "install required system packages", _apply_packages, dry_run
        )
    else:
        results.append(OperationResult("packages", "skipped", "package installation disabled"))

    if spec.key.mode == "generate":
        _operation(
            results,
            "ssh_key",
            f"generate key pair at {spec.key.private_key}",
            lambda: _generate_key(spec.key.private_key),
            dry_run,
        )
    else:
        results.append(
            OperationResult("ssh_key", "unchanged", f"use existing key at {spec.key.private_key}")
        )

    _operation(
        results,
        "runtime_config",
        f"write TAP runtime config to {CONFIG_PATH}",
        lambda: _write_if_changed(CONFIG_PATH, cfg.to_text(), 0o600),
        dry_run,
    )

    if settings.configure_sshd:
        _operation(results, "sshd", "configure local SSH server", lambda: _apply_sshd(cfg), dry_run)
    else:
        results.append(OperationResult("sshd", "skipped", "sshd configuration disabled"))

    if settings.configure_proxychains:
        _operation(
            results,
            "proxychains",
            "configure local SOCKS proxy client",
            lambda: _apply_proxychains(cfg),
            dry_run,
        )
    else:
        results.append(
            OperationResult("proxychains", "skipped", "proxychains configuration disabled")
        )

    _operation(results, "service", "install and enable tap.service", _apply_service, dry_run)
    if settings.client_name:
        _operation(
            results,
            "motd",
            "write TAP client MOTD",
            lambda: _apply_motd(settings.client_name),
            dry_run,
        )
    if settings.start_service:
        _operation(
            results,
            "service_start",
            "start tap.service",
            _start_service,
            dry_run,
        )
    else:
        results.append(OperationResult("service_start", "skipped", "service startup disabled"))
    return results


def operation_dicts(results: list[OperationResult]) -> list[dict[str, str]]:
    """Convert operation results to a JSON-friendly, stable representation."""
    return [asdict(result) for result in results]


TOTAL_STEPS = 7


def install() -> None:
    ui.banner()
    started = time.monotonic()
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    ui.step(1, TOTAL_STEPS, "Installing system packages")
    install_system_packages()

    ui.step(2, TOTAL_STEPS, "Collecting configuration")
    cfg = collect_config()
    cfg.save()
    ui.success(f"Configuration written to {CONFIG_PATH}")

    ui.step(3, TOTAL_STEPS, "Configuring sshd")
    configure_sshd(cfg)

    ui.step(4, TOTAL_STEPS, "Writing proxychains config")
    write_proxychains(cfg)

    ui.step(5, TOTAL_STEPS, "Installing systemd service")
    install_service()

    ui.step(6, TOTAL_STEPS, "Applying MOTD and desktop background")
    install_motd(ui.ask("Client/engagement name for the MOTD (optional)", ""))
    set_background()

    ui.step(7, TOTAL_STEPS, "Starting TAP")
    started_service = ui.confirm("Start TAP now?", default=True)
    if started_service:
        ui.run_step("Starting tap.service", ["systemctl", "start", "tap.service"])

    elapsed = time.monotonic() - started
    ui.summary(
        [
            ("Remote target", f"{cfg.username}@{cfg.ipaddr}:{cfg.port}"),
            ("Local port", cfg.local_port),
            ("SOCKS port", cfg.socks_proxy_port),
            ("SSH key", str(PRIVATE_KEY)),
            ("Config", str(CONFIG_PATH)),
            ("Service", "started" if started_service else "installed (not started)"),
            ("Elapsed", f"{elapsed:.0f}s"),
        ]
    )


def uninstall() -> None:
    ui.info("Uninstalling TAP…")
    ui.run_step("Stopping tap.service", ["systemctl", "stop", "tap.service"])
    ui.run_step("Disabling tap.service", ["systemctl", "disable", "tap.service"])
    SERVICE_PATH.unlink(missing_ok=True)
    ui.run_step("Reloading systemd", ["systemctl", "daemon-reload"])
    # Legacy init.d artifact from older versions.
    Path("/etc/init.d/tap").unlink(missing_ok=True)
    if INSTALL_DIR.is_dir():
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    ui.success("TAP has been uninstalled.")
