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
from pathlib import Path

from tap import INSTALL_DIR, data_path, ui
from tap.config import CONFIG_PATH, TapConfig
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


def generate_ssh_key() -> None:
    PRIVATE_KEY.parent.mkdir(mode=0o700, exist_ok=True)
    for key in (PRIVATE_KEY, PRIVATE_KEY.with_suffix(".pub")):
        key.unlink(missing_ok=True)
    ui.info(f"Generating a 4096-bit RSA SSH key pair at {PRIVATE_KEY}…")
    # Run directly (no spinner/capture): ssh-keygen writes progress to the tty.
    subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-b", "4096", "-N", "", "-f", str(PRIVATE_KEY)],
        check=True,
    )
    ui.success("Generated SSH key pair")


def upload_public_key(cfg: TapConfig) -> None:
    """Install the public key on the remote server via ``ssh-copy-id``.

    ``ssh-copy-id`` prompts the operator for the remote password directly on the
    terminal (one time), so no password is captured or stored by TAP.
    """
    target = f"{cfg.username}@{cfg.ipaddr}"
    pub = PRIVATE_KEY.with_suffix(".pub")
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
        generate_ssh_key()
    elif not PRIVATE_KEY.is_file():
        ui.warn(f"No key found at {PRIVATE_KEY}; generating one.")
        generate_ssh_key()
    if not ui.confirm("Is the public key already installed on the remote server?", default=False):
        upload_public_key(cfg)

    return cfg


# --------------------------------------------------------------------------
# Top-level entry points
# --------------------------------------------------------------------------


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
