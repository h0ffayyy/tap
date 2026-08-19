"""Host installation, configuration, and removal for TAP.

Replaces the imperative top-level ``setup.py``. Exposes :func:`install`,
:func:`uninstall`, and :func:`update_password`, invoked via the ``tap`` CLI.
System-level side effects (apt, sshd, systemd) live here; the pure
transformations are factored out so they can be unit-tested.
"""

from __future__ import annotations

import getpass
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

import pexpect

from tap import INSTALL_DIR, data_path
from tap.config import CONFIG_PATH, TapConfig
from tap.crypto import encrypt_password
from tap.ssh import PRIVATE_KEY

log = logging.getLogger("tap.install")

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
    log.info("Installing system packages: %s", " ".join(APT_PACKAGES))
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    subprocess.run(["apt-get", "update"], check=False, env=env)
    result = subprocess.run(["apt-get", "-y", "install", *APT_PACKAGES], check=False, env=env)
    if result.returncode != 0:
        log.warning("Package installation returned %s; continuing.", result.returncode)


def configure_sshd(cfg: TapConfig) -> None:
    if not SSHD_CONFIG.is_file():
        log.warning("%s not found; skipping sshd configuration.", SSHD_CONFIG)
        return
    log.info("Configuring sshd (PermitRootLogin=%s).", cfg.permit_root_login)
    backup = SSHD_CONFIG.with_suffix(".tap.bak")
    if not backup.exists():
        shutil.copy2(SSHD_CONFIG, backup)
    text = SSHD_CONFIG.read_text()
    text = set_sshd_option(text, "PermitRootLogin", cfg.permit_root_login)
    text = set_sshd_option(text, "PermitTunnel", "point-to-point")
    SSHD_CONFIG.write_text(text)
    subprocess.run(["systemctl", "restart", "ssh"], check=False)


def write_proxychains(cfg: TapConfig) -> None:
    if not cfg.socks_proxy_port:
        return
    log.info("Writing %s (socks5 127.0.0.1 %s).", PROXYCHAINS_CONF, cfg.socks_proxy_port)
    PROXYCHAINS_CONF.write_text(proxychains_conf(cfg.socks_proxy_port))


def install_service() -> None:
    tap_bin = shutil.which("tap") or "/usr/local/bin/tap"
    log.info("Installing systemd service using %s.", tap_bin)
    SERVICE_PATH.write_text(render_service(tap_bin))
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "enable", "tap.service"], check=False)
    subprocess.run(["systemctl", "enable", "ssh"], check=False)


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
    log.info("Generating an ed25519 SSH key pair at %s.", PRIVATE_KEY)
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(PRIVATE_KEY)],
        check=True,
    )


def upload_public_key(cfg: TapConfig, one_time_password: str) -> None:
    pub = PRIVATE_KEY.with_suffix(".pub").read_text().strip()
    hostname = (
        Path("/etc/hostname").read_text().strip() if Path("/etc/hostname").is_file() else "tap"
    )
    target = f"{cfg.username}@{cfg.ipaddr}"
    log.info("Uploading public key to %s (one-time password prompt).", target)
    command = (
        f"ssh -o StrictHostKeyChecking=accept-new {target} -p {cfg.port} "
        f'"mkdir -p ~/.ssh && chmod 700 ~/.ssh && '
        f"printf '# TAP box: {hostname}\\n{pub}\\n' >> ~/.ssh/authorized_keys\""
    )
    child = pexpect.spawn(command, encoding="utf-8", timeout=60)
    idx = child.expect(["assword", pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        child.sendline(one_time_password)
        child.expect([pexpect.EOF, pexpect.TIMEOUT])
    child.close()
    if child.exitstatus not in (0, None):
        log.warning("Key upload exited with status %s; verify manually.", child.exitstatus)


# --------------------------------------------------------------------------
# Interactive configuration
# --------------------------------------------------------------------------


def _prompt(text: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or default


def _yesno(text: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    answer = input(f"{text} [{d}]: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def collect_config() -> TapConfig:
    print("\n=== TAP configuration ===")
    use_keys = _yesno("Use SSH keys (recommended)? Choose 'no' for password auth", default=True)

    cfg = TapConfig(ssh_keys="ON" if use_keys else "OFF")
    cfg.ipaddr = _prompt("Remote SSH host/IP to call back to")
    cfg.port = _prompt("Remote SSH port", "22")
    cfg.username = _prompt("Username on the REMOTE server (root not recommended)", "tap")
    cfg.local_port = _prompt("LOCAL port to expose on the remote server", "10003")
    cfg.socks_proxy_port = _prompt("SOCKS proxy port on the remote server", "10004")
    cfg.command_updates = _prompt("Remote command URL (optional, HTTPS)", "")
    if cfg.command_updates:
        cfg.command_hmac_key = getpass.getpass(
            "Optional HMAC key to authenticate command files (blank to skip): "
        ).strip()
    cfg.permit_root_login = "no"
    if _yesno("Allow root login over SSH on THIS box? (not recommended)", default=False):
        cfg.permit_root_login = "yes"

    if use_keys:
        if _yesno("Generate a new SSH key pair?", default=True):
            generate_ssh_key()
        if not _yesno("Is the public key already installed on the remote server?", default=False):
            one_time = getpass.getpass("Remote SSH password (one time, to upload the key): ")
            upload_public_key(cfg, one_time)
    else:
        print("[!] Password authentication is discouraged; SSH keys are safer.")
        password = getpass.getpass(f"Password for {cfg.username}@{cfg.ipaddr}: ")
        cfg.password = encrypt_password(password)

    return cfg


# --------------------------------------------------------------------------
# Top-level entry points
# --------------------------------------------------------------------------


def install() -> None:
    print("=== TrustedSec Attack Platform (TAP) installer ===")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    install_system_packages()

    cfg = collect_config()
    cfg.save()
    print(f"[*] Configuration written to {CONFIG_PATH}")

    configure_sshd(cfg)
    write_proxychains(cfg)
    install_service()
    install_motd(_prompt("Client/engagement name for the MOTD (optional)", ""))
    set_background()

    if _yesno("Start TAP now?", default=True):
        subprocess.run(["systemctl", "start", "tap.service"], check=False)
        print("[*] TAP service started.")

    if _yesno("Install PTF (PenTesters Framework) now?", default=False):
        _install_ptf()

    print("[*] Installation complete.")


def uninstall() -> None:
    print("[*] Uninstalling TAP...")
    subprocess.run(["systemctl", "stop", "tap.service"], check=False)
    subprocess.run(["systemctl", "disable", "tap.service"], check=False)
    SERVICE_PATH.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    # Legacy init.d artifact from older versions.
    Path("/etc/init.d/tap").unlink(missing_ok=True)
    if INSTALL_DIR.is_dir():
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    print("[*] TAP has been uninstalled.")


def update_password() -> None:
    cfg = TapConfig.load()
    password = getpass.getpass("Enter the new SSH password to encrypt and store: ")
    cfg.password = encrypt_password(password)
    cfg.ssh_keys = "OFF"
    cfg.save()
    print("[*] Password re-encrypted and stored.")


def _install_ptf() -> None:
    ptf_dir = Path("/pentest/ptf")
    try:
        ptf_dir.parent.mkdir(parents=True, exist_ok=True)
        if not ptf_dir.is_dir():
            subprocess.run(
                ["git", "clone", "https://github.com/trustedsec/ptf.git", str(ptf_dir)],
                check=True,
            )
        print(f"[*] PTF cloned to {ptf_dir}. Run it with: cd {ptf_dir} && ./ptf")
    except subprocess.CalledProcessError as exc:
        log.warning("PTF installation failed: %s", exc)
