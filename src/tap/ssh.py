"""Reverse-SSH tunnel management.

Ported from the historical ``ssh_run`` with three notable changes:

* Host keys are verified (``StrictHostKeyChecking=accept-new``) instead of
  ``known_hosts`` being deleted before every connection, which had silently
  disabled MITM protection.
* Connect and monitor are separated: :func:`serve` raises when the tunnel
  drops so the daemon's outer loop owns retry/backoff.
* ``logging`` and targeted error handling replace ``print`` and bare ``except``.
"""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path

import pexpect

from tap.config import TapConfig

log = logging.getLogger("tap.ssh")

PRIVATE_KEY = Path("/root/.ssh/id_ed25519")
_INITIAL_SETTLE_SECONDS = 5
_PASSWORD_PROMPT = "assword"


def _common_opts(cfg: TapConfig) -> list[str]:
    opts = [
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
        "-o",
        "ExitOnForwardFailure=yes",
    ]
    if cfg.use_ssh_keys:
        opts += [
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-i",
            str(PRIVATE_KEY),
        ]
    return opts


def _fix_key_perms() -> None:
    for key, mode in ((PRIVATE_KEY, 0o600), (PRIVATE_KEY.with_suffix(".pub"), 0o644)):
        if key.is_file():
            key.chmod(mode)


def kill_stale_tunnels(port: str) -> None:
    """Kill lingering ssh processes bound to the same remote port."""
    proc = subprocess.run(["ss", "-antp"], capture_output=True, text=True, check=False)
    for line in proc.stdout.splitlines():
        if port in line and "ssh" in line and "ESTAB" in line:
            for field in line.split():
                if field.startswith("pid="):
                    pid = field.split("pid=")[1].split(",")[0]
                    log.info("Killing stale ssh tunnel pid %s on port %s", pid, port)
                    subprocess.run(["kill", pid], check=False)


def _spawn_with_password(command: str, password: str) -> pexpect.spawn:
    """Spawn an ssh command, answering a password prompt if one appears."""
    child = pexpect.spawn(command, encoding="utf-8", timeout=60)
    index = child.expect([_PASSWORD_PROMPT, "Last login", pexpect.EOF, pexpect.TIMEOUT])
    if index == 0:
        child.sendline(password)
    return child


def _reverse_tunnel_cmd(cfg: TapConfig) -> str:
    opts = " ".join(_common_opts(cfg))
    return (
        f"ssh -N {opts} "
        f"-R 127.0.0.1:{cfg.local_port}:127.0.0.1:22 "
        f"{cfg.username}@{cfg.ipaddr} -p {cfg.port}"
    )


def _socks_cmd(cfg: TapConfig) -> str:
    opts = " ".join(_common_opts(cfg))
    return f"ssh -N {opts} -D {cfg.socks_proxy_port} " f"{cfg.username}@{cfg.ipaddr} -p {cfg.port}"


def _tunnel_is_listening(cfg: TapConfig, password: str) -> bool:
    """Check, over the control connection, that the remote port is LISTENing."""
    opts = " ".join(_common_opts(cfg))
    check = (
        f"ssh {opts} {cfg.username}@{cfg.ipaddr} -p {cfg.port} "
        f"\"ss -ant | grep -q ':{cfg.local_port}.*LISTEN' && echo TAP_UP || echo TAP_DOWN\""
    )
    try:
        child = _spawn_with_password(check, password)
        idx = child.expect(["TAP_UP", "TAP_DOWN", pexpect.EOF, pexpect.TIMEOUT])
        child.close()
        return idx == 0
    except pexpect.ExceptionPexpect:
        return False


def serve(cfg: TapConfig, password: str) -> None:
    """Establish the reverse tunnel and monitor it until it drops.

    Raises :class:`ConnectionError` when the tunnel can no longer be verified,
    so the caller can reconnect.
    """
    _fix_key_perms()
    kill_stale_tunnels(cfg.port)

    log.info("Initializing reverse SSH tunnel to %s:%s", cfg.ipaddr, cfg.port)
    tunnel = _spawn_with_password(_reverse_tunnel_cmd(cfg), password)
    time.sleep(_INITIAL_SETTLE_SECONDS)

    socks: pexpect.spawn | None = None
    try:
        while True:
            if not tunnel.isalive():
                raise ConnectionError("Reverse tunnel process exited.")
            if not _tunnel_is_listening(cfg, password):
                raise ConnectionError("Remote port is no longer listening.")

            if cfg.socks_proxy_port and (socks is None or not socks.isalive()):
                log.info("Establishing SOCKS proxy on remote port %s", cfg.socks_proxy_port)
                socks = _spawn_with_password(_socks_cmd(cfg), password)

            log.debug("Tunnel healthy; sleeping %ss", cfg.check_interval)
            time.sleep(cfg.check_interval)
    finally:
        for child in (socks, tunnel):
            if child is not None and child.isalive():
                child.terminate(force=True)
