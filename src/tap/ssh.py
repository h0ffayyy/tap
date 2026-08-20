"""Reverse-SSH tunnel management (keys-only).

TAP authenticates with an SSH key and ``BatchMode=yes``, so ssh never prompts
interactively -- which means no ``pexpect`` and no stored password. A single
ssh process carries both the reverse port-forward and the SOCKS proxy; ssh's
own keepalives (``ServerAliveInterval``) make it exit when the link dies, and
the daemon's outer loop reconnects with backoff. (``autossh`` could be dropped
in here as a resilience layer, but ssh keepalives plus the supervisor loop
cover the same ground without an extra dependency.)

Host keys are verified (``StrictHostKeyChecking=accept-new``); the command is
built as an argument list, so there is no shell to inject into.
"""

from __future__ import annotations

import logging
import subprocess
from collections.abc import Callable
from pathlib import Path

from tap.config import TapConfig

log = logging.getLogger("tap.ssh")

PRIVATE_KEY = Path("/root/.ssh/id_rsa")
_TERMINATE_GRACE_SECONDS = 5


def private_key(cfg: TapConfig) -> Path:
    """Return the configured SSH identity, retaining the legacy default."""
    return Path(cfg.identity_file) if cfg.identity_file else PRIVATE_KEY


def _common_opts(cfg: TapConfig) -> list[str]:
    return [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "ExitOnForwardFailure=yes",
        "-i",
        str(private_key(cfg)),
    ]


def tunnel_command(cfg: TapConfig) -> list[str]:
    """Build the ssh argument list for the reverse tunnel (+ SOCKS if set)."""
    cmd = ["ssh", "-N", *_common_opts(cfg)]
    cmd += ["-R", f"127.0.0.1:{cfg.local_port}:127.0.0.1:22"]
    if cfg.socks_proxy_port:
        cmd += ["-D", f"127.0.0.1:{cfg.socks_proxy_port}"]
    cmd += [f"{cfg.username}@{cfg.ipaddr}", "-p", cfg.port]
    return cmd


def _fix_key_perms(cfg: TapConfig) -> None:
    key_path = private_key(cfg)
    for key, mode in ((key_path, 0o600), (key_path.with_suffix(".pub"), 0o644)):
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


def serve(cfg: TapConfig, on_connected: Callable[[int], None] | None = None) -> None:
    """Establish the tunnel and block until it drops.

    Raises :class:`ConnectionError` when ssh exits, so the caller reconnects.
    Propagates :class:`KeyboardInterrupt` (e.g. SIGTERM) after tearing the
    child down cleanly.
    """
    _fix_key_perms(cfg)
    kill_stale_tunnels(cfg.port)

    cmd = tunnel_command(cfg)
    log.info("Initializing reverse SSH tunnel to %s:%s", cfg.ipaddr, cfg.port)
    log.debug("ssh command: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd)
    try:
        # ExitOnForwardFailure makes an early exit meaningful.  Surviving a
        # short grace period is the best portable readiness signal ssh offers
        # without adding a control socket or a second dependency.
        try:
            status = proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            if on_connected is not None:
                on_connected(proc.pid)
            status = proc.wait()
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=_TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                proc.kill()

    raise ConnectionError(f"ssh tunnel exited (status {status}).")
