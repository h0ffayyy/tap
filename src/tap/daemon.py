"""TAP supervisor daemon.

Loads config, launches the remote command poller in a background thread, and
keeps the reverse-SSH tunnel up with bounded exponential backoff between
reconnect attempts. Authentication is key-only, so no secrets are handled here.
"""

from __future__ import annotations

import logging
import signal
import subprocess
import threading
import time

from tap import commands, ssh
from tap.config import TapConfig

log = logging.getLogger("tap.daemon")

_MIN_BACKOFF = 5
_MAX_BACKOFF = 300


def run() -> None:
    """Run the supervisor loop until interrupted."""
    _install_signal_handlers()
    cfg = TapConfig.load()

    if cfg.command_updates:
        poller = threading.Thread(
            target=commands.poll_loop, args=(cfg,), name="tap-commands", daemon=True
        )
        poller.start()

    backoff = _MIN_BACKOFF
    while True:
        try:
            ssh.serve(cfg)
        except KeyboardInterrupt:
            log.info("Interrupted; shutting down TAP.")
            break
        except ConnectionError as exc:
            log.warning("Tunnel down (%s); reconnecting in %ss.", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)
        except Exception:
            log.exception("Unexpected error in supervisor; retrying in %ss.", backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)


def stop() -> None:
    """Terminate any running TAP daemon/tunnel processes (used by systemd)."""
    log.info("Stopping TAP processes.")
    subprocess.run(["pkill", "-f", "tap run"], check=False)
    subprocess.run(["pkill", "-f", "ssh -N .*-R 127.0.0.1"], check=False)


def _install_signal_handlers() -> None:
    def _handler(signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _handler)
