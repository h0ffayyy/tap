"""TAP supervisor daemon.

Loads config, launches the remote command poller in a background thread, and
keeps the reverse-SSH tunnel up with bounded exponential backoff between
reconnect attempts. Authentication is key-only, so no secrets are handled here.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from typing import Any

from tap import commands, runtime, ssh
from tap.config import TapConfig

log = logging.getLogger("tap.daemon")

_MIN_BACKOFF = 5
_MAX_BACKOFF = 300


def _publish_state(state: str, **values: Any) -> None:
    """Publish diagnostics without allowing a full /run filesystem to stop TAP."""
    try:
        runtime.write_state(state, **values)
    except OSError:
        log.exception("Could not publish TAP runtime state.")


def run() -> None:
    """Run the supervisor loop until interrupted."""
    _install_signal_handlers()
    cfg = TapConfig.load()
    _publish_state("starting", supervisor_pid=os.getpid(), started_at=runtime.now())

    if cfg.command_updates:
        poller = threading.Thread(
            target=commands.poll_loop, args=(cfg,), name="tap-commands", daemon=True
        )
        poller.start()

    backoff = _MIN_BACKOFF
    while True:
        try:
            _publish_state("connecting", supervisor_pid=os.getpid(), ssh_pid=None)
            ssh.serve(
                cfg,
                on_connected=lambda pid: _publish_state(
                    "connected",
                    supervisor_pid=os.getpid(),
                    ssh_pid=pid,
                    connected_at=runtime.now(),
                    last_error=None,
                ),
            )
        except KeyboardInterrupt:
            log.info("Interrupted; shutting down TAP.")
            _publish_state("stopped", supervisor_pid=os.getpid(), ssh_pid=None)
            break
        except ConnectionError as exc:
            log.warning("Tunnel down (%s); reconnecting in %ss.", exc, backoff)
            retry_at = time.time() + backoff
            _publish_state(
                "backoff",
                supervisor_pid=os.getpid(),
                ssh_pid=None,
                last_error=str(exc),
                retry_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(retry_at)),
            )
            time.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF)
        except Exception:
            log.exception("Unexpected error in supervisor; retrying in %ss.", backoff)
            _publish_state(
                "backoff",
                supervisor_pid=os.getpid(),
                ssh_pid=None,
                last_error="unexpected supervisor error",
            )
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
