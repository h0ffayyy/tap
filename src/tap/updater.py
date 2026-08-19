"""Self-update for the TAP codebase.

Replaces the old ``update.py`` / ``tap_update``. When ``AUTO_UPDATE`` is on it
runs the configured update command (default ``git pull``) inside the install
directory. Package upgrades of the host OS are intentionally not performed here:
unattended ``apt dist-upgrade`` on a remote dropbox risks apt-lock hangs and
mid-engagement breakage (see CHANGELOG 1.3.3).
"""

from __future__ import annotations

import logging
import os
import subprocess

from tap import INSTALL_DIR
from tap.config import TapConfig

log = logging.getLogger("tap.updater")


def update() -> None:
    cfg = TapConfig.load()
    if not cfg.auto_update_enabled:
        log.info(
            "AUTO_UPDATE is off; not updating. To update manually: cd %s && git pull",
            INSTALL_DIR,
        )
        return

    if not INSTALL_DIR.is_dir():
        log.error("Install directory %s missing; cannot update.", INSTALL_DIR)
        return

    command = cfg.update_server.strip() or "git pull"
    log.info("Updating TAP codebase: %s (in %s)", command, INSTALL_DIR)
    result = subprocess.run(command, shell=True, cwd=os.fspath(INSTALL_DIR), check=False)
    if result.returncode == 0:
        log.info("TAP update complete.")
    else:
        log.warning("TAP update command exited with status %s.", result.returncode)
