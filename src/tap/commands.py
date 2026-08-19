"""Remote command channel.

TAP can poll a URL for a command file and execute it -- a fallback control
path for when the reverse-SSH tunnel is down. The historical implementation was
non-functional (a constant-truthy guard, ``bytes``/``str`` mix-ups, a broken
hash comparison) and unauthenticated. This rewrite fixes the logic and adds
optional HMAC-SHA256 verification.

Command file format::

    SIGNATURE=<hex hmac-sha256 of everything below this line>   # optional
    EXECUTE COMMANDS
    <shell command 1>
    <shell command 2>

If ``command_hmac_key`` is configured, a valid ``SIGNATURE=`` line is REQUIRED
and the file is refused otherwise. Each distinct file is executed once (tracked
by content hash) so re-polling the same file is a no-op.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import subprocess
import time
import urllib.request
from pathlib import Path

from tap.config import TapConfig

log = logging.getLogger("tap.commands")

HEADER = "EXECUTE COMMANDS"
_LEGACY_HEADER = "EXECUTE COMMAND"
STATE_PATH = Path("/var/lib/tap/last_command.sha256")
POLL_SECONDS = 120


def _fetch(url: str) -> str:
    if not url.lower().startswith("https://"):
        log.warning("Command URL is not HTTPS (%s) -- traffic is unauthenticated in transit.", url)
    req = urllib.request.Request(url, headers={"User-Agent": "tap"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (operator-controlled URL)
        return resp.read().decode("utf-8", errors="replace")


def _split_signature(body: str) -> tuple[str | None, str]:
    """Return ``(signature, payload)`` splitting off a leading SIGNATURE= line."""
    lines = body.splitlines()
    if lines and lines[0].startswith("SIGNATURE="):
        signature = lines[0].split("=", 1)[1].strip()
        payload = "\n".join(lines[1:])
        return signature, payload
    return None, body


def _verify(payload: str, signature: str | None, key: str) -> bool:
    if not key:
        if signature is not None:
            log.debug("Command file is signed but no HMAC key is configured; ignoring signature.")
        return True
    if signature is None:
        log.error("HMAC key is configured but the command file has no SIGNATURE line. Refusing.")
        return False
    expected = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        log.error("Command file signature is invalid. Refusing to execute.")
        return False
    return True


def _already_executed(payload: str) -> bool:
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return STATE_PATH.is_file() and STATE_PATH.read_text().strip() == digest


def _record_executed(payload: str) -> None:
    digest = hashlib.sha256(payload.encode()).hexdigest()
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(digest)


def _run_commands(payload: str) -> None:
    for raw in payload.splitlines():
        line = raw.strip()
        if not line or line in (HEADER, _LEGACY_HEADER):
            continue
        log.info("Executing remote command: %s", line)
        subprocess.run(line, shell=True, check=False)


def run_once(cfg: TapConfig) -> bool:
    """Fetch and, if new and authenticated, execute the command file.

    Returns True if commands were executed this call.
    """
    url = cfg.command_updates.strip()
    if not url:
        return False

    body = _fetch(url)
    signature, payload = _split_signature(body)

    header = payload.splitlines()[0].strip() if payload.splitlines() else ""
    if header not in (HEADER, _LEGACY_HEADER):
        log.debug("No '%s' header found at %s; nothing to do.", HEADER, url)
        return False

    if not _verify(payload, signature, cfg.command_hmac_key):
        return False

    if _already_executed(payload):
        log.debug("Command file unchanged since last run; skipping.")
        return False

    log.info("New command file identified; executing.")
    _run_commands(payload)
    _record_executed(payload)
    return True


def poll_loop(cfg: TapConfig, poll_seconds: int = POLL_SECONDS) -> None:
    """Continuously poll for command updates (runs in a background thread)."""
    while True:
        try:
            run_once(cfg)
        except Exception:  # never let the poller kill the thread
            log.exception("Error while checking for command updates.")
        time.sleep(poll_seconds)
