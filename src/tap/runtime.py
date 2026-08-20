"""Ephemeral, atomic runtime state for TAP's supervisor.

The daemon writes a small status document under ``/run`` so operator-facing
commands do not have to infer tunnel health from fragile process-name matches.
It intentionally contains operational metadata only: never credentials,
command payloads, or private-key material.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RUNTIME_DIR = Path("/run/tap")
STATE_PATH = RUNTIME_DIR / "status.json"
SCHEMA_VERSION = 1


def now() -> str:
    """Return an unambiguous UTC timestamp suitable for the state document."""
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_state(path: Path | None = None) -> dict[str, Any] | None:
    """Read runtime state, returning ``None`` when it is absent or malformed."""
    path = path or STATE_PATH
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def write_state(state: str, path: Path | None = None, **values: Any) -> None:
    """Atomically publish a runtime-state transition.

    Existing fields are retained unless overwritten, which lets reconnect
    transitions preserve useful context such as the connection start time.
    """
    path = path or STATE_PATH
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    data = load_state(path) or {"schema_version": SCHEMA_VERSION}
    data.update(values)
    data["schema_version"] = SCHEMA_VERSION
    if state == "backoff":
        try:
            data["reconnect_attempts"] = int(data.get("reconnect_attempts", 0)) + 1
        except (TypeError, ValueError):
            data["reconnect_attempts"] = 1
    data["state"] = state
    data["updated_at"] = now()

    fd, temporary = tempfile.mkstemp(prefix=".status-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    except Exception:
        with suppress(OSError):
            os.unlink(temporary)
        raise
