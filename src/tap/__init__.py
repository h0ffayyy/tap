"""The Trusted Access Platform (TAP).

A remote penetration-testing dropbox builder: it installs a self-healing
reverse-SSH tunnel back to a server you control, so a pre-configured box can
be dropped on a target network and reached from the outside.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

__version__ = "2.0.0"

# Filesystem location TAP installs itself to when deployed on a host.
INSTALL_DIR = Path("/usr/share/tap")


def data_path(name: str) -> Path:
    """Return the on-disk path to a bundled data asset (motd, unit file, image)."""
    return Path(str(resources.files("tap.data") / name))
