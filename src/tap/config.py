"""Typed loading and writing of the TAP config file.

The on-disk format is the historical ``KEY=value`` line format (``#`` comments
and blank lines ignored) so existing deployments keep working, but it is parsed
into a typed :class:`TapConfig` instead of being re-scraped with regexes on
every access.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path

from tap import INSTALL_DIR

CONFIG_PATH = INSTALL_DIR / "config"


def _parse_lines(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"')
    return values


@dataclass
class TapConfig:
    """Parsed TAP configuration.

    Field names map to the historical uppercase config keys via
    :data:`_KEY_MAP`. All values are stored as strings except where a typed
    accessor is provided.
    """

    username: str = "root"
    ipaddr: str = ""
    port: str = "22"
    local_port: str = "10003"
    socks_proxy_port: str = "10004"
    # The SSH identity used for the reverse tunnel.  Keeping the historical
    # root key as the default preserves existing installations while allowing
    # non-interactive provisioning to use a pre-authorized per-device key.
    identity_file: str = "/root/.ssh/id_rsa"
    command_updates: str = ""
    auto_update: str = "OFF"
    update_server: str = "git pull"
    ssh_check_interval: str = "60"
    log_everything: str = "ON"
    permit_root_login: str = "no"
    # Optional shared secret; when set, remote command files must carry a valid
    # HMAC-SHA256 signature line or they are refused (see tap.commands).
    command_hmac_key: str = field(default="", repr=False)

    # --- typed convenience accessors -------------------------------------

    @property
    def check_interval(self) -> int:
        try:
            return int(self.ssh_check_interval)
        except ValueError:
            return 60

    @property
    def auto_update_enabled(self) -> bool:
        return self.auto_update.strip().lower() == "on"

    @property
    def log_enabled(self) -> bool:
        return self.log_everything.strip().lower() in {"on", "yes", "true"}

    # --- (de)serialization -----------------------------------------------

    @classmethod
    def load(cls, path: Path | None = None) -> TapConfig:
        path = path or CONFIG_PATH
        values = _parse_lines(path.read_text())
        kwargs: dict[str, str] = {}
        for name, key in _KEY_MAP.items():
            if key in values:
                kwargs[name] = values[key]
        return cls(**kwargs)

    def to_text(self) -> str:
        lines = [
            "# TAP Configuration File",
            "#",
            "# SSH Connection Settings",
            f"USERNAME={self.username}",
            f"IPADDR={self.ipaddr}",
            f"PORT={self.port}",
            f"LOCAL_PORT={self.local_port}",
            f"SOCKS_PROXY_PORT={self.socks_proxy_port}",
            f"IDENTITY_FILE={self.identity_file}",
            "",
            "# Update Settings",
            f"COMMAND_UPDATES={self.command_updates}",
            f"AUTO_UPDATE={self.auto_update}",
            f"UPDATE_SERVER={self.update_server}",
            "",
            "# SSH Settings",
            f"SSH_CHECK_INTERVAL={self.ssh_check_interval}",
            "# Allow root login over SSH on this host (yes/no/prohibit-password)",
            f"PERMIT_ROOT_LOGIN={self.permit_root_login}",
            "# Optional HMAC-SHA256 key authenticating remote command files (empty = unauthenticated)",
            f"COMMAND_HMAC_KEY={self.command_hmac_key}",
            "",
            "# Logging (log every SSH command to syslog)",
            f"LOG_EVERYTHING={self.log_everything}",
            "",
        ]
        return "\n".join(lines)

    def save(self, path: Path | None = None) -> None:
        path = path or CONFIG_PATH
        path.write_text(self.to_text())
        path.chmod(0o600)


_KEY_MAP: dict[str, str] = {f.name: f.name.upper() for f in fields(TapConfig)}
