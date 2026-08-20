"""Versioned, non-interactive provisioning specifications for TAP.

The installed TAP runtime configuration intentionally remains the compatible
``KEY=value`` format.  This module handles the richer TOML input used by
automation, validates it before installation begins, and keeps secrets out of
rendered plans and JSON output.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tap.config import TapConfig

SCHEMA_VERSION = 1


class ProvisionError(ValueError):
    """Raised when a provisioning file is syntactically or structurally invalid."""


@dataclass(frozen=True)
class KeySettings:
    mode: str
    private_key: Path
    public_key: Path
    public_key_preinstalled: bool


@dataclass(frozen=True)
class InstallationSettings:
    install_packages: bool
    configure_sshd: bool
    configure_proxychains: bool
    client_name: str
    start_service: bool


@dataclass(frozen=True)
class ProvisionSpec:
    config: TapConfig
    key: KeySettings
    installation: InstallationSettings


def _section(data: dict[str, Any], name: str, required: bool = False) -> dict[str, Any]:
    value = data.get(name, {})
    if required and name not in data:
        raise ProvisionError(f"missing required [{name}] section")
    if not isinstance(value, dict):
        raise ProvisionError(f"[{name}] must be a TOML table")
    return value


def _unknown(section: dict[str, Any], allowed: set[str], name: str) -> None:
    extras = sorted(set(section) - allowed)
    if extras:
        raise ProvisionError(f"unknown key(s) in [{name}]: {', '.join(extras)}")


def _string(section: dict[str, Any], key: str, *, default: str | None = None) -> str:
    value = section.get(key, default)
    if not isinstance(value, str):
        raise ProvisionError(f"{key} must be a string")
    return value.strip()


def _port(section: dict[str, Any], key: str, default: int) -> str:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ProvisionError(f"{key} must be an integer port")
    return str(value)


def _bool(section: dict[str, Any], key: str, default: bool) -> bool:
    value = section.get(key, default)
    if not isinstance(value, bool):
        raise ProvisionError(f"{key} must be true or false")
    return value


def _secret(commands: dict[str, Any], environ: Mapping[str, str]) -> str:
    key_file = commands.get("hmac_key_file")
    key_env = commands.get("hmac_key_env")
    if key_file is not None and key_env is not None:
        raise ProvisionError("use only one of hmac_key_file or hmac_key_env")
    if key_file is None and key_env is None:
        return ""
    if key_file is not None:
        if not isinstance(key_file, str) or not key_file.strip():
            raise ProvisionError("hmac_key_file must be a non-empty string")
        try:
            return Path(key_file).read_text().strip()
        except OSError as exc:
            raise ProvisionError(f"could not read hmac_key_file: {exc}") from exc
    if not isinstance(key_env, str) or not key_env.strip():
        raise ProvisionError("hmac_key_env must be a non-empty string")
    value = environ.get(key_env)
    if not value:
        raise ProvisionError(f"hmac_key_env {key_env!r} is unset or empty")
    return value


def load(path: Path, environ: Mapping[str, str] | None = None) -> ProvisionSpec:
    """Load one strict, versioned TOML provisioning file."""
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ProvisionError(f"could not load {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProvisionError("provisioning file must contain a TOML table")
    _unknown(data, {"schema_version", "connection", "ssh", "commands", "installation"}, "root")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ProvisionError(f"schema_version must be {SCHEMA_VERSION}")

    connection = _section(data, "connection", required=True)
    ssh = _section(data, "ssh", required=True)
    commands = _section(data, "commands")
    installation = _section(data, "installation")
    _unknown(connection, {"host", "port", "username", "remote_port", "socks_port"}, "connection")
    _unknown(
        ssh,
        {"key_mode", "private_key", "public_key", "public_key_preinstalled", "permit_root_login"},
        "ssh",
    )
    _unknown(commands, {"url", "hmac_key_file", "hmac_key_env"}, "commands")
    _unknown(
        installation,
        {
            "install_packages",
            "configure_sshd",
            "configure_proxychains",
            "client_name",
            "start_service",
        },
        "installation",
    )

    private_key = Path(_string(ssh, "private_key", default="/root/.ssh/id_rsa"))
    public_key = Path(_string(ssh, "public_key", default=f"{private_key}.pub"))
    cfg = TapConfig(
        ipaddr=_string(connection, "host"),
        port=_port(connection, "port", 22),
        username=_string(connection, "username"),
        local_port=_port(connection, "remote_port", 10003),
        socks_proxy_port=_port(connection, "socks_port", 10004),
        identity_file=str(private_key),
        command_updates=_string(commands, "url", default=""),
        command_hmac_key=_secret(commands, environ or os.environ),
        permit_root_login="yes" if _bool(ssh, "permit_root_login", False) else "no",
    )
    return ProvisionSpec(
        config=cfg,
        key=KeySettings(
            mode=_string(ssh, "key_mode"),
            private_key=private_key,
            public_key=public_key,
            public_key_preinstalled=_bool(ssh, "public_key_preinstalled", False),
        ),
        installation=InstallationSettings(
            install_packages=_bool(installation, "install_packages", True),
            configure_sshd=_bool(installation, "configure_sshd", True),
            configure_proxychains=_bool(installation, "configure_proxychains", True),
            client_name=_string(installation, "client_name", default=""),
            start_service=_bool(installation, "start_service", True),
        ),
    )


def _valid_port(value: str) -> bool:
    try:
        return 1 <= int(value) <= 65535
    except ValueError:
        return False


def validate(spec: ProvisionSpec) -> list[str]:
    """Return all preflight errors without mutating the host."""
    errors: list[str] = []
    cfg = spec.config
    if not cfg.ipaddr:
        errors.append("connection.host must not be empty")
    if not cfg.username:
        errors.append("connection.username must not be empty")
    for name, value in (("connection.port", cfg.port), ("connection.remote_port", cfg.local_port)):
        if not _valid_port(value):
            errors.append(f"{name} must be within 1-65535")
    if cfg.socks_proxy_port and not _valid_port(cfg.socks_proxy_port):
        errors.append("connection.socks_port must be within 1-65535")
    if cfg.command_updates and not cfg.command_updates.lower().startswith("https://"):
        errors.append("commands.url must use HTTPS")
    if cfg.command_updates and not cfg.command_hmac_key:
        errors.append("commands.url requires hmac_key_file or hmac_key_env")
    if spec.key.mode not in {"existing", "generate"}:
        errors.append("ssh.key_mode must be 'existing' or 'generate'")
    for name, path in (
        ("ssh.private_key", spec.key.private_key),
        ("ssh.public_key", spec.key.public_key),
    ):
        if not path.is_absolute():
            errors.append(f"{name} must be an absolute path")
    if spec.key.mode == "existing":
        if not spec.key.private_key.is_file():
            errors.append(f"ssh.private_key does not exist: {spec.key.private_key}")
        if not spec.key.public_key.is_file():
            errors.append(f"ssh.public_key does not exist: {spec.key.public_key}")
        if spec.installation.start_service and not spec.key.public_key_preinstalled:
            errors.append(
                "start_service requires ssh.public_key_preinstalled=true for an existing key"
            )
    if spec.key.mode == "generate":
        if spec.key.private_key.exists() or spec.key.public_key.exists():
            errors.append("refusing to overwrite an existing generated key path")
        if spec.key.public_key_preinstalled:
            errors.append("generated keys cannot be declared preinstalled")
        if spec.installation.start_service:
            errors.append("generated keys require installation.start_service=false")
    return errors


def render(spec: ProvisionSpec) -> dict[str, Any]:
    """Return a safe, secret-free representation for plans and JSON output."""
    return {
        "schema_version": SCHEMA_VERSION,
        "connection": {
            "host": spec.config.ipaddr,
            "port": int(spec.config.port),
            "username": spec.config.username,
            "remote_port": int(spec.config.local_port),
            "socks_port": int(spec.config.socks_proxy_port)
            if spec.config.socks_proxy_port
            else None,
        },
        "ssh": {
            "key_mode": spec.key.mode,
            "private_key": str(spec.key.private_key),
            "public_key": str(spec.key.public_key),
            "public_key_preinstalled": spec.key.public_key_preinstalled,
            "permit_root_login": spec.config.permit_root_login,
        },
        "commands": {
            "enabled": bool(spec.config.command_updates),
            "hmac_configured": bool(spec.config.command_hmac_key),
        },
        "installation": {
            "install_packages": spec.installation.install_packages,
            "configure_sshd": spec.installation.configure_sshd,
            "configure_proxychains": spec.installation.configure_proxychains,
            "client_name": spec.installation.client_name,
            "start_service": spec.installation.start_service,
        },
    }
