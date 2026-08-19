# The TrustedSec Attack Platform (TAP)

**TAP** is a remote penetration-testing dropbox builder, by David Kennedy
([@HackingDave](https://github.com/HackingDave)) /
[TrustedSec](https://www.trustedsec.com).

You pre-configure a fresh Linux box, run `tap install`, and TAP stands up a
self-healing **reverse SSH tunnel** back to a server you control. From that
server you can reach the dropbox locally. TAP rebuilds the tunnel automatically
when it drops, and can optionally poll a URL for commands as a fallback control
path if the tunnel is lost entirely.

> **2.0** is a full modernization: an installable package with a single `tap`
> CLI, systemd-managed service, AES-256-GCM password storage, verified SSH host
> keys, root login off by default, and an optionally-authenticated command
> channel. See [CHANGELOG.md](CHANGELOG.md).

## Install

Requires Python 3.11+; install and run as **root** on the dropbox.

```bash
sudo pip install .        # or: sudo uv pip install --system .
sudo tap install          # interactive: remote server, ports, auth method
```

The installer writes `/usr/share/tap/config`, configures `sshd`, installs the
systemd unit, and offers to start TAP. Remove everything with `sudo tap uninstall`.

## Commands

| Command | Description |
| --- | --- |
| `tap install` / `tap uninstall` | Install or remove TAP on the host (root). |
| `tap run` / `tap stop` | Run or stop the reverse-SSH supervisor (systemd uses these). |
| `tap update` | Update the TAP codebase per the config. |
| `tap passwd` | Re-encrypt and store a new SSH password. |

## Accessing the dropbox

TAP binds a local port on your remote server. From that server:

```bash
ssh username@localhost -p <LOCAL_PORT>
```

Use a **non-root** account on the remote server for the tunnel.

## Authentication

SSH keys are the default and recommended method — `tap install` generates an
ed25519 pair and uploads the public key. Password auth is also supported; the
password is stored with AES-256-GCM under a per-box key in `/root/.tap/store`.
This is obfuscation-at-rest (a root attacker can still recover it), so **prefer
keys**. Rotate a stored password with `sudo tap passwd`.

## Remote command channel

Point `COMMAND_UPDATES` at an HTTPS URL and TAP polls it every two minutes.
File format:

```
SIGNATURE=<hex hmac-sha256 of the lines below>   # required only if COMMAND_HMAC_KEY is set
EXECUTE COMMANDS
<shell command 1>
<shell command 2>
```

Set `COMMAND_HMAC_KEY` to require a valid signature (unsigned files are then
refused). Each distinct file runs once.

## More

- **Proxychains** — `proxychains4 <command>` routes traffic over the SSH SOCKS proxy.
- **VPN** — `scripts/ssh-tunnel.sh` (Geoff Walton, TrustedSec) creates a full
  `tun` VPN over SSH; run as root, `-h` for usage. `sshuttle` also works for
  low-volume traffic.
- **Logging** — with `LOG_EVERYTHING`, all SSH commands are logged to syslog.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy src/tap && pytest
```

Runs on Debian/Ubuntu with systemd; CI covers Python 3.11–3.14.
