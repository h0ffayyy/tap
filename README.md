# The TrustedSec Attack Platform (TAP)

**TAP** is a remote penetration-testing dropbox builder.

- Written by: David Kennedy ([@HackingDave](https://github.com/HackingDave))
- Company: TrustedSec (<https://www.trustedsec.com>)
- Project page: <https://github.com/trustedsec/tap>
- Supported OS: Linux (Debian/Ubuntu preferred)

## What is TAP?

For folks in the security industry, travel adds real cost and burden to an
engagement. TAP makes deploying a remote testing box simple, self-healing, and
stable. You pre-configure a fresh machine, run the TAP installer, and it stands
up a service that establishes a **reverse SSH tunnel** back to a server you
control on the Internet. From that server you can reach the dropbox locally.
TAP detects when the tunnel goes stale and rebuilds it automatically.

If the tunnel is lost entirely, TAP can also poll a URL for a command file and
execute it — a fallback control path to recover the box.

## What changed in 2.0

Version 2.0 is a modernization of the codebase:

- Installs as a proper Python package (`pip`/`uv`) exposing a single `tap` CLI.
- Managed by **systemd** (`tap.service`) instead of the old init.d + heartbeat
  chain; liveness is handled by `Restart=always`.
- Password storage now uses real authenticated encryption (**AES-256-GCM**),
  replacing the previous broken ECB scheme.
- SSH host keys are **verified** (`StrictHostKeyChecking=accept-new`) instead of
  `known_hosts` being wiped before every connection.
- Root SSH login defaults to **off**; enable it explicitly at install time.
- The remote-command channel is fixed and supports optional **HMAC-SHA256**
  authentication of command files.
- Typed configuration, `logging`, targeted error handling, tests, linting
  (ruff), type checking (mypy), and CI.

See [CHANGELOG.md](CHANGELOG.md) for the full history.

## Installation

TAP requires Python 3.11+ and must be installed and run as **root** on the
dropbox.

```bash
# from a checkout of this repo
sudo pip install .
# or, with uv
sudo uv pip install --system .
```

Then configure and install the service:

```bash
sudo tap install
```

The installer prompts for the remote SSH server, ports, authentication method
(SSH keys are the recommended default), and optional remote-command URL. It
writes `/usr/share/tap/config`, configures `sshd`, installs the systemd unit,
and offers to start TAP immediately.

### Uninstall

```bash
sudo tap uninstall
```

## The `tap` command

| Command          | Description                                              |
| ---------------- | ------------------------------------------------------- |
| `tap install`    | Configure the host and install the TAP service (root).  |
| `tap uninstall`  | Remove TAP and its service from the host (root).        |
| `tap run`        | Run the reverse-SSH supervisor loop (used by systemd).  |
| `tap stop`       | Stop a running TAP daemon.                              |
| `tap update`     | Update the TAP codebase per the config.                 |
| `tap passwd`     | Re-encrypt and store a new SSH password.                |

## Accessing the dropbox

When TAP connects back to your remote server it binds a **local port** there.
From the remote server:

```bash
ssh username@localhost -p <LOCAL_PORT>
```

Use a **non-root** account on the remote server for the tunnel — it only needs
to hold the reverse port forward, not privileged access.

## Authentication

SSH keys are the recommended (and default) method. TAP generates an
**ed25519** key pair and uploads the public key to your remote server during
`tap install`.

If you choose password authentication, the password is encrypted at rest with
AES-256-GCM using a per-box key stored in `/root/.tap/store` (mode `0600`).
Note this is obfuscation-at-rest, not a secret split from its key: a root
attacker with persistent access to the box can still recover it. **Prefer SSH
keys.** To rotate a stored password later, run `sudo tap passwd`.

## Remote command channel

Set a `COMMAND_UPDATES` URL (HTTPS recommended) in the config and TAP polls it
every two minutes. The file format is:

```
SIGNATURE=<hex hmac-sha256 of everything below this line>   # optional
EXECUTE COMMANDS
<shell command 1>
<shell command 2>
```

If you set `COMMAND_HMAC_KEY` in the config (or at install time), a valid
`SIGNATURE=` line becomes **required** and unsigned/mis-signed files are
refused. Each distinct file is executed once. To generate a signature:

```bash
printf 'EXECUTE COMMANDS\nid\nwhoami\n' > payload.txt
sig=$(openssl dgst -sha256 -hmac "$COMMAND_HMAC_KEY" -hex payload.txt | awk '{print $NF}')
{ echo "SIGNATURE=$sig"; cat payload.txt; } > commands.txt
```

## Proxychains

TAP configures `proxychains4` (proxychains-ng) to tunnel HTTP/HTTPS traffic
through the SSH SOCKS proxy. Prefix a command with `proxychains4` to route it
over the tunnel, e.g. `proxychains4 apt-get update`.

## SSH VPN tunneling

Two options for a full VPN into the remote network:

1. **sshuttle** — good for low-volume traffic. Install `sshuttle`, then forward
   the TAP local port and point sshuttle at it:

   ```bash
   ssh -f user@remote-server -L 10003:localhost:22 -N
   sshuttle --dns -vr user@localhost:10003 0/0
   ```

   Note: port scans and other high-volume traffic do not work well over
   sshuttle — prefer the transparent VPN below for those.

2. **Transparent VPN** — `scripts/ssh-tunnel.sh` (by Geoff Walton, TrustedSec)
   creates a `tun` interface and VPNs you into the system over SSH. Run it as
   root; `-h` prints usage.

## Logging

If enabled at install time (`LOG_EVERYTHING`), every command run over SSH on the
dropbox is logged to syslog (`/var/log/messages`), so you can hand records to
the customer.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy src/tap
pytest
```

CI runs the same checks across Python 3.11–3.14.

## Supported operating systems

Debian/Ubuntu with systemd. Tested against current Ubuntu LTS releases.
