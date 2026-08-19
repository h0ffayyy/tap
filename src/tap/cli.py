"""Command-line entry point for TAP.

Dispatches the top-level subcommands:

    tap install     configure the host and install the systemd service (root)
    tap uninstall   remove the service and installed files (root)
    tap run         run the reverse-SSH supervisor loop (invoked by systemd)
    tap stop        stop a running TAP daemon
    tap update      pull the latest TAP codebase / config-driven update

Implementation modules are imported lazily inside each handler so the CLI
itself stays importable even on hosts missing the system-level dependencies.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from tap import __version__


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("[!] This command must be run as root.")


def _cmd_install(_args: argparse.Namespace) -> int:
    _require_root()
    from tap import install

    install.install()
    return 0


def _cmd_uninstall(_args: argparse.Namespace) -> int:
    _require_root()
    from tap import install

    install.uninstall()
    return 0


def _cmd_run(_args: argparse.Namespace) -> int:
    from tap import daemon

    daemon.run()
    return 0


def _cmd_stop(_args: argparse.Namespace) -> int:
    from tap import daemon

    daemon.stop()
    return 0


def _cmd_update(_args: argparse.Namespace) -> int:
    from tap import updater

    updater.update()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tap",
        description="The Trusted Access Platform - remote reverse-SSH pentest dropbox.",
    )
    parser.add_argument("--version", action="version", version=f"TAP {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")

    sub = parser.add_subparsers(dest="command", required=True)

    handlers = {
        "install": (_cmd_install, "Configure the host and install the TAP service."),
        "uninstall": (_cmd_uninstall, "Remove TAP and its service from the host."),
        "run": (_cmd_run, "Run the reverse-SSH supervisor loop (used by systemd)."),
        "stop": (_cmd_stop, "Stop a running TAP daemon."),
        "update": (_cmd_update, "Update the TAP codebase per the config."),
    }
    for name, (func, help_text) in handlers.items():
        p = sub.add_parser(name, help=help_text)
        p.set_defaults(func=func)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command in ("install", "uninstall"):
        # Interactive commands get the rich-styled console; the daemon and other
        # commands keep plain logging so journald/systemd output stays plain.
        from tap import ui

        ui.configure_logging(args.verbose)
    else:
        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            format="%(message)s",
            stream=sys.stdout,
        )

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
