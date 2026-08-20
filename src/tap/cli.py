"""Command-line entry point for TAP.

Dispatches the top-level subcommands:

    tap install     configure the host and install the systemd service (root)
    tap uninstall   remove the service and installed files (root)
    tap run         run the reverse-SSH supervisor loop (invoked by systemd)
    tap stop        stop a running TAP daemon
    tap update      pull the latest TAP codebase / config-driven update
    tap status      show the local TAP service and tunnel state
    tap doctor      run read-only local and gateway diagnostics

Implementation modules are imported lazily inside each handler so the CLI
itself stays importable even on hosts missing the system-level dependencies.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from tap import __version__


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("[!] This command must be run as root.")


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return timeout


def _print_provision(payload: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True))
        return
    print(f"TAP provisioning: {payload['result'].upper()}")
    for error in payload.get("errors", []):
        print(f"  ERROR  {error}")
    for operation in payload.get("operations", []):
        print(
            f"  {operation['operation']:<16} {operation['status'].upper():<9} {operation['summary']}"
        )


def _cmd_install(args: argparse.Namespace) -> int:
    if not args.config:
        if args.non_interactive or args.dry_run or args.json:
            raise SystemExit("--non-interactive, --dry-run, and --json require --config")
        _require_root()
        from tap import install

        install.install()
        return 0
    if not args.non_interactive:
        raise SystemExit("--config requires --non-interactive")
    if not args.dry_run:
        _require_root()

    from tap import install, provision

    try:
        spec = provision.load(Path(args.config))
    except provision.ProvisionError as exc:
        _print_provision({"result": "invalid", "errors": [str(exc)]}, args.json)
        return 2
    errors = provision.validate(spec)
    if errors:
        _print_provision({"result": "invalid", "errors": errors}, args.json)
        return 2
    try:
        operations = install.install_noninteractive(spec, dry_run=args.dry_run)
    except install.InstallationError as exc:
        _print_provision({"result": "failed", "errors": [str(exc)]}, args.json)
        return 1
    _print_provision(
        {
            "result": "planned" if args.dry_run else "success",
            "provision": provision.render(spec),
            "operations": install.operation_dicts(operations),
        },
        args.json,
    )
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


def _cmd_diagnostics(args: argparse.Namespace) -> int:
    from tap import diagnostics

    report = (
        diagnostics.collect_doctor(timeout=args.timeout)
        if args.command == "doctor"
        else diagnostics.collect_status()
    )
    if not args.quiet:
        output = diagnostics.render_json(report) if args.json else diagnostics.render_human(report)
        print(output)
    return report.exit_code


def _cmd_config(args: argparse.Namespace) -> int:
    from tap import provision

    try:
        spec = provision.load(Path(args.file))
    except provision.ProvisionError as exc:
        payload: dict[str, Any] = {"result": "invalid", "errors": [str(exc)]}
        _print_provision(payload, args.json)
        return 2
    errors = provision.validate(spec)
    if args.config_action == "validate":
        payload = {"result": "valid" if not errors else "invalid", "errors": errors}
    else:
        payload = {
            "result": "valid" if not errors else "invalid",
            "errors": errors,
            "provision": provision.render(spec),
        }
    _print_provision(payload, args.json)
    return 0 if not errors else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tap",
        description="The Trusted Access Platform - remote reverse-SSH access dropbox.",
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
        "status": (_cmd_diagnostics, "Show the local TAP service and tunnel status."),
        "doctor": (_cmd_diagnostics, "Run read-only TAP health diagnostics."),
        "config": (_cmd_config, "Validate or render a TAP provisioning file."),
    }
    for name, (func, help_text) in handlers.items():
        p = sub.add_parser(name, help=help_text)
        if name in {"status", "doctor"}:
            p.add_argument(
                "--json", action="store_true", help="Write a machine-readable JSON report."
            )
            p.add_argument(
                "--quiet", action="store_true", help="Suppress output; use only the exit code."
            )
        if name == "doctor":
            p.add_argument(
                "--timeout",
                type=_positive_timeout,
                default=5,
                help="Maximum seconds for each network check.",
            )
        if name == "install":
            p.add_argument("--config", help="Versioned TOML provisioning file.")
            p.add_argument(
                "--non-interactive", action="store_true", help="Never prompt; requires --config."
            )
            p.add_argument(
                "--dry-run", action="store_true", help="Validate and show planned changes only."
            )
            p.add_argument("--json", action="store_true", help="Write a machine-readable result.")
        if name == "config":
            config_sub = p.add_subparsers(dest="config_action", required=True)
            for action in ("validate", "render"):
                action_parser = config_sub.add_parser(
                    action, help=f"{action.title()} a provisioning file."
                )
                action_parser.add_argument("file", help="TOML provisioning file.")
                action_parser.add_argument(
                    "--json", action="store_true", help="Write a machine-readable result."
                )
        p.set_defaults(func=func)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "uninstall" or (args.command == "install" and not args.config):
        # Interactive commands get the rich-styled console; the daemon and other
        # commands keep plain logging so journald/systemd output stays plain.
        from tap import ui

        ui.configure_logging(args.verbose)
    else:
        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            format="%(message)s",
            stream=sys.stderr if getattr(args, "json", False) else sys.stdout,
        )

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
