"""Smoke tests for the CLI wiring (does not touch the system)."""

import pytest

import tap
from tap import cli


def test_version_is_set():
    assert tap.__version__


def test_parser_builds_and_lists_subcommands():
    parser = cli.build_parser()
    # argparse stores the subparsers action; make sure our commands are wired.
    subactions = [a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction"]
    assert subactions, "expected a subparser group"
    choices = set(subactions[0].choices)
    assert {
        "install",
        "uninstall",
        "run",
        "stop",
        "update",
        "status",
        "doctor",
        "config",
    } <= choices
    assert "passwd" not in choices  # password auth removed (key-only)


def test_no_command_errors():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_doctor_timeout_must_be_positive():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["doctor", "--timeout", "0"])
