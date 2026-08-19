import logging

from rich.logging import RichHandler

from tap import ui


def test_run_step_success_returns_completed_process():
    result = ui.run_step("noop", ["true"])
    assert result.returncode == 0


def test_run_step_failure_does_not_raise():
    result = ui.run_step("failing", ["sh", "-c", "exit 3"])
    assert result.returncode == 3


def test_ask_returns_default_on_empty_input(monkeypatch):
    monkeypatch.setattr(ui.console, "input", lambda *a, **k: "")
    assert ui.ask("Host", default="example.com") == "example.com"


def test_confirm_returns_default_on_empty_input(monkeypatch):
    monkeypatch.setattr(ui.console, "input", lambda *a, **k: "")
    assert ui.confirm("Proceed?", default=True) is True
    assert ui.confirm("Proceed?", default=False) is False


def test_configure_logging_attaches_rich_handler():
    root = logging.getLogger()
    original = root.handlers[:]
    try:
        ui.configure_logging(verbose=False)
        assert any(isinstance(h, RichHandler) for h in root.handlers)
    finally:
        root.handlers = original
