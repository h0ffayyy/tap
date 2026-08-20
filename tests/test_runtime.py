import json

from tap import runtime


def test_write_and_load_state(tmp_path):
    path = tmp_path / "status.json"
    runtime.write_state("connecting", path, supervisor_pid=123)
    state = runtime.load_state(path)
    assert state is not None
    assert state["schema_version"] == 1
    assert state["state"] == "connecting"
    assert state["supervisor_pid"] == 123
    assert state["updated_at"].endswith("Z")
    assert (path.stat().st_mode & 0o777) == 0o640


def test_write_state_preserves_existing_values(tmp_path):
    path = tmp_path / "status.json"
    runtime.write_state("connecting", path, supervisor_pid=123)
    runtime.write_state("connected", path, ssh_pid=456)
    assert runtime.load_state(path) == {
        "schema_version": 1,
        "state": "connected",
        "supervisor_pid": 123,
        "ssh_pid": 456,
        "updated_at": runtime.load_state(path)["updated_at"],
    }


def test_backoff_increments_reconnect_attempts(tmp_path):
    path = tmp_path / "status.json"
    runtime.write_state("backoff", path)
    runtime.write_state("backoff", path)
    assert runtime.load_state(path)["reconnect_attempts"] == 2


def test_load_state_rejects_malformed_json(tmp_path):
    path = tmp_path / "status.json"
    path.write_text("not json")
    assert runtime.load_state(path) is None


def test_state_is_json_document(tmp_path):
    path = tmp_path / "status.json"
    runtime.write_state("stopped", path)
    assert json.loads(path.read_text())["state"] == "stopped"
