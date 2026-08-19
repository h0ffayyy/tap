import hashlib
import hmac

from tap import commands


def _sign(payload, key):
    return hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def test_split_signature_present():
    sig, payload = commands._split_signature("SIGNATURE=abc\nEXECUTE COMMANDS\nid\n")
    assert sig == "abc"
    assert payload == "EXECUTE COMMANDS\nid"


def test_split_signature_absent():
    sig, payload = commands._split_signature("EXECUTE COMMANDS\nid\n")
    assert sig is None
    assert payload == "EXECUTE COMMANDS\nid\n"


def test_verify_no_key_allows():
    assert commands._verify("EXECUTE COMMANDS\nid", None, "") is True


def test_verify_key_requires_signature():
    assert commands._verify("EXECUTE COMMANDS\nid", None, "secret") is False


def test_verify_valid_signature():
    payload = "EXECUTE COMMANDS\nid"
    assert commands._verify(payload, _sign(payload, "secret"), "secret") is True


def test_verify_wrong_signature():
    payload = "EXECUTE COMMANDS\nid"
    assert commands._verify(payload, _sign(payload, "other"), "secret") is False


def test_dedup_state(tmp_path, monkeypatch):
    state = tmp_path / "last.sha256"
    monkeypatch.setattr(commands, "STATE_PATH", state)
    payload = "EXECUTE COMMANDS\nid"
    assert commands._already_executed(payload) is False
    commands._record_executed(payload)
    assert commands._already_executed(payload) is True
