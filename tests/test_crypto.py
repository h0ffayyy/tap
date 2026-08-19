import base64

import pytest

from tap import crypto


def test_encrypt_decrypt_roundtrip(tmp_path):
    key = tmp_path / "store"
    blob = crypto.encrypt_password("hunter2", key_path=key)
    assert blob and blob != "hunter2"
    assert crypto.decrypt_password(blob, key_path=key) == "hunter2"


def test_key_file_created_root_only(tmp_path):
    key = tmp_path / "store"
    crypto.encrypt_password("x", key_path=key)
    assert key.is_file()
    assert (key.stat().st_mode & 0o777) == 0o600


def test_decrypt_without_key_returns_empty(tmp_path):
    assert crypto.decrypt_password("whatever", key_path=tmp_path / "missing") == ""


def test_decrypt_empty_blob_returns_empty(tmp_path):
    key = tmp_path / "store"
    crypto.encrypt_password("x", key_path=key)
    assert crypto.decrypt_password("", key_path=key) == ""


def test_tampered_ciphertext_is_rejected(tmp_path):
    key = tmp_path / "store"
    blob = crypto.encrypt_password("secret", key_path=key)
    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 0x01  # flip a ciphertext bit
    tampered = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(ValueError):
        crypto.decrypt_password(tampered, key_path=key)


def test_unique_nonce_per_encryption(tmp_path):
    key = tmp_path / "store"
    a = crypto.encrypt_password("same", key_path=key)
    b = crypto.encrypt_password("same", key_path=key)
    assert a != b  # random nonce -> different blobs
