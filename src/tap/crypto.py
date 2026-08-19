"""Authenticated encryption for the stored SSH password.

TAP needs to feed a password to ``ssh`` non-interactively, so the password must
be recoverable on the box. This is obfuscation-at-rest, not a secret split from
its key: a root attacker with persistent access can still recover it (SSH keys
remain the recommended, and default, option). What this module *does* guarantee
is a correct, authenticated construction -- AES-256-GCM with a random per-box
key -- instead of the previous broken, unauthenticated ECB scheme.

Blob format (base64 of):  nonce(12) || tag(16) || ciphertext
Key file:                 base64 of a random 32-byte key, mode 0600.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from Crypto.Cipher import AES

KEY_DIR = Path("/root/.tap")
KEY_PATH = KEY_DIR / "store"

_KEY_LEN = 32
_NONCE_LEN = 12
_TAG_LEN = 16


def _load_or_create_key(key_path: Path) -> bytes:
    if key_path.is_file():
        return base64.b64decode(key_path.read_text().strip())
    key_path.parent.mkdir(mode=0o700, exist_ok=True)
    key = os.urandom(_KEY_LEN)
    key_path.write_text(base64.b64encode(key).decode())
    key_path.chmod(0o600)
    return key


def encrypt_password(plaintext: str, key_path: Path = KEY_PATH) -> str:
    """Encrypt ``plaintext`` with a per-box key, returning the config blob.

    A key is generated and stored at ``key_path`` on first use.
    """
    key = _load_or_create_key(key_path)
    cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(_NONCE_LEN))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(bytes(cipher.nonce) + tag + ciphertext).decode()


def decrypt_password(blob: str, key_path: Path = KEY_PATH) -> str:
    """Decrypt a config blob produced by :func:`encrypt_password`.

    Returns an empty string when no blob or key is available. Raises
    ``ValueError`` if the ciphertext fails authentication (tampering).
    """
    if not blob or not key_path.is_file():
        return ""
    key = base64.b64decode(key_path.read_text().strip())
    raw = base64.b64decode(blob)
    nonce = raw[:_NONCE_LEN]
    tag = raw[_NONCE_LEN : _NONCE_LEN + _TAG_LEN]
    ciphertext = raw[_NONCE_LEN + _TAG_LEN :]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()
