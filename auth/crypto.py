"""
Cryptographic helpers for the auth subsystem.

Key separation
--------------
Everything here is keyed from MFA_ENCRYPTION_KEY - never from SECRET_KEY. So:
  * rotating SECRET_KEY only invalidates sessions / CSRF tokens;
  * rotating MFA_ENCRYPTION_KEY is supported without invalidating anything: put the old
    key(s) in MFA_ENCRYPTION_KEY_PREVIOUS, run scripts/rotate_keys.py to re-encrypt
    stored TOTP secrets, and keep the previous key listed until the remaining keyed
    hashes (recovery codes, trusted devices) have been used, regenerated or expired.

What is protected
-----------------
* TOTP secrets: encrypted at rest.
    - Preferred: Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` package.
    - Fallback:  stdlib HMAC-SHA256 counter-mode + encrypt-then-MAC when `cryptography`
      cannot be installed (dev/test only; production requires cryptography).
  Ciphertexts are prefixed so formats and key generations can coexist.
* One-time codes, recovery codes, trusted-device tokens and password-reset tokens: stored
  as keyed hashes (HMAC-SHA256) so a database leak alone does not reveal them.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from flask import current_app

try:  # optional compiled dependency
    from cryptography.fernet import Fernet, InvalidToken

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - exercised on platforms without wheels
    Fernet = InvalidToken = None  # type: ignore[assignment]
    HAVE_CRYPTOGRAPHY = False

STDLIB_PREFIX = "hs1:"


def backend_name() -> str:
    return "cryptography/Fernet" if HAVE_CRYPTOGRAPHY else "stdlib HMAC-CTR fallback"


# ------------------------------------------------------------------- keys

def _material(key: str) -> bytes:
    """32 raw bytes from a configured key (Fernet-formatted or any string)."""
    try:
        raw = base64.urlsafe_b64decode(key.encode())
        if len(raw) == 32:
            return raw
    except (ValueError, TypeError):
        pass
    return hashlib.sha256(("mfa:" + key).encode()).digest()


def _current_key() -> bytes:
    key = current_app.config.get("MFA_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("MFA_ENCRYPTION_KEY is not configured")
    return _material(key)


def _all_keys() -> list[bytes]:
    """Current key first, then previous generations (for verification / decryption only)."""
    keys = [_current_key()]
    for old in current_app.config.get("MFA_ENCRYPTION_KEY_PREVIOUS") or []:
        keys.append(_material(old))
    return keys


def _subkey(material: bytes, purpose: bytes) -> bytes:
    return hmac.new(material, purpose, hashlib.sha256).digest()


# --------------------------------------------------------------- Fernet path

def _fernet(material: bytes):
    return Fernet(base64.urlsafe_b64encode(material))


# --------------------------------------------------------------- stdlib path

def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(enc_key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _stdlib_encrypt(plaintext: bytes, material: bytes | None = None) -> str:
    material = material or _current_key()
    enc_key, mac_key = _subkey(material, b"enc"), _subkey(material, b"mac")
    nonce = os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(enc_key, nonce, len(plaintext))))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return STDLIB_PREFIX + base64.urlsafe_b64encode(nonce + ct + tag).decode()


def _stdlib_decrypt(token: str, material: bytes) -> bytes | None:
    try:
        blob = base64.urlsafe_b64decode(token[len(STDLIB_PREFIX):].encode())
    except (ValueError, TypeError):
        return None
    if len(blob) < 48:
        return None
    nonce, ct, tag = blob[:16], blob[16:-32], blob[-32:]
    enc_key, mac_key = _subkey(material, b"enc"), _subkey(material, b"mac")
    if not hmac.compare_digest(hmac.new(mac_key, nonce + ct, hashlib.sha256).digest(), tag):
        return None
    return bytes(a ^ b for a, b in zip(ct, _keystream(enc_key, nonce, len(ct))))


# ------------------------------------------------------------------ public

def encrypt_secret(plaintext: str) -> str:
    """Encrypt with the CURRENT key."""
    if HAVE_CRYPTOGRAPHY:
        return _fernet(_current_key()).encrypt(plaintext.encode()).decode()
    return _stdlib_encrypt(plaintext.encode())


def _decrypt_with(ciphertext: str, material: bytes) -> str | None:
    if ciphertext.startswith(STDLIB_PREFIX):
        raw = _stdlib_decrypt(ciphertext, material)
        return raw.decode() if raw is not None else None
    if not HAVE_CRYPTOGRAPHY:
        return None
    try:
        return _fernet(material).decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return None


def decrypt_secret(ciphertext: str) -> str | None:
    """Decrypt with the current key, falling back to previous key generations."""
    for material in _all_keys():
        value = _decrypt_with(ciphertext, material)
        if value is not None:
            return value
    if not HAVE_CRYPTOGRAPHY and not ciphertext.startswith(STDLIB_PREFIX):
        current_app.logger.error("Fernet ciphertext found but `cryptography` is not installed.")
    return None


def needs_reencryption(ciphertext: str) -> bool:
    """True if the value is not decryptable with the current key (i.e. uses a previous key)."""
    return _decrypt_with(ciphertext, _current_key()) is None and decrypt_secret(ciphertext) is not None


def keyed_hash(value: str) -> str:
    """HMAC-SHA256 hex digest keyed with the CURRENT key (for storing new values)."""
    return hmac.new(_subkey(_current_key(), b"hash"), value.encode(), hashlib.sha256).hexdigest()


def keyed_hash_candidates(value: str) -> list[str]:
    """Hashes under every configured key generation (for lookups)."""
    return [hmac.new(_subkey(m, b"hash"), value.encode(), hashlib.sha256).hexdigest() for m in _all_keys()]


def keyed_hash_matches(value: str, stored: str) -> bool:
    """Constant-time check of `value` against a stored hash under any key generation."""
    matched = False
    for candidate in keyed_hash_candidates(value):
        if hmac.compare_digest(candidate, stored):
            matched = True
    return matched


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def generate_numeric_code(length: int = 6) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))


def generate_recovery_code() -> str:
    """Human-friendly code, e.g. 'k7x4-29mq-v8d3' (~58 bits of entropy)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no ambiguous chars
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "-".join(groups)


def normalise_recovery_code(raw: str) -> str:
    return raw.strip().lower().replace(" ", "")


def generate_token() -> str:
    return secrets.token_urlsafe(32)


generate_device_token = generate_token
