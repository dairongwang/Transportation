"""
RFC 6238 TOTP / RFC 4226 HOTP using only the Python standard library.

Pure Python, no compiled dependencies, identical behaviour on Linux, macOS and
Windows. Verified against the RFC 6238 test vectors in tests/test_totp.py and
cross-checked against pyotp when it happens to be installed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

DIGITS = 6
PERIOD = 30


def random_base32(length: int = 32) -> str:
    """Random base32 secret (160 bits for length=32), as used by authenticator apps."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _decode_secret(secret: str) -> bytes:
    s = secret.strip().replace(" ", "").upper()
    s += "=" * (-len(s) % 8)
    return base64.b32decode(s, casefold=True)


def hotp(secret: str, counter: int, digits: int = DIGITS, algorithm: str = "sha1") -> str:
    key = _decode_secret(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def counter_for(timestamp: float | None = None, period: int = PERIOD) -> int:
    return int((time.time() if timestamp is None else timestamp) // period)


def totp(secret: str, timestamp: float | None = None, digits: int = DIGITS, period: int = PERIOD,
         algorithm: str = "sha1") -> str:
    return hotp(secret, counter_for(timestamp, period), digits, algorithm)


def verify(secret: str, code: str, timestamp: float | None = None, window: int = 1,
           digits: int = DIGITS, period: int = PERIOD) -> int | None:
    """
    Return the matching counter (time step) if `code` is valid within +/- `window`
    steps of `timestamp`, else None. Comparison is constant-time.
    """
    code = code.strip().replace(" ", "")
    if not (code.isdigit() and len(code) == digits):
        return None
    base = counter_for(timestamp, period)
    for offset in range(-window, window + 1):
        counter = base + offset
        if hmac.compare_digest(hotp(secret, counter, digits), code):
            return counter
    return None


def provisioning_uri(secret: str, account: str, issuer: str, digits: int = DIGITS, period: int = PERIOD) -> str:
    """otpauth:// URI understood by Google Authenticator, Authy, 1Password, Microsoft Authenticator..."""
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    query = urllib.parse.urlencode(
        {"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": digits, "period": period}
    )
    return f"otpauth://totp/{label}?{query}"
