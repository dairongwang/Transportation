"""The stdlib TOTP implementation against the RFC test vectors (and pyotp, if present)."""

import base64

import pytest

from auth import totp

RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()

# RFC 4226 Appendix D
HOTP_VECTORS = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
# RFC 6238 Appendix B (SHA1, 8 digits)
TOTP_VECTORS = {
    59: "94287082",
    1111111109: "07081804",
    1111111111: "14050471",
    1234567890: "89005924",
    2000000000: "69279037",
    20000000000: "65353130",
}


def test_hotp_rfc4226_vectors():
    for counter, expected in enumerate(HOTP_VECTORS):
        assert totp.hotp(RFC_SECRET, counter) == expected


def test_totp_rfc6238_vectors():
    for ts, expected in TOTP_VECTORS.items():
        assert totp.totp(RFC_SECRET, ts, digits=8) == expected


def test_verify_window_and_rejections():
    code = totp.totp(RFC_SECRET, 1000)
    assert totp.verify(RFC_SECRET, code, timestamp=1000) == 33
    assert totp.verify(RFC_SECRET, code, timestamp=1000 + 30) == 33  # previous step, within window
    assert totp.verify(RFC_SECRET, code, timestamp=1000 + 90) is None  # too old
    assert totp.verify(RFC_SECRET, "12345", timestamp=1000) is None  # wrong length
    assert totp.verify(RFC_SECRET, "abcdef", timestamp=1000) is None  # not digits
    assert totp.verify(RFC_SECRET, " " + code[:3] + " " + code[3:] + " ", timestamp=1000) == 33  # spaces ok


def test_secret_and_uri_format():
    secret = totp.random_base32()
    assert len(secret) == 32 and set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    uri = totp.provisioning_uri(secret, "alice@example.com", "ServiceUber")
    assert uri.startswith("otpauth://totp/ServiceUber%3Aalice%40example.com?")
    assert f"secret={secret}" in uri and "issuer=ServiceUber" in uri and "digits=6" in uri


def test_matches_pyotp_if_installed():
    pyotp = pytest.importorskip("pyotp")
    secret = totp.random_base32()
    for ts in (0, 1_700_000_000, 2_000_000_000):
        assert totp.totp(secret, ts) == pyotp.TOTP(secret).at(ts)
    assert pyotp.parse_uri(totp.provisioning_uri(secret, "a@b.c", "X")).secret == secret
