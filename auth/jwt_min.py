"""
Minimal JWT support - just what Sign in with Apple needs, no PyJWT dependency.

  * HS256 sign/verify      (stdlib)            - used by the FAKE identity provider
  * RS256 verify via JWKS  (cryptography)      - Apple id_token verification
  * ES256 sign             (cryptography)      - Apple client_secret generation

Only `alg` values we explicitly ask for are accepted (no "alg: none", no confusion attacks).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False


class JWTError(Exception):
    pass


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _split(token: str) -> tuple[dict, dict, bytes, bytes]:
    try:
        h, p, s = token.split(".")
        header = json.loads(b64url_decode(h))
        payload = json.loads(b64url_decode(p))
        return header, payload, f"{h}.{p}".encode(), b64url_decode(s)
    except (ValueError, json.JSONDecodeError) as exc:
        raise JWTError("malformed token") from exc


def peek(token: str) -> tuple[dict, dict]:
    """Header and payload WITHOUT verification (use only to pick the key)."""
    header, payload, _, _ = _split(token)
    return header, payload


# --------------------------------------------------------------------- HS256

def sign_hs256(payload: dict, secret: str, kid: str = "fake-1") -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    signing_input = f"{b64url_encode(json.dumps(header).encode())}.{b64url_encode(json.dumps(payload).encode())}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url_encode(sig)}"


def verify_hs256(token: str, secret: str) -> dict:
    header, payload, signing_input, sig = _split(token)
    if header.get("alg") != "HS256":
        raise JWTError("unexpected alg")
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise JWTError("bad signature")
    return payload


# --------------------------------------------------------------------- RS256

def verify_rs256_jwks(token: str, jwks: dict) -> dict:
    if not HAVE_CRYPTOGRAPHY:
        raise JWTError("RS256 verification requires the `cryptography` package")
    header, payload, signing_input, sig = _split(token)
    if header.get("alg") != "RS256":
        raise JWTError("unexpected alg")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if key is None:
        raise JWTError("unknown key id")
    n = int.from_bytes(b64url_decode(key["n"]), "big")
    e = int.from_bytes(b64url_decode(key["e"]), "big")
    public = rsa.RSAPublicNumbers(e, n).public_key()
    try:
        public.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:  # noqa: BLE001
        raise JWTError("bad signature") from exc
    return payload


# --------------------------------------------------------------------- ES256

def sign_es256(payload: dict, private_key_pem: str, kid: str) -> str:
    if not HAVE_CRYPTOGRAPHY:
        raise JWTError("ES256 signing requires the `cryptography` package")
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise JWTError("Apple private key must be an EC (P-256) key")
    header = {"alg": "ES256", "kid": kid}
    signing_input = f"{b64url_encode(json.dumps(header).encode())}.{b64url_encode(json.dumps(payload).encode())}"
    der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")  # JOSE format
    return f"{signing_input}.{b64url_encode(raw)}"


# -------------------------------------------------------------------- claims

def check_claims(payload: dict, *, issuer: str | list[str], audience: str, nonce: str | None = None, leeway: int = 60) -> None:
    issuers = [issuer] if isinstance(issuer, str) else issuer
    if payload.get("iss") not in issuers:
        raise JWTError("wrong issuer")
    aud = payload.get("aud")
    if audience not in (aud if isinstance(aud, list) else [aud]):
        raise JWTError("wrong audience")
    now = time.time()
    if payload.get("exp") is not None and now > payload["exp"] + leeway:
        raise JWTError("token expired")
    if payload.get("iat") is not None and payload["iat"] > now + leeway:
        raise JWTError("token issued in the future")
    if nonce is not None and payload.get("nonce") != nonce:
        raise JWTError("nonce mismatch")
