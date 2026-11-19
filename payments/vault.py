"""
FAKE card vault / tokenisation service (what Stripe.js + the Stripe API do in real life).

Card-on-file tokenisation, the way the app uses it:

  browser ──(PAN, expiry, CVC)──▶ vault.create_single_use_token()      POST /dev/payments/tokenize
          ◀── tok_DUMMY.<payload>.<sig> + brand/last4/expiry ──
  browser ──(single-use token only)──▶ our server  POST /account/payments/card/new
  server  ──(single-use token, customer)──▶ vault.exchange()            gateway.save_card()
          ◀── card_DUMMY.<payload>.<sig>  = the CARD-ON-FILE TOKEN ID ──
  server stores the token ID (encrypted at rest) + brand / last4 / expiry / fingerprint.
  Every later charge sends (token ID, customer) - never a card number.

Wallets (Stripe / PayPal) follow the SAME pipeline: the provider's approval page mints a
single-use GRANT (tok_DUMMY... with t="wallet_grant") that carries only a masked e-mail and a
fingerprint; our server exchanges it for a customer-bound token ID (pm_DUMMY... / BA-DUMMY...).
The full account e-mail never reaches our server - only the masked form for display.

Properties the real thing has and this stub keeps:
  * the PAN / CVC never reach the merchant server (only the browser and the vault see them);
  * single-use tokens expire after SINGLE_USE_TTL seconds and can be exchanged exactly once;
  * a card-on-file token is bound to one customer: charging it for another customer fails,
    so a token leaked from our database is useless to a fraudster on its own;
  * tokens are opaque, HMAC-signed blobs - a tampered or forged token is rejected;
  * `fingerprint` identifies the same physical card across tokens without revealing it
    (used for duplicate detection).

The "vault storage" is stateless: everything the vault needs lives inside the signed token
(a real vault keeps it server-side). Consumed single-use nonces are kept in memory.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass

from flask import current_app

from . import cards
from .cards import PaymentError

SINGLE_USE_TTL = 600  # seconds a single-use token stays exchangeable
PREFIX = {"single": "tok_DUMMY", "card": "card_DUMMY", "stripe": "pm_DUMMY", "paypal": "BA-DUMMY"}
_consumed_nonces: set[str] = set()


@dataclass(frozen=True)
class SingleUseToken:
    token: str
    brand: str
    last4: str
    exp_month: int
    exp_year: int


@dataclass(frozen=True)
class CardOnFile:
    token_id: str
    brand: str
    last4: str
    exp_month: int
    exp_year: int
    fingerprint: str


@dataclass(frozen=True)
class WalletGrant:
    token: str  # single-use, returned to our server by the provider's redirect
    kind: str
    account_email_masked: str


@dataclass(frozen=True)
class WalletOnFile:
    token_id: str
    kind: str
    account_email_masked: str  # e.g. d•••r@p•••l.example - the vault never discloses the full address
    fingerprint: str


def mask_email(email: str) -> str:
    """
    Keep just enough for the owner to recognise the account, nothing a hacker can reuse:
    first + last character of the local part, first + last character of the domain name,
    the TLD as is.  dummy.rider@paypal.example -> d•••r@p•••l.example ; jo@x.io -> j•••@x•••.io
    """
    email = (email or "").strip()
    if "@" not in email:
        return "•••"
    local, _, domain = email.rpartition("@")
    name, dot, tld = domain.rpartition(".")
    if not dot:
        name, tld = domain, ""

    def part(text: str) -> str:
        if len(text) >= 4:
            return f"{text[0]}•••{text[-1]}"
        return f"{text[:1]}•••"

    return f"{part(local)}@{part(name)}{dot}{tld}"


# ------------------------------------------------------------------ signing

def _key() -> bytes:
    raw = current_app.config.get("FAKE_VAULT_SIGNING_KEY") or "DUMMY_FAKE_VAULT_SIGNING_KEY"
    return hashlib.sha256(("vault:" + raw).encode()).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(payload_b64: str) -> str:
    return hmac.new(_key(), payload_b64.encode(), hashlib.sha256).hexdigest()[:32]


def mint(prefix: str, payload: dict) -> str:
    payload_b64 = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return f"{prefix}.{payload_b64}.{_sign(payload_b64)}"


def inspect(token: str) -> dict | None:
    """Verify the signature and return the payload, or None for anything forged / malformed."""
    try:
        prefix, payload_b64, sig = (token or "").split(".")
    except ValueError:
        return None
    if prefix not in PREFIX.values() or not hmac.compare_digest(sig, _sign(payload_b64)):
        return None
    try:
        payload = json.loads(_unb64(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def fingerprint_of(number: str) -> str:
    """Stable identifier of a physical card that does not reveal the number."""
    return hmac.new(_key(), ("fp:" + number).encode(), hashlib.sha256).hexdigest()[:24]


# ------------------------------------------------------------------ client side (browser -> vault)

def create_single_use_token(number: str, exp_month, exp_year, cvc: str) -> SingleUseToken:
    """Called by the browser (via /dev/payments/tokenize). Never called with data from our server."""
    number = cards.normalise_number(number)
    if not cards.luhn_valid(number):
        raise PaymentError("invalid_number")
    try:
        exp_month, exp_year = int(exp_month), int(exp_year)
    except (TypeError, ValueError):
        raise PaymentError("invalid_expiry") from None
    if exp_year < 100:
        exp_year += 2000
    if not cards.expiry_valid(exp_month, exp_year):
        raise PaymentError("invalid_expiry")
    brand = cards.detect_brand(number)
    cvc = (cvc or "").strip()
    if not cvc.isdigit() or len(cvc) != (4 if brand == "amex" else 3):
        raise PaymentError("invalid_cvc")
    behaviour, stage = cards.TEST_CARDS.get(number, ("ok", ""))
    if stage == "tokenize":
        raise PaymentError(behaviour)
    payload = {
        "t": "single", "n": secrets.token_hex(8), "exp": int(time.time()) + SINGLE_USE_TTL,
        "br": brand, "l4": number[-4:], "em": exp_month, "ey": exp_year, "fp": fingerprint_of(number),
        "b": behaviour, "s": stage,  # scripted test-card behaviour travels inside the token
    }
    return SingleUseToken(token=mint(PREFIX["single"], payload), brand=brand, last4=number[-4:],
                          exp_month=exp_month, exp_year=exp_year)


# ------------------------------------------------------------------ server side (our server -> vault)

def _consume_single_use(token: str, expected_type: str) -> dict:
    """Verify + burn a single-use token (card token or wallet grant)."""
    p = inspect(token)
    if not p or p.get("t") != expected_type:
        raise PaymentError("invalid_token")
    if p["exp"] < time.time():
        raise PaymentError("token_expired")
    if p["n"] in _consumed_nonces:
        raise PaymentError("token_used")
    _consumed_nonces.add(p["n"])
    return p


def exchange(single_use_token: str, customer_ref: str) -> CardOnFile:
    """Turn a single-use card token into a card-on-file token bound to `customer_ref`."""
    p = _consume_single_use(single_use_token, "single")
    payload = {"t": "card", "c": customer_ref, "i": secrets.token_hex(8), "br": p["br"], "l4": p["l4"],
               "em": p["em"], "ey": p["ey"], "fp": p["fp"], "b": p["b"], "s": p["s"]}
    return CardOnFile(token_id=mint(PREFIX["card"], payload), brand=p["br"], last4=p["l4"],
                      exp_month=p["em"], exp_year=p["ey"], fingerprint=p["fp"])


# ------------------------------------------------------------------ wallets (Stripe / PayPal)

def create_wallet_grant(kind: str, account_email: str) -> WalletGrant:
    """
    Minted by the PROVIDER after the user approves (fake_provider.py plays it). The grant
    carries a masked e-mail and a fingerprint only - never the full address.
    """
    if kind not in ("stripe", "paypal"):
        raise PaymentError("processing_error", "Unknown wallet provider.")
    email = (account_email or "").strip().lower()
    if not cards.EMAIL_RE.match(email):
        raise PaymentError("processing_error", "The provider returned an invalid account e-mail.")
    behaviour = "wallet_declined" if "declined" in email else "ok"
    stage = "later" if (behaviour != "ok" and "later" in email) else "charge"
    payload = {
        "t": "wallet_grant", "k": kind, "n": secrets.token_hex(8), "exp": int(time.time()) + SINGLE_USE_TTL,
        "me": mask_email(email), "fp": hmac.new(_key(), (f"wfp:{kind}:" + email).encode(), hashlib.sha256).hexdigest()[:24],
        "b": behaviour, "s": stage,
    }
    return WalletGrant(token=mint(PREFIX["single"], payload), kind=kind, account_email_masked=payload["me"])


def exchange_wallet(grant: str, customer_ref: str) -> WalletOnFile:
    """Turn a single-use wallet grant into a wallet-on-file token bound to `customer_ref`."""
    p = _consume_single_use(grant, "wallet_grant")
    kind = p["k"]
    payload = {"t": kind, "c": customer_ref, "i": secrets.token_hex(8), "me": p["me"], "fp": p["fp"],
               "b": p["b"], "s": p["s"]}
    return WalletOnFile(token_id=mint(PREFIX[kind], payload), kind=kind, account_email_masked=p["me"],
                        fingerprint=p["fp"])


def update_expiry(token_id: str, customer_ref: str, exp_month: int, exp_year: int) -> str:
    """Re-date a card on file (real vaults allow updating expiry without the PAN). -> new token id."""
    p = _owned(token_id, customer_ref)
    if p.get("t") != "card":
        raise PaymentError("invalid_token")
    p = {**p, "em": exp_month, "ey": exp_year, "i": secrets.token_hex(8)}
    return mint(PREFIX["card"], p)


def _owned(token_id: str, customer_ref: str) -> dict:
    p = inspect(token_id)
    if not p or p.get("t") in ("single", "wallet_grant"):
        raise PaymentError("invalid_token")
    if not hmac.compare_digest(str(p.get("c", "")), customer_ref):
        raise PaymentError("token_customer_mismatch")
    return p


def outcome(token_id: str, customer_ref: str, capture: bool, amount: float | None = None) -> str:
    """'ok' or a failure code for a charge/hold on this token for this customer."""
    try:
        p = _owned(token_id, customer_ref)
    except PaymentError as exc:
        return exc.code
    if p["b"] == "ok":
        return "ok"
    if p.get("s") == "later" and not capture:  # "later" tokens pass the validation hold
        return "ok"
    if p.get("s") == "limit" and (amount is None or amount <= cards.LOW_BALANCE_LIMIT):
        return "ok"  # low-balance card: small amounts (the validation hold) are fine
    return p["b"]


def detach(token_id: str, customer_ref: str) -> bool:
    try:
        _owned(token_id, customer_ref)
    except PaymentError:
        return False
    return True  # a real vault would delete the card here


def token_hint(token_id: str) -> str:
    """Short, non-sensitive identifier for support screens: prefix + last 6 chars."""
    if not token_id or "." not in token_id:
        return "—"
    return f"{token_id.split('.')[0]}…{token_id[-6:]}"
