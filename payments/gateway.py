"""
Payment gateway abstraction (server side).

The merchant server NEVER handles card numbers. The browser tokenises the card with the
vault (payments/vault.py in fake mode, Stripe.js/hosted fields in real life) and posts a
single-use token; everything below works with tokens only:

  * save_card(single_use_token, customer)   -> card-on-file token ID bound to the customer
  * save_wallet(grant, customer)            -> wallet token ID (Stripe / PayPal) from the
                                               single-use grant the provider redirected back with
  * update_card_expiry(token_id, customer)  -> re-dated token ID
  * authorize(token_id, customer, amount)   temporary hold (validation of a new method, and
                                               the ride pre-authorisation placed when a driver
                                               is picked)
  * capture(hold_ref, token_id, ...)        settle a hold for the final amount (<= the hold)
  * void(hold_ref)                          release the hold
  * charge(token_id, customer, amount)      captured charge
  * detach(token_id, customer)              forget the card at the vault (on delete)
  * refund(charge_ref, token_id, ...)       return (part of) a captured charge (manager refunds)

Scripted test-card behaviour (see payments/cards.py) travels inside the signed token, so the
fake gateway is deterministic across restarts. A real implementation wraps the processor's
API behind the same methods and is registered under "real" in `_BACKENDS`.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import vault
from .cards import (  # noqa: F401  (re-exported: tests and older callers import these from here)
    FAILURE_MESSAGES,
    TEST_CARDS,
    PaymentError,
    detect_brand,
    expiry_valid,
    failure_message,
    looks_like_pan,
    luhn_valid,
    normalise_number,
)
from .vault import CardOnFile, WalletOnFile


@dataclass(frozen=True)
class ChargeResult:
    ok: bool
    provider_ref: str | None
    failure_reason: str | None = None
    captured: bool = True  # False for an authorisation hold (see authorize / void)


@dataclass(frozen=True)
class VoidResult:
    ok: bool
    failure_reason: str | None = None


def customer_ref(user_id: int) -> str:
    """Stable per-user customer id at the vault; tokens are bound to it."""
    return f"cus_DUMMY_{user_id}"


# ------------------------------------------------------------------ interface

class PaymentGateway:
    name = "abstract"

    def save_card(self, single_use_token: str, customer: str) -> CardOnFile:
        raise NotImplementedError  # pragma: no cover

    def save_wallet(self, grant: str, customer: str) -> WalletOnFile:
        raise NotImplementedError  # pragma: no cover

    def update_card_expiry(self, token_id: str, customer: str, exp_month: int, exp_year: int) -> str:
        raise NotImplementedError  # pragma: no cover

    def authorize(self, token_id: str, customer: str, amount: float, currency: str, description: str = "") -> ChargeResult:
        raise NotImplementedError  # pragma: no cover

    def capture(self, hold_ref: str, token_id: str, customer: str, amount: float, currency: str,
                description: str = "") -> ChargeResult:
        """Capture (part of) an authorisation hold. The hold is finished either way."""
        raise NotImplementedError  # pragma: no cover

    def void(self, provider_ref: str) -> VoidResult:
        raise NotImplementedError  # pragma: no cover

    def charge(self, token_id: str, customer: str, amount: float, currency: str, description: str = "") -> ChargeResult:
        raise NotImplementedError  # pragma: no cover

    def detach(self, token_id: str, customer: str) -> bool:
        raise NotImplementedError  # pragma: no cover

    def refund(self, charge_ref: str, token_id: str | None, customer: str, amount: float, currency: str) -> ChargeResult:
        """Return (part of) a captured charge to the payment method it was taken from."""
        raise NotImplementedError  # pragma: no cover


class FakeGateway(PaymentGateway):
    """Offline stub backed by the fake vault. Deterministic, no network."""

    name = "fake"

    def save_card(self, single_use_token: str, customer: str) -> CardOnFile:
        return vault.exchange(single_use_token, customer)

    def save_wallet(self, grant: str, customer: str) -> WalletOnFile:
        return vault.exchange_wallet(grant, customer)

    def update_card_expiry(self, token_id: str, customer: str, exp_month: int, exp_year: int) -> str:
        return vault.update_expiry(token_id, customer, exp_month, exp_year)

    def authorize(self, token_id: str, customer: str, amount: float, currency: str, description: str = "") -> ChargeResult:
        if amount <= 0:
            return ChargeResult(ok=False, provider_ref=None, failure_reason="invalid_amount", captured=False)
        outcome = vault.outcome(token_id, customer, capture=False, amount=amount)
        if outcome == "ok":
            return ChargeResult(ok=True, provider_ref=f"auth_DUMMY_{secrets.token_hex(8)}", captured=False)
        return ChargeResult(ok=False, provider_ref=None, failure_reason=outcome, captured=False)

    def capture(self, hold_ref: str, token_id: str, customer: str, amount: float, currency: str,
                description: str = "") -> ChargeResult:
        if not (hold_ref or "").startswith("auth_DUMMY_"):
            return ChargeResult(ok=False, provider_ref=None, failure_reason="invalid_token")
        if amount <= 0:
            return ChargeResult(ok=False, provider_ref=None, failure_reason="invalid_amount")
        # The stub vault is stateless, so the card's scripted behaviour decides - like a real
        # processor, a "later" card authorises fine but fails when money actually moves.
        outcome = vault.outcome(token_id, customer, capture=True, amount=amount)
        if outcome == "ok":
            return ChargeResult(ok=True, provider_ref=f"ch_DUMMY_{secrets.token_hex(8)}")
        return ChargeResult(ok=False, provider_ref=None, failure_reason=outcome)

    def void(self, provider_ref: str) -> VoidResult:
        if (provider_ref or "").startswith(("auth_DUMMY_", "ch_DUMMY_")):
            return VoidResult(ok=True)
        return VoidResult(ok=False, failure_reason="void_failed")

    def charge(self, token_id: str, customer: str, amount: float, currency: str, description: str = "") -> ChargeResult:
        if amount <= 0:
            return ChargeResult(ok=False, provider_ref=None, failure_reason="invalid_amount")
        outcome = vault.outcome(token_id, customer, capture=True, amount=amount)
        if outcome == "ok":
            return ChargeResult(ok=True, provider_ref=f"ch_DUMMY_{secrets.token_hex(8)}")
        return ChargeResult(ok=False, provider_ref=None, failure_reason=outcome)

    def detach(self, token_id: str, customer: str) -> bool:
        return vault.detach(token_id, customer)

    def refund(self, charge_ref: str, token_id: str | None, customer: str, amount: float, currency: str) -> ChargeResult:
        if not (charge_ref or "").startswith("ch_DUMMY_"):
            return ChargeResult(ok=False, provider_ref=None, failure_reason="refund_failed")
        if amount <= 0:
            return ChargeResult(ok=False, provider_ref=None, failure_reason="invalid_amount")
        return ChargeResult(ok=True, provider_ref=f"re_DUMMY_{secrets.token_hex(8)}")


class NotConfiguredGateway(PaymentGateway):
    """PAYMENTS_MODE=real without an implementation: fail loudly instead of pretending."""

    name = "real (not configured)"

    def save_card(self, *a, **k):
        raise PaymentError("not_configured")

    def save_wallet(self, *a, **k):
        raise PaymentError("not_configured")

    def update_card_expiry(self, *a, **k):
        raise PaymentError("not_configured")

    def authorize(self, *a, **k):
        return ChargeResult(ok=False, provider_ref=None, failure_reason="not_configured", captured=False)

    def capture(self, *a, **k):
        return ChargeResult(ok=False, provider_ref=None, failure_reason="not_configured")

    def void(self, *a, **k):
        return VoidResult(ok=False, failure_reason="not_configured")

    def charge(self, *a, **k):
        return ChargeResult(ok=False, provider_ref=None, failure_reason="not_configured")

    def detach(self, *a, **k):
        return False

    def refund(self, *a, **k):
        return ChargeResult(ok=False, provider_ref=None, failure_reason="not_configured")


_BACKENDS = {"fake": FakeGateway, "real": NotConfiguredGateway}


def get_gateway() -> PaymentGateway:
    from flask import current_app

    mode = current_app.config.get("PAYMENTS_MODE", "fake")
    return _BACKENDS.get(mode, NotConfiguredGateway)()
