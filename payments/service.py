"""
Payment-method management and ride charging (the only place that talks to the gateway).

Card-on-file rule: this module never accepts or logs a card number. Cards arrive as a
single-use token minted in the browser; we exchange it for a customer-bound token ID,
store that ID encrypted, and use it for every hold / charge / void / detach.

Ride money flow (card / wallet rides; cash rides touch none of this):
  pick a driver   -> hold_for_ride()     authorisation hold of RIDE_PREAUTH_FACTOR x the
                                         driver's quoted fare (default 1.5 = estimate + 50 %)
  driver declines / rider cancels / no driver found -> release_hold()   hold voided
  ride completed  -> charge_ride()       the hold is captured for the ACTUAL fare (never more
                                         than the hold); the rest is released automatically
"""

from __future__ import annotations

import logging

from flask import current_app

from clock import utcnow
from extensions import db
from models import PAYMENT_KINDS, PaymentMethod, PaymentTransaction, RideRequest, User

from . import gateway as gw
from .gateway import PaymentError, customer_ref

log = logging.getLogger("payments")


class PaymentMethodError(Exception):
    """User-facing validation / authorization problem."""


# ------------------------------------------------------------------ queries

def active_methods(user: User) -> list[PaymentMethod]:
    return (PaymentMethod.query.filter_by(user_id=user.id, deleted_at=None)
            .order_by(PaymentMethod.is_default.desc(), PaymentMethod.created_at.asc()).all())


def default_method(user: User) -> PaymentMethod | None:
    return PaymentMethod.query.filter_by(user_id=user.id, deleted_at=None, is_default=True).first()


def get_owned(user: User, method_id: int) -> PaymentMethod:
    m = db.session.get(PaymentMethod, method_id)
    if m is None or m.user_id != user.id or m.deleted_at is not None:
        raise PaymentMethodError("Payment method not found.")
    return m


def can_have_payment_methods(user: User) -> bool:
    """Payment methods are for riders: seller-only accounts never pay for anything."""
    return user.role != "seller"


def _check_limit(user: User) -> None:
    if len(active_methods(user)) >= int(current_app.config.get("PAYMENT_METHODS_MAX", 10)):
        raise PaymentMethodError("You have reached the maximum number of payment methods.")


def _clean_label(label: str | None) -> str | None:
    label = (label or "").strip()[:60]
    return label or None


def _make_default_if_first(user: User, method: PaymentMethod, make_default: bool) -> None:
    others = [m for m in active_methods(user) if m.id != method.id]
    if make_default or not others:
        for m in others:
            m.is_default = False
        method.is_default = True


# ------------------------------------------------------------------ validation

def validation_amount() -> float:
    try:
        return max(0.0, float(current_app.config.get("PAYMENT_VALIDATION_AMOUNT", 1.0)))
    except (TypeError, ValueError):
        return 1.0


def validate_method(method: PaymentMethod) -> PaymentTransaction | None:
    """
    Confirm a method really works: place a small authorisation hold, then void it.
    Raises PaymentError (method stays unverified) if the hold is refused. Returns the
    "voided" transaction that documents the check, or None when validation is disabled.
    """
    amount = validation_amount()
    if amount <= 0:
        method.verified_at = utcnow()  # validation switched off: trust the gateway token
        method.verification_ref = None
        return None
    currency = current_app.config.get("PAYMENT_CURRENCY", "USD")
    g = gw.get_gateway()
    hold = g.authorize(method.token_id, customer_ref(method.user_id), amount, currency, f"Validation of {method.display}")
    if not hold.ok:
        db.session.add(PaymentTransaction(
            kind="verification",
            user_id=method.user_id, payment_method_id=method.id, amount=amount, currency=currency, status="failed",
            failure_reason=hold.failure_reason, description=f"Validation hold for {method.display}",
        ))
        log.info("validation failed user=%s method=%s reason=%s", method.user_id, method.id, hold.failure_reason)
        raise PaymentError(hold.failure_reason or "processing_error",
                           f"We could not validate this payment method: {gw.failure_message(hold.failure_reason)}")
    released = g.void(hold.provider_ref)
    tx = PaymentTransaction(
        kind="verification",
        user_id=method.user_id, payment_method_id=method.id, amount=amount, currency=currency,
        status="voided" if released.ok else "succeeded", provider_ref=hold.provider_ref,
        failure_reason=None if released.ok else "void_failed",
        description=f"Validation hold for {method.display}" + (" (voided)" if released.ok else " (release pending)"),
    )
    db.session.add(tx)
    method.verified_at = utcnow()
    method.verification_ref = hold.provider_ref
    if not released.ok:  # the hold will expire on its own; never leave the user guessing
        log.warning("validation hold %s for method %s could not be voided", hold.provider_ref, method.id)
    log.info("validated user=%s method=%s hold=%s voided=%s", method.user_id, method.id, hold.provider_ref, released.ok)
    return tx


def revalidate(user: User, method_id: int) -> PaymentTransaction | None:
    m = get_owned(user, method_id)
    try:
        tx = validate_method(m)
    except PaymentError:
        db.session.commit()  # keep the failed-validation transaction for the history
        raise
    db.session.commit()
    return tx


# ------------------------------------------------------------------ ride pre-authorisation

def preauth_factor() -> float:
    try:
        return max(1.0, float(current_app.config.get("RIDE_PREAUTH_FACTOR", 1.5)))
    except (TypeError, ValueError):
        return 1.5


def preauth_amount(estimate: float) -> float:
    """Money reserved when a driver is picked: the estimated fare plus the safety margin, rounded UP to the cent."""
    import math

    raw = max(0.0, float(estimate or 0.0)) * preauth_factor()
    return math.ceil(raw * 100 - 1e-7) / 100


def _hold_transaction(ride: RideRequest) -> PaymentTransaction | None:
    if not ride.preauth_ref:
        return None
    return PaymentTransaction.query.filter_by(ride_id=ride.id, provider_ref=ride.preauth_ref).first()


def hold_for_ride(ride: RideRequest, estimate: float) -> PaymentTransaction | None:
    """
    Pre-authorise preauth_amount(estimate) on the ride's payment method. Cash rides -> None.
    An existing hold that already covers the amount is kept; a smaller one is released and
    replaced. Raises PaymentError when the gateway refuses (the caller decides what that
    means for the ride - the ride keeps preauth_status="failed" for display).
    """
    method = ride.payment_method
    if method is None:
        return None
    amount = preauth_amount(estimate)
    if ride.has_hold and ride.preauth_amount is not None and ride.preauth_amount >= amount:
        return _hold_transaction(ride)  # still sufficient (e.g. the next driver is cheaper)
    if ride.has_hold:
        release_hold(ride, "replaced by a larger pre-authorisation")
    currency = current_app.config.get("PAYMENT_CURRENCY", "USD")
    desc = f"Pre-authorisation for ride #{ride.id}: estimate {currency} {float(estimate):.2f} x {preauth_factor():g}"
    hold = gw.get_gateway().authorize(method.token_id, customer_ref(ride.rider_id), amount, currency, desc)
    tx = PaymentTransaction(
        kind="hold",
        user_id=ride.rider_id, payment_method_id=method.id, ride_id=ride.id, amount=amount, currency=currency,
        status="held" if hold.ok else "failed", provider_ref=hold.provider_ref, failure_reason=hold.failure_reason,
        description=desc,
    )
    db.session.add(tx)
    ride.preauth_amount = amount
    ride.preauth_at = utcnow()
    if not hold.ok:
        ride.preauth_ref = None
        ride.preauth_status = "failed"
        log.info("preauth failed ride=%s method=%s amount=%.2f reason=%s", ride.id, method.id, amount, hold.failure_reason)
        raise PaymentError(
            hold.failure_reason or "processing_error",
            f"We could not reserve {currency} {amount:.2f} on {method.display}: {gw.failure_message(hold.failure_reason)}",
        )
    ride.preauth_ref = hold.provider_ref
    ride.preauth_status = "held"
    log.info("preauth held ride=%s method=%s amount=%.2f %s ref=%s", ride.id, method.id, amount, currency, hold.provider_ref)
    return tx


def release_hold(ride: RideRequest, reason: str = "") -> bool:
    """Void an outstanding pre-authorisation (ride cancelled, no driver, method changed). True if one was released."""
    if not ride.has_hold:
        return False
    released = gw.get_gateway().void(ride.preauth_ref)
    tx = _hold_transaction(ride)
    if tx is not None:
        tx.status = "released" if released.ok else "held"
        if reason:
            tx.description = f"{tx.description} - released: {reason}"[:200]
        if not released.ok:
            tx.failure_reason = "void_failed"
    if not released.ok:  # the hold expires on its own at the provider; do not block the ride
        log.warning("preauth %s for ride %s could not be voided", ride.preauth_ref, ride.id)
    ride.preauth_status = "released"
    log.info("preauth released ride=%s ref=%s voided=%s (%s)", ride.id, ride.preauth_ref, released.ok, reason)
    return True


# ------------------------------------------------------------------ add

def add_card(user: User, *, card_token: str, billing_name: str = "", label: str | None = None,
             make_default: bool = False) -> PaymentMethod:
    """
    `card_token` is the SINGLE-USE token the browser obtained from the vault. It is exchanged
    for a card-on-file token ID bound to this customer; the ID is stored encrypted.
    """
    if not can_have_payment_methods(user):
        raise PaymentMethodError("Seller-only accounts do not need payment methods.")
    _check_limit(user)
    if gw.looks_like_pan(card_token):  # somebody posted a card number where a token belongs
        log.warning("raw card data rejected for user=%s (token field contained a PAN-like value)", user.id)
        raise PaymentError("raw_card_data")
    billing_name = (billing_name or "").strip()[:120]
    if not billing_name:
        raise PaymentMethodError("Please enter the name on the card.")
    card = gw.get_gateway().save_card((card_token or "").strip(), customer_ref(user.id))  # raises PaymentError
    dup = PaymentMethod.query.filter_by(user_id=user.id, deleted_at=None, kind="card", fingerprint=card.fingerprint).first()
    if dup is not None:
        raise PaymentError("duplicate_card", f"This card is already on file as {dup.display}.")
    method = PaymentMethod(
        user_id=user.id, kind="card", label=_clean_label(label), brand=card.brand, last4=card.last4,
        exp_month=card.exp_month, exp_year=card.exp_year, billing_name=billing_name, fingerprint=card.fingerprint,
    )
    method.token_id = card.token_id
    db.session.add(method)
    db.session.flush()
    validate_method(method)  # raises PaymentError -> caller rolls back, nothing is stored
    _make_default_if_first(user, method, make_default)
    db.session.commit()
    log.info("payment_method added user=%s kind=card brand=%s last4=%s token=%s", user.id, card.brand, card.last4, method.token_hint)
    return method


def add_wallet(user: User, grant: str, *, expected_kind: str | None = None, label: str | None = None,
               make_default: bool = False) -> PaymentMethod:
    """
    `grant` is the SINGLE-USE token the provider redirected back with after the user approved.
    It is exchanged for a wallet-on-file token ID bound to this customer. The vault returns a
    MASKED e-mail and a fingerprint only - the full account address never reaches this app.
    """
    if not can_have_payment_methods(user):
        raise PaymentMethodError("Seller-only accounts do not need payment methods.")
    _check_limit(user)
    if "@" in (grant or ""):  # an e-mail address where a grant belongs: refuse, never store
        log.warning("wallet grant rejected for user=%s (looked like an e-mail address)", user.id)
        raise PaymentError("invalid_token")
    w = gw.get_gateway().save_wallet((grant or "").strip(), customer_ref(user.id))  # raises PaymentError
    if w.kind not in PAYMENT_KINDS or w.kind == "card" or (expected_kind and w.kind != expected_kind):
        raise PaymentMethodError("The grant is for a different wallet provider.")
    existing = PaymentMethod.query.filter_by(user_id=user.id, deleted_at=None, kind=w.kind, fingerprint=w.fingerprint).first()
    if existing:
        raise PaymentMethodError(f"{existing.kind_label} account {w.account_email_masked} is already linked.")
    kind = w.kind
    method = PaymentMethod(user_id=user.id, kind=kind, label=_clean_label(label),
                           account_email_masked=w.account_email_masked, fingerprint=w.fingerprint)
    method.token_id = w.token_id
    db.session.add(method)
    db.session.flush()
    validate_method(method)  # raises PaymentError -> caller rolls back, nothing is stored
    _make_default_if_first(user, method, make_default)
    db.session.commit()
    log.info("payment_method added user=%s kind=%s account=%s token=%s", user.id, kind, w.account_email_masked, method.token_hint)
    return method


# ------------------------------------------------------------------ modify / delete

def update_method(user: User, method_id: int, *, label=None, billing_name=None, exp_month=None, exp_year=None,
                  make_default: bool | None = None) -> PaymentMethod:
    """Modify the editable bits. The card number itself can't change: delete and re-add."""
    m = get_owned(user, method_id)
    m.label = _clean_label(label) if label is not None else m.label
    if m.kind == "card":
        if billing_name is not None:
            billing_name = billing_name.strip()[:120]
            if not billing_name:
                raise PaymentMethodError("Please enter the name on the card.")
            m.billing_name = billing_name
        if exp_month not in (None, "") or exp_year not in (None, ""):
            try:
                em, ey = int(exp_month), int(exp_year)
            except (TypeError, ValueError):
                raise PaymentError("invalid_expiry") from None
            if ey < 100:
                ey += 2000
            if not gw.expiry_valid(em, ey):
                raise PaymentError("invalid_expiry")
            if (em, ey) != (m.exp_month, m.exp_year):
                # the vault re-dates the card on file (no PAN needed) and hands back a new token id
                m.token_id = gw.get_gateway().update_card_expiry(m.token_id, customer_ref(user.id), em, ey)
                m.exp_month, m.exp_year = em, ey
                validate_method(m)  # a re-dated card is validated again (raises -> caller rolls back)
    if make_default:
        set_default(user, m.id, commit=False)
    db.session.commit()
    return m


def set_default(user: User, method_id: int, commit: bool = True) -> PaymentMethod:
    m = get_owned(user, method_id)
    for other in active_methods(user):
        other.is_default = other.id == m.id
    if commit:
        db.session.commit()
    return m


def delete_method(user: User, method_id: int) -> None:
    m = get_owned(user, method_id)
    open_ride = RideRequest.query.filter(
        RideRequest.payment_method_id == m.id,
        RideRequest.status.in_(("searching", "offered", "accepted", "in_progress")),
    ).first()
    if open_ride:
        raise PaymentMethodError(f"This method is selected for your active ride #{open_ride.id}. Finish or cancel it first.")
    if not gw.get_gateway().detach(m.token_id, customer_ref(user.id)):
        log.warning("vault detach refused for method %s (token %s); deleting locally anyway", m.id, m.token_hint)
    m.deleted_at = utcnow()
    was_default = m.is_default
    m.is_default = False
    if was_default:
        remaining = active_methods(user)
        if remaining:
            remaining[0].is_default = True
    db.session.commit()
    log.info("payment_method deleted user=%s id=%s", user.id, m.id)


# ------------------------------------------------------------------ charging

def charge_ride(ride: RideRequest) -> PaymentTransaction | None:
    """
    Charge the rider for a completed ride. Cash rides return None. Failures do not block the
    ride (it is already over) - they are recorded and surfaced on the ride and Account pages.
    """
    if ride.payment_method is None:
        ride.payment_status = "cash"
        return None
    method = ride.payment_method
    currency = current_app.config.get("PAYMENT_CURRENCY", "USD")
    amount = round(float(ride.fare or 0.0), 2)
    gateway = gw.get_gateway()
    description = f"Ride #{ride.id} {ride.pickup_address} -> {ride.dropoff_address}"
    if ride.has_hold and ride.preauth_amount is not None and amount <= ride.preauth_amount + 1e-9:
        # Settle against the pre-authorisation placed when the driver was picked. Only the
        # actual fare is taken; the remainder of the hold is released by the provider.
        result = gateway.capture(ride.preauth_ref, method.token_id, customer_ref(ride.rider_id), amount, currency, description)
        description += f" (captured from pre-authorisation {ride.preauth_ref})"
        hold_tx = _hold_transaction(ride)
        if hold_tx is not None:
            hold_tx.status = "captured" if result.ok else "released"
        ride.preauth_status = "captured" if result.ok else "released"
    else:
        if ride.has_hold:  # fare exceeds the hold (should not happen: fare = the quote the hold was sized from)
            release_hold(ride, "fare exceeded the pre-authorised amount; charged in full instead")
        result = gateway.charge(method.token_id, customer_ref(ride.rider_id), amount, currency, description)
    tx = PaymentTransaction(
        kind="charge",
        user_id=ride.rider_id, payment_method_id=method.id, ride_id=ride.id, amount=amount, currency=currency,
        status="succeeded" if result.ok else "failed", provider_ref=result.provider_ref,
        failure_reason=result.failure_reason, description=description[:200],
    )
    db.session.add(tx)
    ride.payment_status = "paid" if result.ok else "failed"
    if result.ok:
        ride.payment_token = result.provider_ref
    log.info("charge ride=%s method=%s amount=%.2f %s -> %s", ride.id, method.id, amount, currency, tx.status)
    return tx


def retry_charge(user: User, ride: RideRequest, method_id: int) -> PaymentTransaction:
    """Rider retries a failed ride payment with another stored method."""
    if ride.rider_id != user.id:
        raise PaymentMethodError("Unauthorized.")
    if ride.status != "completed" or ride.payment_status != "failed":
        raise PaymentMethodError("This ride has no failed payment to retry.")
    ride.payment_method = get_owned(user, method_id)
    tx = charge_ride(ride)
    db.session.commit()
    return tx


# ------------------------------------------------------------------ refunds (issued by a manager)

class RefundError(Exception):
    """The refund is not possible. str(exc) is user-facing; `conflict` -> HTTP 409 instead of 400."""

    def __init__(self, message: str, conflict: bool = False) -> None:
        super().__init__(message)
        self.conflict = conflict


def refunded_amount(tx: PaymentTransaction) -> float:
    return round(sum(r.amount for r in tx.refunds if r.status == "succeeded"), 2)


def refundable_amount(tx: PaymentTransaction) -> float:
    """What can still be refunded on a charge (0 for anything that is not a successful charge)."""
    if (tx.kind or "") != "charge" or tx.status != "succeeded":
        return 0.0
    return max(0.0, round(tx.amount - refunded_amount(tx), 2))


def refund_charge(tx: PaymentTransaction, amount, reason: str, actor: str) -> PaymentTransaction:
    """
    Refund (part of) a successful ride payment back to the payment method it was charged to.
    Records a `refund` transaction (succeeded or failed) linked to the charge; commits; e-mails the
    user. Raises RefundError before anything is sent when the request is not acceptable.
    """
    import math

    if (tx.kind or "") != "charge" or tx.status != "succeeded":
        raise RefundError("Only successful payments can be refunded.", conflict=True)
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        raise RefundError("The refund amount must be a number.") from None
    if not math.isfinite(amount) or amount <= 0 or round(amount, 2) != round(amount, 6):
        raise RefundError("The refund amount must be a positive amount in cents (e.g. 5.50).")
    amount = round(amount, 2)
    remaining = refundable_amount(tx)
    if amount > remaining + 1e-9:
        raise RefundError(f"At most {tx.currency} {remaining:.2f} can still be refunded on this payment.", conflict=True)
    reason = " ".join((reason or "").split())[:300]
    if len(reason) < 5:
        raise RefundError("A refund needs a reason (at least 5 characters) - the user sees it.")
    method = tx.payment_method
    result = gw.get_gateway().refund(tx.provider_ref, method.token_id if method else None,
                                     customer_ref(tx.user_id), amount, tx.currency)
    what = f"ride #{tx.ride_id}" if tx.ride_id else f"payment #{tx.id}"
    refund = PaymentTransaction(
        kind="refund", refund_of_id=tx.id, user_id=tx.user_id, payment_method_id=tx.payment_method_id,
        ride_id=tx.ride_id, amount=amount, currency=tx.currency, status="succeeded" if result.ok else "failed",
        provider_ref=result.provider_ref, failure_reason=result.failure_reason, refund_reason=reason,
        created_by=(actor or "system")[:80], description=f"Refund of {what}: {reason}"[:200],
    )
    db.session.add(refund)
    db.session.commit()
    log.info("refund tx=%s amount=%.2f %s -> %s by %s", tx.id, amount, tx.currency, refund.status, actor)
    if result.ok:
        from background.service import _notify  # same best-effort e-mail helper

        _notify(tx.user, f"refund of {tx.currency} {amount:.2f}",
                f"We refunded {tx.currency} {amount:.2f} for {what} to "
                f"{method.display if method else 'your payment method'}.\nReason: {reason}")
    return refund
