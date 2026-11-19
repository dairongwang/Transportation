"""
A user's FINANCIAL TRANSACTION REPORT (used by the admin dashboard's Users tab).

One list, newest first, built from every place money is recorded for the user:

  type          where it comes from
  ------------  -----------------------------------------------------------------------------
  buy           ride payments by card / wallet (PaymentTransaction kind=charge), completed rides
                paid in CASH, service bookings the user made (Booking as buyer)
  sell          completed rides the user DROVE (the fare), bookings of services the user sells
  refund        refunds of the user's payments (PaymentTransaction kind=refund, issued by a manager)
  hold          pre-authorisations placed when a driver was ordered (money reserved, not charged)
  verification  the small hold placed and voided to validate a new payment method

Filters: date range (inclusive, UTC dates), payment method, transaction type.
Payment-method filter values:
  "<id>"         one of the user's own stored methods (removed ones included)
  "cash"         cash rides (as rider or as driver)
  "other_party"  sales paid electronically by the buyer (the buyer's card / wallet)
  "booking"      service bookings (paid with a booking token)

Totals count only SETTLED money: successful payments / refunds, completed cash rides, paid or
cash rides driven, completed bookings. Holds and verifications never move money.
No token ids, card numbers or another user's payment details are ever part of a row.
"""

from __future__ import annotations

from datetime import date, datetime, time

from flask import current_app

from models import Booking, PaymentMethod, PaymentTransaction, RideRequest, Service, User

TYPES = {
    "buy": "Buy (payment)", "sell": "Sell (earning)", "refund": "Refund",
    "hold": "Pre-authorisation hold", "verification": "Card verification",
}
KIND_TO_TYPE = {"charge": "buy", "refund": "refund", "hold": "hold", "verification": "verification"}
SPECIAL_METHODS = {
    "cash": "Cash", "other_party": "Card / wallet of the other party (sales)", "booking": "Service booking payment",
}


class LedgerFilterError(ValueError):
    """An invalid filter value (HTTP 400)."""


def _kind(tx: PaymentTransaction) -> str:
    if tx.kind:
        return tx.kind
    if tx.status in ("held", "captured", "released") or (tx.description or "").startswith("Pre-authorisation"):
        return "hold"
    return "verification" if tx.ride_id is None else "charge"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def method_options(user: User) -> list[dict]:
    """Values for the payment-method filter: the user's own methods (removed ones too) + the special ones."""
    own = PaymentMethod.query.filter_by(user_id=user.id).order_by(PaymentMethod.id).all()
    opts = [{"value": str(m.id), "label": m.display + (" (removed)" if m.deleted_at else "")} for m in own]
    return opts + [{"value": k, "label": v} for k, v in SPECIAL_METHODS.items()]


def _method_label(m: PaymentMethod | None) -> str:
    if m is None:
        return "—"
    return m.display + (" (removed)" if m.deleted_at else "")


def _rows(user: User) -> list[dict]:
    from . import service as payments

    currency = current_app.config.get("PAYMENT_CURRENCY", "USD")
    rows: list[dict] = []

    # A. the user's own payment operations
    for tx in PaymentTransaction.query.filter_by(user_id=user.id).all():
        kind = _kind(tx)
        ttype = KIND_TO_TYPE.get(kind, "buy")
        ride = tx.ride
        driver = ride.driver.user.username if ride is not None and ride.driver is not None else None
        settled = tx.status == "succeeded" and ttype in ("buy", "refund")
        rows.append({
            "id": f"pt-{tx.id}", "transaction_id": tx.id, "date": _iso(tx.created_at), "type": ttype,
            "category": "ride" if tx.ride_id else "payment method",
            "description": (f"Ride #{tx.ride_id} {ride.pickup_address} → {ride.dropoff_address}" if ride is not None
                            and ttype == "buy" else tx.description or ""),
            "counterparty": driver, "method": str(tx.payment_method_id) if tx.payment_method_id else None,
            "method_label": _method_label(tx.payment_method), "status": tx.status, "amount": round(tx.amount, 2),
            "currency": tx.currency,
            "direction": ("out" if ttype == "buy" else "in" if ttype == "refund" else "none") if settled else "none",
            "settled": settled, "reference": tx.provider_ref, "failure_reason": tx.failure_reason,
            "ride_id": tx.ride_id, "booking_id": None,
            "refund_of": tx.refund_of_id, "refund_reason": tx.refund_reason, "issued_by": tx.created_by,
            "refunded_amount": payments.refunded_amount(tx) if kind == "charge" else 0.0,
            "refundable_amount": payments.refundable_amount(tx),
        })

    # B. rides the user took and paid in CASH (card rides are already in A)
    for ride in RideRequest.query.filter_by(rider_id=user.id, status="completed", payment_method_id=None).all():
        rows.append(_ride_row(ride, "buy", ride.driver.user.username if ride.driver else None, "cash", currency,
                              status="cash", settled=True))

    # C. rides the user drove (their earnings)
    drv = user.driver_profile
    if drv is not None:
        for ride in RideRequest.query.filter_by(driver_id=drv.id, status="completed").all():
            cash = ride.payment_method_id is None
            status = ride.payment_status or ("cash" if cash else "pending")
            rows.append(_ride_row(ride, "sell", ride.rider.username, "cash" if cash else "other_party", currency,
                                  status=status, settled=status in ("paid", "cash")))

    # D / E. service bookings: as buyer, and on the user's own services
    for b in Booking.query.filter_by(buyer_id=user.id).all():
        rows.append(_booking_row(b, "buy", b.service.seller.username if b.service else None, currency))
    sold = Booking.query.join(Service, Booking.service_id == Service.id).filter(Service.seller_id == user.id).all()
    for b in sold:
        rows.append(_booking_row(b, "sell", b.buyer.username if b.buyer else None, currency))
    return rows


def _ride_row(ride: RideRequest, ttype: str, counterparty, method: str, currency: str, *, status: str, settled: bool) -> dict:
    amount = round(ride.fare or 0.0, 2)
    return {
        "id": f"ride-{ride.id}-{ttype}", "transaction_id": None, "date": _iso(ride.created_at), "type": ttype,
        "category": "ride", "description": f"Ride #{ride.id} {ride.pickup_address} → {ride.dropoff_address}",
        "counterparty": counterparty, "method": method, "method_label": SPECIAL_METHODS[method] if method != "other_party"
        else "Card / wallet of the rider", "status": status, "amount": amount, "currency": currency,
        "direction": ("out" if ttype == "buy" else "in") if settled else "none", "settled": settled,
        "reference": ride.payment_token if ttype == "sell" else None, "failure_reason": None,
        "ride_id": ride.id, "booking_id": None, "refund_of": None, "refund_reason": None, "issued_by": None,
        "refunded_amount": 0.0, "refundable_amount": 0.0,
    }


def _booking_row(b: Booking, ttype: str, counterparty, currency: str) -> dict:
    settled = b.status == "completed"
    title = b.service.title if b.service else f"service #{b.service_id}"
    return {
        "id": f"booking-{b.id}-{ttype}", "transaction_id": None, "date": _iso(b.created_at), "type": ttype,
        "category": "service", "description": f"Booking #{b.id}: {title}", "counterparty": counterparty,
        "method": "booking", "method_label": SPECIAL_METHODS["booking"], "status": b.status,
        "amount": round(b.amount or 0.0, 2), "currency": currency,
        "direction": ("out" if ttype == "buy" else "in") if settled else "none", "settled": settled,
        "reference": b.payment_token, "failure_reason": None, "ride_id": None, "booking_id": b.id,
        "refund_of": None, "refund_reason": None, "issued_by": None, "refunded_amount": 0.0, "refundable_amount": 0.0,
    }


def _parse_date(raw: str | None, name: str) -> date | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        raise LedgerFilterError(f"{name} must be a date (YYYY-MM-DD)") from None


def report(user: User, *, date_from: str | None = None, date_to: str | None = None, method: str | None = None,
           ttype: str | None = None) -> dict:
    """Filtered rows (newest first) + totals + the filter options. Raises LedgerFilterError."""
    d_from, d_to = _parse_date(date_from, "date_from"), _parse_date(date_to, "date_to")
    if d_from and d_to and d_from > d_to:
        raise LedgerFilterError("date_from must not be after date_to")
    ttype = (ttype or "").strip()
    if ttype and ttype not in TYPES:
        raise LedgerFilterError(f"unknown transaction type '{ttype}'")
    method = (method or "").strip()
    options = method_options(user)
    if method and method not in {o["value"] for o in options}:
        raise LedgerFilterError(f"unknown payment method '{method}' for this user")

    rows = _rows(user)
    if d_from:
        start = datetime.combine(d_from, time.min).isoformat()
        rows = [r for r in rows if r["date"] and r["date"] >= start]
    if d_to:
        end = datetime.combine(d_to, time.max).isoformat()
        rows = [r for r in rows if r["date"] and r["date"] <= end]
    if method:
        rows = [r for r in rows if r["method"] == method]
    if ttype:
        rows = [r for r in rows if r["type"] == ttype]
    rows.sort(key=lambda r: (r["date"] or "", r["id"]), reverse=True)

    money_out = round(sum(r["amount"] for r in rows if r["direction"] == "out"), 2)
    money_in = round(sum(r["amount"] for r in rows if r["direction"] == "in"), 2)
    by_type = {t: {"count": 0, "settled_amount": 0.0} for t in TYPES}
    for r in rows:
        by_type[r["type"]]["count"] += 1
        if r["settled"]:
            by_type[r["type"]]["settled_amount"] = round(by_type[r["type"]]["settled_amount"] + r["amount"], 2)
    return {
        "items": rows,
        "totals": {
            "count": len(rows), "currency": current_app.config.get("PAYMENT_CURRENCY", "USD"),
            "money_out": money_out, "money_in": money_in, "net": round(money_in - money_out, 2),
            "open_holds": round(sum(r["amount"] for r in rows if r["type"] == "hold" and r["status"] == "held"), 2),
            "by_type": by_type,
        },
        "filters": {"date_from": d_from.isoformat() if d_from else None, "date_to": d_to.isoformat() if d_to else None,
                    "method": method or None, "type": ttype or None},
        "types": [{"value": k, "label": v} for k, v in TYPES.items()],
        "methods": options,
    }


def transaction_row(tx: PaymentTransaction) -> dict:
    """The report row of one PaymentTransaction (for the refund page)."""
    return next(r for r in _rows(tx.user) if r.get("transaction_id") == tx.id)
