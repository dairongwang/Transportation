"""
The Account tab.

  GET       /account                         overview: profile, default payment method, recent rides
  POST      /account/profile                 update display name
  GET       /account/payments                payment methods + transaction history
  GET/POST  /account/payments/card/new       add a credit / debit card (tokenised by the gateway)
  POST      /account/payments/connect/<p>    start linking Stripe / PayPal (redirect to provider)
  GET       /account/payments/connect/<p>/callback   provider redirects back here
  GET/POST  /account/payments/<id>/edit      modify nickname / name on card / expiry / default
  POST      /account/payments/<id>/validate  validate again (small hold, voided immediately)
  POST      /account/payments/<id>/default   make default
  POST      /account/payments/<id>/delete    remove (soft delete)
  POST      /account/payments/retry/<ride>   retry a failed ride payment with another method
  GET       /api/account/payments            JSON list (no tokens, no numbers)
"""

from __future__ import annotations

import secrets

from flask import abort, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from extensions import db
from models import PaymentTransaction, RideRequest

from . import api_bp, bp, gateway as gw, service
from .gateway import PaymentError
from .service import PaymentMethodError

CONNECT_STATE_KEY = "payment_connect_state"


def _method_json(m) -> dict:
    return {
        "id": m.id, "kind": m.kind, "label": m.label, "display": m.display, "brand": m.brand, "last4": m.last4,
        "expiry": m.expiry, "expired": m.is_expired, "account_email_masked": m.account_email_masked,
        "billing_name": m.billing_name, "is_default": m.is_default, "created_at": m.created_at.isoformat(),
        "verified": m.is_verified, "verified_at": m.verified_at.isoformat() if m.verified_at else None,
        "token_hint": m.token_hint,  # never the token id itself
    }


@bp.app_context_processor
def _inject():
    return {"payments_mode": lambda: current_app.config.get("PAYMENTS_MODE", "fake")}


# ================================================================= overview / profile

@bp.route("")
@login_required
def overview():
    recent = (RideRequest.query.filter_by(rider_id=current_user.id)
              .order_by(RideRequest.created_at.desc()).limit(5).all())
    return render_template(
        "account/overview.html", methods=service.active_methods(current_user),
        default=service.default_method(current_user), recent_rides=recent,
        can_pay=service.can_have_payment_methods(current_user),
    )


@bp.route("/profile", methods=["POST"])
@login_required
def profile():
    name = request.form.get("display_name", "").strip()[:120]
    current_user.display_name = name or None
    db.session.commit()
    flash("Profile updated.", "success")
    return redirect(url_for("account.overview"))


# ================================================================= payment methods

@bp.route("/payments")
@login_required
def payments():
    txs = (PaymentTransaction.query.filter_by(user_id=current_user.id)
           .order_by(PaymentTransaction.created_at.desc()).limit(20).all())
    failed_rides = RideRequest.query.filter_by(rider_id=current_user.id, status="completed", payment_status="failed").all()
    return render_template(
        "account/payments.html", methods=service.active_methods(current_user), transactions=txs,
        failed_rides=failed_rides, can_pay=service.can_have_payment_methods(current_user),
        max_methods=current_app.config["PAYMENT_METHODS_MAX"], validation_amount=service.validation_amount(),
    )


@bp.route("/payments/card/new", methods=["GET", "POST"])
@login_required
def add_card():
    if not service.can_have_payment_methods(current_user):
        flash("Seller-only accounts do not need payment methods.", "error")
        return redirect(url_for("account.payments"))
    form = {"billing_name": current_user.display_name or "", "label": "", "make_default": ""}
    ctx = dict(validation_amount=service.validation_amount(), tokenize_url=current_app.config["TOKENIZATION_URL"],
               publishable_key=current_app.config["STRIPE_PUBLISHABLE_KEY"])
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in form}
        # Defence in depth: this endpoint must only ever receive a token. If a (buggy or
        # malicious) client posts card data, refuse it and do not process anything.
        if any(k in request.form for k in ("number", "cvc", "card_number")) or any(
            gw.looks_like_pan(v) for v in request.form.values()
        ):
            current_app.logger.warning("Raw card data posted to /account/payments/card/new by user=%s - rejected", current_user.id)
            flash(gw.failure_message("raw_card_data"), "error")
            return render_template("account/card_form.html", form=form, **ctx), 400
        try:
            m = service.add_card(
                current_user, card_token=request.form.get("card_token", ""), billing_name=form["billing_name"],
                label=form["label"], make_default=bool(form["make_default"]),
            )
        except (PaymentError, PaymentMethodError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return render_template("account/card_form.html", form=form, **ctx), 400
        flash(f"{m.display} added and validated (token {m.token_hint})." + (" It is your default." if m.is_default else ""), "success")
        return redirect(url_for("account.payments"))
    return render_template("account/card_form.html", form=form, **ctx)


@bp.route("/payments/connect/<provider>", methods=["POST"])
@login_required
def connect(provider: str):
    if provider not in ("stripe", "paypal"):
        abort(404)
    if not service.can_have_payment_methods(current_user):
        flash("Seller-only accounts do not need payment methods.", "error")
        return redirect(url_for("account.payments"))
    if current_app.config.get("PAYMENTS_MODE") != "fake" or not current_app.config.get("ENABLE_DEV_TOOLS"):
        flash("Linking a wallet needs the real provider integration (PAYMENTS_MODE=real), which the demo does not ship.", "error")
        return redirect(url_for("account.payments"))
    state = secrets.token_urlsafe(16)
    session[CONNECT_STATE_KEY] = {"state": state, "provider": provider, "label": request.form.get("label", "")[:60],
                                  "make_default": bool(request.form.get("make_default"))}
    callback = url_for("account.connect_callback", provider=provider)
    return redirect(url_for("fake_payments.authorize", provider=provider, state=state, redirect_uri=callback))


@bp.route("/payments/connect/<provider>/callback")
@login_required
def connect_callback(provider: str):
    pending = session.pop(CONNECT_STATE_KEY, None)
    state = request.args.get("state", "")
    if not pending or pending.get("provider") != provider or not secrets.compare_digest(pending.get("state", ""), state):
        flash("The connection attempt is invalid or has expired. Please try again.", "error")
        return redirect(url_for("account.payments"))
    if request.args.get("error"):
        flash(f"{provider.title()} connection cancelled.", "info")
        return redirect(url_for("account.payments"))
    grant = request.args.get("code", "")  # single-use wallet grant minted by the provider
    try:
        m = service.add_wallet(current_user, grant, expected_kind=provider, label=pending.get("label"),
                               make_default=pending.get("make_default", False))
    except PaymentError as exc:
        db.session.rollback()
        if exc.code in ("invalid_token", "token_expired", "token_used"):
            flash("The provider returned an invalid code. Please try again.", "error")
        else:
            flash(str(exc), "error")
        return redirect(url_for("account.payments"))
    except PaymentMethodError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("account.payments"))
    flash(f"{m.display} linked and validated." + (" It is your default." if m.is_default else ""), "success")
    return redirect(url_for("account.payments"))


@bp.route("/payments/<int:method_id>/edit", methods=["GET", "POST"])
@login_required
def edit_method(method_id: int):
    try:
        m = service.get_owned(current_user, method_id)
    except PaymentMethodError:
        abort(404)
    if request.method == "POST":
        try:
            service.update_method(
                current_user, m.id, label=request.form.get("label", ""),
                billing_name=request.form.get("billing_name") if m.kind == "card" else None,
                exp_month=request.form.get("exp_month"), exp_year=request.form.get("exp_year"),
                make_default=bool(request.form.get("make_default")),
            )
        except (PaymentError, PaymentMethodError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return render_template("account/edit_method.html", m=m), 400
        flash(f"{m.display} updated.", "success")
        return redirect(url_for("account.payments"))
    return render_template("account/edit_method.html", m=m)


@bp.route("/payments/<int:method_id>/validate", methods=["POST"])
@login_required
def validate(method_id: int):
    try:
        m = service.get_owned(current_user, method_id)
        tx = service.revalidate(current_user, method_id)
        if tx is None:
            flash(f"{m.display} marked as verified (validation holds are disabled).", "info")
        elif tx.status == "voided":
            flash(f"{m.display} validated: a {tx.currency} {tx.amount:.2f} hold was placed and voided.", "success")
        else:
            flash(f"{m.display} validated; the {tx.currency} {tx.amount:.2f} hold will be released by the provider automatically.", "warning")
    except (PaymentError, PaymentMethodError) as exc:
        flash(str(exc), "error")
    return redirect(url_for("account.payments"))


@bp.route("/payments/<int:method_id>/default", methods=["POST"])
@login_required
def make_default(method_id: int):
    try:
        m = service.set_default(current_user, method_id)
        flash(f"{m.display} is now your default.", "success")
    except PaymentMethodError as exc:
        flash(str(exc), "error")
    return redirect(url_for("account.payments"))


@bp.route("/payments/<int:method_id>/delete", methods=["POST"])
@login_required
def delete_method(method_id: int):
    try:
        m = service.get_owned(current_user, method_id)
        display = m.display
        service.delete_method(current_user, method_id)
        flash(f"{display} removed.", "info")
    except PaymentMethodError as exc:
        flash(str(exc), "error")
    return redirect(url_for("account.payments"))


@bp.route("/payments/retry/<int:ride_id>", methods=["POST"])
@login_required
def retry(ride_id: int):
    ride = db.session.get(RideRequest, ride_id) or abort(404)
    try:
        tx = service.retry_charge(current_user, ride, request.form.get("payment_method_id", type=int) or 0)
        if tx.status == "succeeded":
            flash(f"Ride #{ride.id} paid (${tx.amount:.2f}).", "success")
        else:
            flash(f"Payment failed again: {gw.failure_message(tx.failure_reason)}", "error")
    except (PaymentError, PaymentMethodError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(request.form.get("next") or url_for("account.payments"))


# ================================================================= JSON

@api_bp.route("/payments")
@login_required
def api_payments():
    return jsonify(methods=[_method_json(m) for m in service.active_methods(current_user)])
