"""
FAKE vault tokenisation endpoint + FAKE Stripe / PayPal "connect your account" pages (dev only).

    POST /dev/payments/tokenize   {number, exp_month, exp_year, cvc, publishable_key}
                                  -> {token, brand, last4, exp_month, exp_year}
    Plays Stripe.js: the BROWSER calls this directly with the card data and receives a
    single-use token; our own server never sees the number. Requires the publishable key.

Linking a wallet to a real provider is a redirect dance: the app sends the user to the
provider, the user approves, the provider redirects back with a one-time code which the app
exchanges for a token. This blueprint plays the provider so the whole dance can be
validated offline:

    GET  /dev/payments/<provider>/authorize?state=..&redirect_uri=..   approval page
    POST /dev/payments/<provider>/authorize                            approve -> redirect back
                                                                       with ?code=..&state=..
                                                                       cancel  -> ?error=cancelled

The code is a single-use WALLET GRANT minted by the vault (payments/vault.py): signed,
short-lived, one-shot, and carrying only a masked e-mail + fingerprint - the full e-mail the
user typed on this (provider) page never travels to our app. Like the fake OAuth provider
this is registered only when ENABLE_DEV_TOOLS is on.
"""

from __future__ import annotations

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request

from extensions import csrf

from . import vault
from .cards import PaymentError

fake_payments_bp = Blueprint("fake_payments", __name__, url_prefix="/dev/payments")

PROVIDERS = {"stripe": "Stripe", "paypal": "PayPal"}


@fake_payments_bp.route("/tokenize", methods=["POST"])
@csrf.exempt  # the vault is a different site in real life; it authenticates with the publishable key
def tokenize():
    data = request.get_json(silent=True) or request.form
    key = data.get("publishable_key") or request.headers.get("X-Publishable-Key", "")
    if key != current_app.config.get("STRIPE_PUBLISHABLE_KEY"):
        return jsonify(error="invalid_publishable_key", message="Unknown publishable key."), 401
    try:
        tok = vault.create_single_use_token(
            str(data.get("number", "")), data.get("exp_month"), data.get("exp_year"), str(data.get("cvc", "")),
        )
    except PaymentError as exc:
        # like a real vault: report what is wrong, log nothing that identifies the card
        return jsonify(error=exc.code, message=str(exc)), 402
    current_app.logger.info("fake vault: single-use token minted for %s •••• %s", tok.brand, tok.last4)
    return jsonify(token=tok.token, brand=tok.brand, last4=tok.last4, exp_month=tok.exp_month, exp_year=tok.exp_year)


@fake_payments_bp.route("/<provider>/authorize", methods=["GET", "POST"])
@csrf.exempt  # the "provider" is a different site; it has no access to our CSRF token
def authorize(provider: str):
    if provider not in PROVIDERS:
        abort(404)
    state = request.values.get("state", "")
    redirect_uri = request.values.get("redirect_uri", "")
    if not state or not redirect_uri.startswith("/"):
        abort(400, description="state and a relative redirect_uri are required")
    if request.method == "POST":
        sep = "&" if "?" in redirect_uri else "?"
        if request.form.get("decision") != "approve":
            return redirect(f"{redirect_uri}{sep}error=cancelled&state={state}")
        email = request.form.get("email", "").strip().lower()
        if "@" not in email:
            return render_template("dev/payment_consent.html", provider=provider, provider_name=PROVIDERS[provider],
                                   state=state, redirect_uri=redirect_uri, email=email,
                                   error="Enter the e-mail of the (dummy) account to link."), 400
        grant = vault.create_wallet_grant(provider, email)  # only masked e-mail + fingerprint inside
        current_app.logger.info("fake %s: account %s approved, grant minted", PROVIDERS[provider], grant.account_email_masked)
        return redirect(f"{redirect_uri}{sep}code={grant.token}&state={state}")
    suggested = request.args.get("email") or f"dummy.rider@{provider}.example"
    return render_template("dev/payment_consent.html", provider=provider, provider_name=PROVIDERS[provider],
                           state=state, redirect_uri=redirect_uri, email=suggested, error=None)
