"""
Rider account + payment methods (credit/debit card, Stripe, PayPal).

  gateway.py        PaymentGateway interface + the offline FAKE gateway (Stripe-style test
                    cards, deterministic tokens, scripted declines)
  service.py        validation, add / modify / delete / set-default, charging a ride
  fake_provider.py  fake Stripe / PayPal "approve this connection" pages (dev only)
  routes.py         the Account tab: /account, /account/payments/...
"""

from flask import Blueprint

bp = Blueprint("account", __name__, url_prefix="/account")
api_bp = Blueprint("account_api", __name__, url_prefix="/api/account")  # JSON, 401 for anonymous

from . import routes  # noqa: E402,F401
