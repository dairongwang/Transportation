"""
Background checks: only users who passed one can use the app.

  provider.py   provider interface + the offline FAKE provider (scripted outcomes, signed webhooks)
  service.py    clearance rules, submit, apply the provider's result, manual review, enforcement
  routes.py     GET/POST /background-check, POST /background-check/dispute, GET /api/background-check,
                POST /background-check/webhook, /dev/background-provider (fake provider console, dev only)
  admin_api.py  /admin-api/v1 - service-to-service API used by the SEPARATE admin dashboard
                (admin_dashboard/), where managers review flagged reports and decide disputes

`init_app()` installs the GATE: every request of a logged-in user who has not passed is
refused - pages redirect to /background-check, JSON / SSE endpoints answer 403 - except the
few endpoints needed to get checked or to manage the account's sign-in (log out, 2FA,
password). Defence in depth: the ride matcher additionally ignores drivers whose check does
not cover driving, and refuses riders / drivers who have not passed (rides/matching.py).
"""

from flask import Blueprint, flash, jsonify, redirect, request, url_for
from flask_login import current_user

bp = Blueprint("background", __name__)
# Stand-in for the provider's side (finishing pending reports), dev only. Manager decisions live
# in the separate admin dashboard.
dev_bp = Blueprint("dev_background", __name__, url_prefix="/dev/background-provider")

# Endpoints a logged-in user may reach before passing (blueprint prefixes or exact names).
EXEMPT_PREFIXES = (
    "background.",       # the check itself
    "auth.",             # log in / out, 2FA, password, security settings
    "dev.", "dev_background.", "fake_oauth.", "fake_payments.",  # dev tools + stand-ins for third parties
    "admin_api.",        # service-to-service (bearer token), no user session involved
)
EXEMPT_ENDPOINTS = {"static", "healthz"}


def _exempt(endpoint: str | None) -> bool:
    if endpoint is None:  # 404 / 405: let Flask answer normally
        return True
    return endpoint in EXEMPT_ENDPOINTS or endpoint.startswith(EXEMPT_PREFIXES)


def _gate():
    from . import service

    if _exempt(request.endpoint) or not current_user.is_authenticated:
        return None
    if current_user.id in service.passed_user_ids([current_user.id]):
        return None  # fast path: one light query for the (usual) user who passed
    st = service.clearance(current_user)
    if st.passed:
        return None
    if request.path.startswith(("/api/", "/events/")) or request.is_json:
        return jsonify(error="Background check required: " + st.message, background_check=st.as_dict(),
                       url=url_for("background.check")), 403
    flash(st.message, "warning")
    return redirect(url_for("background.check"))


def init_app(app) -> None:
    from . import routes  # noqa: F401  (registers the routes on the blueprints)
    from . import service
    from .admin_api import admin_api_bp

    from extensions import db

    from . import live

    live.install_transaction_feed(db)  # managers see financial activity without a refresh
    app.register_blueprint(bp)
    app.register_blueprint(admin_api_bp)  # answers 404 itself when ADMIN_API_ENABLED=false
    if app.config.get("ENABLE_DEV_TOOLS"):
        app.register_blueprint(dev_bp)
        routes.register_legacy_redirect(app)
    app.before_request(_gate)

    @app.context_processor
    def _inject():
        def background_clearance():
            return service.clearance(current_user) if current_user.is_authenticated else None

        def background_version():
            from . import live

            return live.version(current_user) if current_user.is_authenticated else ""

        return {"background_clearance": background_clearance, "background_version": background_version}
