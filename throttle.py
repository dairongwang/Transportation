"""
IP-based rate limiting (Flask-Limiter) and failure counters used for CAPTCHA decisions.

This complements the per-account lockout in models.User: lockout alone lets an attacker
lock a victim out by hammering their username, so we also throttle by client IP and ask
for a CAPTCHA after a few failures - which stops bots before the lockout triggers.

Storage: RATELIMIT_STORAGE_URI  (memory:// for one process, redis://host:6379/0 for
multi-worker production). Flask-Limiter is optional: if it is not installed the app
still runs and `limiter_status()` reports "unavailable" so /dev/env and the doctor can
flag it.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from flask import current_app, flash, redirect, render_template, request, url_for

from clock import utcnow

log = logging.getLogger("auth.throttle")

try:
    from flask_limiter import Limiter
    from flask_limiter.errors import RateLimitExceeded

    HAVE_LIMITER = True
except ImportError:  # pragma: no cover
    Limiter = None  # type: ignore[assignment,misc]
    RateLimitExceeded = None  # type: ignore[assignment,misc]
    HAVE_LIMITER = False


def client_ip() -> str:
    """Client address. With BEHIND_PROXY>0 ProxyFix has already rewritten remote_addr."""
    return (request.remote_addr or "127.0.0.1")[:45]


class _NoopLimiter:
    """Stand-in when flask_limiter is missing: decorators become no-ops."""

    enabled = False

    def init_app(self, app):
        pass

    def limit(self, *args, **kwargs):
        return lambda f: f

    def exempt(self, f):
        return f

    def reset(self):
        pass


def _limit_from_config(key: str):
    return lambda: current_app.config.get(key, "")


if HAVE_LIMITER:
    limiter = Limiter(key_func=client_ip, default_limits=[], headers_enabled=True)
else:  # pragma: no cover
    limiter = _NoopLimiter()

# Route decorators (limits are read from config lazily, so tests/env can override them).
login_limit = limiter.limit(_limit_from_config("RATELIMIT_LOGIN"), methods=["POST"])
two_factor_limit = limiter.limit(_limit_from_config("RATELIMIT_2FA"), methods=["POST"])
register_limit = limiter.limit(_limit_from_config("RATELIMIT_REGISTER"), methods=["POST"])
reset_limit = limiter.limit(_limit_from_config("RATELIMIT_RESET"), methods=["POST"])
code_send_limit = limiter.limit(_limit_from_config("RATELIMIT_CODE_SEND"), methods=["POST"])


def init_throttling(app) -> None:
    if app.config.get("BEHIND_PROXY", 0) > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix

        n = app.config["BEHIND_PROXY"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    if not HAVE_LIMITER:  # pragma: no cover
        app.logger.warning("flask_limiter not installed - IP rate limiting is DISABLED. pip install -r requirements.txt")
        return
    # Flask-Limiter reads RATELIMIT_ENABLED / RATELIMIT_STORAGE_URI / RATELIMIT_HEADERS_ENABLED from app.config
    limiter.init_app(app)

    @app.errorhandler(429)
    def _too_many(exc):
        retry = getattr(exc, "retry_after", None)
        if request.method == "POST" and request.endpoint:
            flash("Too many attempts from your network. Please wait a minute and try again.", "error")
            # Show the same page again rather than a bare error
            try:
                return redirect(url_for(request.endpoint, **(request.view_args or {}))), 429
            except Exception:  # noqa: BLE001
                pass
        return render_template("errors/429.html", retry_after=retry), 429


def limiter_status() -> str:
    if not HAVE_LIMITER:
        return "unavailable (flask_limiter not installed)"
    if not current_app.config.get("RATELIMIT_ENABLED", True):
        return "disabled (RATELIMIT_ENABLED=false)"
    return f"enabled ({current_app.config.get('RATELIMIT_STORAGE_URI', 'memory://')})"


# ------------------------------------------------------- failure counters

FAILURE_EVENTS = ("login_failed", "mfa_failed", "captcha_failed", "reset_mfa_failed")


def recent_failures(ip: str | None = None, user_id: int | None = None) -> int:
    """Number of failed auth events from this IP and/or for this user in the CAPTCHA window."""
    from models import AuthEvent

    window = timedelta(minutes=current_app.config["CAPTCHA_WINDOW_MINUTES"])
    q = AuthEvent.query.filter(AuthEvent.event.in_(FAILURE_EVENTS), AuthEvent.created_at > utcnow() - window)
    clauses = []
    if ip:
        clauses.append(AuthEvent.ip_address == ip)
    if user_id is not None:
        clauses.append(AuthEvent.user_id == user_id)
    if not clauses:
        return 0
    from sqlalchemy import or_

    return q.filter(or_(*clauses)).count()
