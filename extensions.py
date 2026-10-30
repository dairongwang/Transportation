"""Flask extension singletons (initialised in create_app)."""

from __future__ import annotations

import hmac
import secrets

from flask import Flask, abort, request, session
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
login_manager = LoginManager()

login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"
# Invalidate the session if IP / user-agent changes (protects against cookie theft).
login_manager.session_protection = "strong"


class CSRFProtect:
    """
    Synchroniser-token CSRF protection with no third-party dependency.

    * A random token is stored in the (signed, HttpOnly) session and exposed to
      templates as ``csrf_token()``.
    * Every state-changing request (POST/PUT/PATCH/DELETE) must echo it back in the
      ``csrf_token`` form field or the ``X-CSRF-Token`` header; mismatch -> HTTP 400.
    * ``@csrf.exempt`` marks a view as exempt (used by the dev-only fake inbox).
    Combined with ``SameSite=Lax`` cookies this covers the classic cross-site POST.
    """

    SESSION_KEY = "_csrf_token"
    FIELD = "csrf_token"
    HEADER = "X-CSRF-Token"
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

    def __init__(self) -> None:
        self._exempt: set[str] = set()

    def init_app(self, app: Flask) -> None:
        app.jinja_env.globals["csrf_token"] = self.generate_token
        app.before_request(self._protect)
        app.extensions["csrf"] = self

    # -------------------------------------------------------------- tokens
    def generate_token(self) -> str:
        token = session.get(self.SESSION_KEY)
        if not token:
            token = secrets.token_urlsafe(32)
            session[self.SESSION_KEY] = token
        return token

    def validate(self, submitted: str | None) -> bool:
        expected = session.get(self.SESSION_KEY)
        return bool(expected and submitted and hmac.compare_digest(expected, submitted))

    # ------------------------------------------------------------- control
    def exempt(self, view):
        self._exempt.add(f"{view.__module__}.{view.__name__}")
        return view

    def _protect(self):
        from flask import current_app

        if not current_app.config.get("CSRF_ENABLED", True):
            return None
        if request.method in self.SAFE_METHODS:
            return None
        view = current_app.view_functions.get(request.endpoint or "")
        if view is not None and f"{view.__module__}.{view.__name__}" in self._exempt:
            return None
        submitted = request.form.get(self.FIELD) or request.headers.get(self.HEADER)
        if not self.validate(submitted):
            abort(400, description="The CSRF token is missing or invalid. Reload the page and try again.")
        return None


csrf = CSRFProtect()
