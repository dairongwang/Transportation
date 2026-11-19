"""Extension singletons: SQLAlchemy and a dependency-free CSRF guard."""

from __future__ import annotations

import hmac
import secrets

from flask import abort, current_app, request, session
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class CSRFProtect:
    """Synchroniser token: every POST must echo the session token in the `csrf_token` field."""

    SESSION_KEY = "_csrf"

    def init_app(self, app) -> None:
        app.jinja_env.globals["csrf_token"] = self.token
        app.before_request(self._protect)

    def token(self) -> str:
        if self.SESSION_KEY not in session:
            session[self.SESSION_KEY] = secrets.token_urlsafe(32)
        return session[self.SESSION_KEY]

    def _protect(self):
        if request.method in ("GET", "HEAD", "OPTIONS") or not current_app.config.get("CSRF_ENABLED", True):
            return None
        expected = session.get(self.SESSION_KEY, "")
        submitted = request.form.get("csrf_token", "")
        if not expected or not submitted or not hmac.compare_digest(expected, submitted):
            abort(400, description="The form expired (CSRF token missing or invalid). Reload the page and try again.")
        return None


csrf = CSRFProtect()
