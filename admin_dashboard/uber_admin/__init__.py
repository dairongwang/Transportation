"""
ServiceUber ADMIN DASHBOARD - a separate application for managers.

  * reviews flagged background-check reports (approve / reject)
  * decides disputes raised by rejected users (after the dispute's re-check)
  * keeps its own operators (managers / viewers) and its own audit log

It shares NO code and NO database with the ServiceUber app: everything goes through the app's
Admin API (/admin-api/v1, bearer token) - see uber_admin/client.py. Develop, test, deploy and
operate it on its own (own requirements, .env, port, WSGI entry point).
"""

from __future__ import annotations

import logging
import os

from flask import Flask, flash, g, redirect, render_template, request, url_for

from .client import MainAppClient, MainAppError, MainAppUnavailable
from .config import DEMO_USERS, get_config
from .extensions import csrf, db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def create_app(config_name: str | None = None, overrides: dict | None = None, api_client=None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(get_config(config_name))
    if overrides:
        app.config.update(overrides)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    csrf.init_app(app)
    app.extensions["main_api"] = api_client or MainAppClient(
        app.config["MAIN_APP_API_URL"], app.config["MAIN_APP_API_TOKEN"], app.config["MAIN_APP_API_TIMEOUT"])

    from .auth import bp as auth_bp, load_admin
    from .views import bp as views_bp

    app.before_request(load_admin)
    app.register_blueprint(auth_bp)
    app.register_blueprint(views_bp)
    _register_handlers(app)

    with app.app_context():
        db.create_all()
        if app.config.get("SEED_DEMO_USERS"):
            seed_demo_users()
    return app


def api() -> MainAppClient:
    from flask import current_app

    return current_app.extensions["main_api"]


def seed_demo_users() -> None:
    """DUMMY operators for development (only when the dashboard has no users yet)."""
    from .models import AdminUser

    if AdminUser.query.count():
        return
    for username, password, role, name in DEMO_USERS:
        u = AdminUser(username=username, role=role, display_name=name)
        u.set_password(password)
        db.session.add(u)
    db.session.commit()
    logging.getLogger("uber_admin").info("Seeded DUMMY admin users: %s", ", ".join(u[0] for u in DEMO_USERS))


def _register_handlers(app: Flask) -> None:
    @app.after_request
    def _headers(resp):
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                                "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if not request.path.startswith("/static/") and resp.mimetype != "text/event-stream":
            resp.headers["Cache-Control"] = "no-store"
        if app.config.get("SESSION_COOKIE_SECURE"):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    @app.errorhandler(MainAppUnavailable)
    def _unavailable(exc):
        return render_template("error.html", title="ServiceUber is not reachable", message=exc.message,
                               hint="Start the ServiceUber app (python app.py in the project root) or check "
                                    "MAIN_APP_API_URL in admin_dashboard/.env."), 503

    @app.errorhandler(MainAppError)
    def _api_error(exc):
        if exc.status == 401:
            return render_template("error.html", title="Admin API token rejected", message=exc.message,
                                   hint="MAIN_APP_API_TOKEN (admin_dashboard/.env) must equal ADMIN_API_TOKEN "
                                        "of the ServiceUber app."), 502
        if exc.status == 404:
            return render_template("error.html", title="Not found", message=exc.message, hint=None), 404
        if request.method == "POST" and g.get("admin") is not None:
            flash(exc.message, "error")
            return redirect(request.referrer or url_for("views.dashboard"))
        return render_template("error.html", title=f"ServiceUber answered HTTP {exc.status}", message=exc.message,
                               hint=None), 502

    @app.errorhandler(400)
    def _bad_request(exc):
        return render_template("error.html", title="Bad request", message=exc.description, hint=None), 400

    @app.errorhandler(403)
    def _forbidden(exc):
        return render_template("error.html", title="Not allowed", message=exc.description, hint=None), 403

    @app.errorhandler(404)
    def _not_found(exc):
        return render_template("error.html", title="Not found", message="This page does not exist.", hint=None), 404

    @app.template_filter("dt")
    def _dt(value):
        """ISO timestamp from the API -> 'YYYY-MM-DD HH:MM'."""
        if not value:
            return "—"
        text = str(value).replace("T", " ")
        return text[:16]
