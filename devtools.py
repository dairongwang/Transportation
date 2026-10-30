"""
Development / test-environment helpers. Registered only when ENABLE_DEV_TOOLS is true
(ProductionConfig forces it off).

  GET  /healthz            liveness probe (always registered)
  GET  /dev/outbox         fake inbox: codes sent via the console/memory backends,
                           readable from a phone/tablet on the same network
  GET  /dev/outbox.json    same, as JSON (used by scripts/smoke_test.py)
  POST /dev/outbox/clear   empty the fake inbox
  GET  /dev/env            platform / dependency / backend report for this install
  GET  /dev/env.json       same, as JSON (used by scripts/check_env.py)
"""

from __future__ import annotations

import importlib.metadata
import os
import platform
import socket
import sys

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, url_for

from auth import crypto
from auth import mfa as mfa_module
from auth.delivery import clear_messages, outbox_path, recent_messages
from config import DUMMY_MFA_ENCRYPTION_KEY, is_dummy
from extensions import csrf, db
from throttle import limiter_status

dev_bp = Blueprint("dev", __name__, url_prefix="/dev")


def _version(dist: str) -> str | None:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return None


def environment_report() -> dict:

    cfg = current_app.config
    return {
        "platform": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "hostname": socket.gethostname(),
        },
        "dependencies": {
            "flask": _version("flask"),
            "sqlalchemy": _version("sqlalchemy"),
            "flask-login": _version("flask-login"),
            "flask-limiter": _version("flask-limiter"),
            "redis": _version("redis"),
            "cryptography": _version("cryptography"),
            "qrcode": _version("qrcode"),
        },
        "features": {
            "totp_backend": "stdlib (auth/totp.py)",
            "secret_encryption": crypto.backend_name(),
            "qr_rendering": "svg (qrcode)" if mfa_module.HAVE_QRCODE else "unavailable - manual key only",
            "email_backend": cfg["EMAIL_BACKEND"],
            "sms_backend": cfg["SMS_BACKEND"],
            "csrf_enabled": bool(cfg.get("CSRF_ENABLED", True)),
            "rate_limiting": limiter_status(),
            "captcha_provider": cfg["CAPTCHA_PROVIDER"],
            "oauth_mode": cfg["OAUTH_MODE"] + (f" ({cfg['OAUTH_FAKE_BASE_URL']})" if cfg.get("OAUTH_FAKE_BASE_URL") else ""),
            "oauth_providers": ", ".join(cfg["OAUTH_PROVIDERS"]),
            "captcha_after_failures": cfg["CAPTCHA_AFTER_FAILURES"],
            "account_lockout": f"{cfg['LOGIN_MAX_FAILED_ATTEMPTS']} failures -> {cfg['LOGIN_LOCKOUT_SECONDS']}s",
            "debug": bool(cfg.get("DEBUG")),
            "dev_tools": bool(cfg.get("ENABLE_DEV_TOOLS")),
        },
        "storage": {
            "database": cfg["SQLALCHEMY_DATABASE_URI"],
            "instance_path": current_app.instance_path,
            "outbox_path": outbox_path(),
            "db_ok": _db_ok(),
        },
        "secrets": {
            "secret_key_is_dummy": is_dummy(cfg["SECRET_KEY"]),
            "mfa_key_is_dummy": cfg["MFA_ENCRYPTION_KEY"] == DUMMY_MFA_ENCRYPTION_KEY,
            "mfa_previous_keys": len(cfg.get("MFA_ENCRYPTION_KEY_PREVIOUS") or []),
            "captcha_key_is_dummy": is_dummy(cfg["CAPTCHA_SECRET_KEY"]),
            "oauth_credentials_are_dummy": any(is_dummy(cfg[k]) for k in ("OAUTH_GOOGLE_CLIENT_SECRET", "OAUTH_FACEBOOK_APP_SECRET", "OAUTH_APPLE_PRIVATE_KEY")),
        },
        "network": {"lan_addresses": lan_addresses()},
    }


def _db_ok() -> bool:
    try:
        db.session.execute(db.text("SELECT 1"))
        return True
    except Exception:  # pragma: no cover
        return False


def lan_addresses() -> list[str]:
    """Best-effort list of non-loopback IPv4 addresses (for phone/tablet testing)."""
    addrs = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except socket.gaierror:
        pass
    try:  # route-based discovery works even when hostname doesn't resolve
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        addrs.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(a for a in addrs if not a.startswith("127."))


@dev_bp.route("/outbox")
def outbox():
    return render_template("dev/outbox.html", messages=recent_messages(30))


@dev_bp.route("/outbox.json")
def outbox_json():
    return jsonify([m.__dict__ for m in recent_messages(30)])


@dev_bp.route("/outbox/clear", methods=["POST"])
@csrf.exempt
def outbox_clear():
    clear_messages()
    flash("Fake inbox cleared.", "info")
    return redirect(url_for("dev.outbox"))


@dev_bp.route("/env")
def env():
    return render_template("dev/env.html", report=environment_report())


@dev_bp.route("/env.json")
def env_json():
    return jsonify(environment_report())


def register_devtools(app) -> None:
    @app.route("/healthz")
    def healthz():
        return jsonify(status="ok", platform=app.config.get("PLATFORM"), pid=os.getpid())

    if app.config.get("ENABLE_DEV_TOOLS"):
        app.register_blueprint(dev_bp)
        app.logger.warning("Dev tools enabled: /dev/outbox and /dev/env are public. Never enable in production.")
