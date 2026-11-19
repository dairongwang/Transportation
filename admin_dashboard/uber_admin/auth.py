"""Sign-in for dashboard operators (managers / viewers): password, lockout, hardened session."""

from __future__ import annotations

from functools import wraps
from urllib.parse import urlparse

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for

from .extensions import db
from .models import AdminUser, AuditEntry, utcnow

bp = Blueprint("auth", __name__)
SESSION_KEY = "admin"


def audit(action: str, target: str | None = None, outcome: str = "ok", detail: str | None = None,
          actor: str | None = None) -> None:
    admin = g.get("admin")
    db.session.add(AuditEntry(actor=actor or (admin.username if admin else None), action=action, target=target,
                              outcome=outcome, detail=(detail or "")[:500] or None, ip=(request.remote_addr or "")[:45]))
    db.session.commit()


def load_admin():
    """Resolve the signed-in operator for this request (None if the session is missing / stale)."""
    g.admin = None
    data = session.get(SESSION_KEY)
    if not data:
        return
    user = db.session.get(AdminUser, data.get("id"))
    if user is None or not user.is_active or data.get("stamp") != user.session_stamp:
        session.pop(SESSION_KEY, None)
        return
    g.admin = user


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("admin") is None:
            return redirect(url_for("auth.login", next=request.full_path if request.method == "GET" else None))
        return view(*args, **kwargs)
    return wrapper


def manager_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("admin") is None:
            return redirect(url_for("auth.login"))
        if not g.admin.can_decide:
            audit("decision_denied", request.path, "denied", "viewer accounts are read-only")
            abort(403, description="Your account is read-only (viewer). Only managers can decide.")
        return view(*args, **kwargs)
    return wrapper


def _safe_next(target: str | None) -> str | None:
    if not target:
        return None
    p = urlparse(target)
    return target if not p.scheme and not p.netloc and target.startswith("/") and not target.startswith("//") else None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.get("admin") is not None:
        return redirect(url_for("views.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = AdminUser.query.filter_by(username=username).first()
        if user is not None and user.is_locked:
            audit("login_blocked", username, "denied", "account locked", actor=username)
            flash("This account is temporarily locked after too many failed attempts.", "error")
            return render_template("login.html"), 423
        if user is None or not user.is_active or not user.check_password(password):
            if user is None:
                AdminUser(username="x", password_hash="").set_password(password)  # similar timing
            else:
                locked = user.register_failure(current_app.config["LOGIN_MAX_FAILED"], current_app.config["LOCKOUT_SECONDS"])
                db.session.commit()
                if locked:
                    audit("account_locked", username, "denied", actor=username)
            audit("login_failed", username[:80], "denied", actor=username[:80] or None)
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401
        next_url = _safe_next(request.args.get("next"))
        session.clear()  # fixation protection
        session.permanent = True
        session[SESSION_KEY] = {"id": user.id, "stamp": user.session_stamp}
        user.failed_logins = 0
        user.locked_until = None
        user.last_login_at = utcnow()
        db.session.commit()
        g.admin = user
        audit("login", user.username)
        return redirect(next_url or url_for("views.dashboard"))
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    if g.get("admin") is not None:
        audit("logout", g.admin.username)
    session.clear()
    flash("Signed out.", "info")
    return redirect(url_for("auth.login"))
