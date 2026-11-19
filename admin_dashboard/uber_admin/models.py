"""The dashboard's OWN data: its operators (managers / viewers) and its audit log."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db

ROLES = ("manager", "viewer")  # manager: decides; viewer: read-only


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AdminUser(db.Model):
    __tablename__ = "admin_user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    display_name = db.Column(db.String(120), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="viewer")
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = utcnow()

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def can_decide(self) -> bool:
        return self.role == "manager" and self.is_active

    @property
    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > utcnow())

    def register_failure(self, max_failed: int, lockout_seconds: int) -> bool:
        self.failed_logins += 1
        if self.failed_logins >= max_failed:
            self.failed_logins = 0
            self.locked_until = utcnow() + timedelta(seconds=lockout_seconds)
            return True
        return False

    @property
    def session_stamp(self) -> str:
        """Changes with the password: older sessions stop working."""
        return f"{self.id}:{int(self.password_changed_at.timestamp() * 1_000_000)}"


class AuditEntry(db.Model):
    """Who did what in the dashboard (decisions, sign-ins). Kept independently of the main app's log."""

    __tablename__ = "audit_entry"

    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(80), nullable=True, index=True)
    action = db.Column(db.String(60), nullable=False)
    target = db.Column(db.String(80), nullable=True)
    outcome = db.Column(db.String(10), nullable=False, default="ok")  # ok | error | denied
    detail = db.Column(db.String(500), nullable=True)
    ip = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
