"""
Lightweight, idempotent schema upgrade for existing SQLite databases.

The original app used `db.create_all()` which never alters existing tables.
This adds the new 2FA columns to `user` and creates the new tables, so an
existing `instance/uber_services.db` keeps working. For anything beyond a
demo, switch to Alembic / Flask-Migrate (see SECURITY_REVIEW.md).
"""

import logging

from sqlalchemy import inspect, text

from extensions import db

log = logging.getLogger("migrations")

# column name -> DDL fragment
USER_COLUMNS = {
    "email_verified": "BOOLEAN NOT NULL DEFAULT 0",
    "phone": "VARCHAR(20)",
    "phone_verified": "BOOLEAN NOT NULL DEFAULT 0",
    "totp_enabled": "BOOLEAN NOT NULL DEFAULT 0",
    "totp_secret_enc": "VARCHAR(255)",
    "totp_last_counter": "INTEGER",
    "email_2fa_enabled": "BOOLEAN NOT NULL DEFAULT 0",
    "sms_2fa_enabled": "BOOLEAN NOT NULL DEFAULT 0",
    "preferred_2fa_method": "VARCHAR(10)",
    "failed_login_attempts": "INTEGER NOT NULL DEFAULT 0",
    "locked_until": "DATETIME",
    "last_login_at": "DATETIME",
    "password_changed_at": "DATETIME",
    "password_is_usable": "BOOLEAN NOT NULL DEFAULT 1",
    "display_name": "VARCHAR(120)",
}


def upgrade() -> None:
    db.create_all()  # creates brand-new tables (one_time_code, recovery_code, ...)
    inspector = inspect(db.engine)
    existing = {c["name"] for c in inspector.get_columns("user")}
    with db.engine.begin() as conn:
        for name, ddl in USER_COLUMNS.items():
            if name not in existing:
                log.info("Adding column user.%s", name)
                conn.execute(text(f"ALTER TABLE user ADD COLUMN {name} {ddl}"))
        # Indexes added after a table already existed (create_all never alters tables).
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_auth_event_ip_event_time "
            "ON auth_event (ip_address, event, created_at)"
        ))
