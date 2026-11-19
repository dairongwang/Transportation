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


# table -> {column name -> DDL fragment} for columns added after the table first shipped
TABLE_COLUMNS = {
    "user": USER_COLUMNS,
    "payment_method": {
        "verified_at": "DATETIME",
        "verification_ref": "VARCHAR(120)",
        "fingerprint": "VARCHAR(64)",
    },
    "ride_request": {
        "payment_method_id": "INTEGER REFERENCES payment_method(id)",
        "payment_status": "VARCHAR(12)",
        "preauth_amount": "FLOAT",
        "preauth_ref": "VARCHAR(120)",
        "preauth_status": "VARCHAR(12)",
        "preauth_at": "DATETIME",
        "selected_offer_id": "INTEGER",
    },
    "payment_transaction": {
        "kind": "VARCHAR(14)",
        "refund_of_id": "INTEGER REFERENCES payment_transaction(id)",
        "refund_reason": "VARCHAR(300)",
        "created_by": "VARCHAR(80)",
    },
    "background_check": {
        "adjudicated_by": "VARCHAR(80)",
        "held_for_review": "BOOLEAN NOT NULL DEFAULT 0",
    },
}


def upgrade() -> None:
    db.create_all()  # creates brand-new tables (one_time_code, recovery_code, payment_method, ...)
    inspector = inspect(db.engine)
    with db.engine.begin() as conn:
        for table, columns in TABLE_COLUMNS.items():
            existing = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    log.info("Adding column %s.%s", table, name)
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
        _encrypt_legacy_payment_tokens(conn)
        _backfill_transaction_kinds(conn)
        _mask_legacy_wallet_emails(conn)
        # Indexes added after a table already existed (create_all never alters tables).
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_auth_event_ip_event_time "
            "ON auth_event (ip_address, event, created_at)"
        ))


LEGACY_TOKEN_PREFIXES = ("tok_DUMMY_", "pm_DUMMY_", "BA-DUMMY_", "card_DUMMY.", "pm_DUMMY.", "BA-DUMMY.")


def _encrypt_legacy_payment_tokens(conn) -> None:
    """
    Earlier builds stored the payment token in clear text. Encrypt such rows in place so a
    database dump no longer reveals token ids. (Tokens from the pre-vault format are also
    re-validated lazily: they fail signature checks and show up as 'unverified'.)
    """
    from auth import crypto

    rows = conn.execute(text("SELECT id, provider_token FROM payment_method")).fetchall()
    for row_id, value in rows:
        if value and value.startswith(LEGACY_TOKEN_PREFIXES):
            log.info("Encrypting legacy payment token of payment_method.id=%s", row_id)
            conn.execute(text("UPDATE payment_method SET provider_token = :v WHERE id = :id"),
                         {"v": crypto.encrypt_secret(value), "id": row_id})


def _mask_legacy_wallet_emails(conn) -> None:
    """Earlier builds stored the wallet's full e-mail; keep only the masked form."""
    from payments.vault import mask_email

    rows = conn.execute(text("SELECT id, account_email FROM payment_method WHERE account_email IS NOT NULL")).fetchall()
    for row_id, value in rows:
        if value and "@" in value and "•" not in value:
            log.info("Masking legacy wallet e-mail of payment_method.id=%s", row_id)
            conn.execute(text("UPDATE payment_method SET account_email = :v WHERE id = :id"),
                         {"v": mask_email(value), "id": row_id})


def _backfill_transaction_kinds(conn) -> None:
    """Rows written before `kind` existed: classify them the way the code that created them did."""
    n = conn.execute(text("""
        UPDATE payment_transaction SET kind = CASE
            WHEN status IN ('held', 'captured', 'released') OR description LIKE 'Pre-authorisation%' THEN 'hold'
            WHEN ride_id IS NULL THEN 'verification'
            ELSE 'charge' END
        WHERE kind IS NULL""")).rowcount
    if n:
        log.info("Classified %s existing payment transaction(s)", n)
