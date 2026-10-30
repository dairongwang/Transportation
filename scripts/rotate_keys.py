#!/usr/bin/env python3
"""
Rotate MFA_ENCRYPTION_KEY without locking anyone out.

  1. Generate a new key:
        python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
  2. In .env set  MFA_ENCRYPTION_KEY=<new>  and  MFA_ENCRYPTION_KEY_PREVIOUS=<old>[,<older>...]
  3. Run:        python scripts/rotate_keys.py
     -> every stored authenticator secret is re-encrypted under the new key.
  4. Keep MFA_ENCRYPTION_KEY_PREVIOUS for up to TRUSTED_DEVICE_DAYS (default 30): recovery
     codes and remembered-device tokens are one-way hashes that are verified against
     previous keys and re-keyed on use (devices) or replaced when regenerated (codes).
     After that window remove the previous key.

Rotating SECRET_KEY needs no script: it only signs sessions/CSRF tokens (users are logged out).
Run with --dry-run to see what would change.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def rotate(app, dry_run: bool = False) -> dict:
    from auth import crypto
    from extensions import db
    from models import User

    stats = {"users_with_totp": 0, "reencrypted": 0, "already_current": 0, "undecryptable": 0}
    with app.app_context():
        for user in User.query.filter(User.totp_secret_enc.isnot(None)).all():
            stats["users_with_totp"] += 1
            if not crypto.needs_reencryption(user.totp_secret_enc):
                if crypto.decrypt_secret(user.totp_secret_enc) is None:
                    stats["undecryptable"] += 1
                else:
                    stats["already_current"] += 1
                continue
            plaintext = crypto.decrypt_secret(user.totp_secret_enc)
            if not dry_run:
                user.totp_secret_enc = crypto.encrypt_secret(plaintext)
            stats["reencrypted"] += 1
        if not dry_run:
            db.session.commit()
    return stats


def main() -> int:
    from app import create_app

    dry = "--dry-run" in sys.argv
    app = create_app()
    prev = app.config.get("MFA_ENCRYPTION_KEY_PREVIOUS") or []
    print(f"Current key: set   Previous keys configured: {len(prev)}   Backend: "
          + ("cryptography/Fernet" if __import__('auth.crypto', fromlist=['x']).HAVE_CRYPTOGRAPHY else "stdlib fallback"))
    if not prev:
        print("WARNING: MFA_ENCRYPTION_KEY_PREVIOUS is empty - nothing encrypted under an old key can be read.")
    stats = rotate(app, dry_run=dry)
    for k, v in stats.items():
        print(f"  {k:18} {v}")
    if stats["undecryptable"]:
        print("Some secrets could not be decrypted with any configured key; affected users must re-enrol their authenticator.")
        return 1
    print("Dry run - nothing written." if dry else "Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
