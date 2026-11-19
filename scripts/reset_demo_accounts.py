#!/usr/bin/env python3
"""
Restore the DUMMY demo accounts (dummy_buyer, dummy_seller, dummy_driver_1..8) after you have
played with them - development only.

    python scripts/reset_demo_accounts.py            # do it
    python scripts/reset_demo_accounts.py --dry-run  # only show what would change

For every demo account that is not currently allowed in, it:
  * adds a fresh passed (DUMMY) background check - rejected / flagged / expired / disputed
    accounts become usable again; open disputes of those accounts are closed;
  * unlocks the account (failed logins / lockout);
and it gives dummy_buyer its DUMMY test card again if it has none, and puts the driver bots back
online with fresh positions. Other (self-registered) accounts are never touched. Refuses to run
with APP_ENV=production or SEED_DEMO_DATA=false.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
os.environ.setdefault("RIDE_SWEEP_INTERVAL_SECONDS", "0")  # no background thread for a one-shot script


def main() -> int:
    dry = "--dry-run" in sys.argv
    if os.environ.get("APP_ENV", "development").lower() == "production":
        sys.exit("Refusing to run with APP_ENV=production.")
    from app import DEMO_IDENTITIES, create_app, seed_demo_payment_methods
    from background import service as bgc
    from clock import utcnow
    from extensions import db
    from models import User
    from rides import simulator
    from rides.simulator import BOT_PREFIX

    app = create_app()
    if not app.config.get("SEED_DEMO_DATA"):
        sys.exit("SEED_DEMO_DATA is off - there are no demo accounts to reset.")
    with app.app_context():
        users = User.query.filter(User.username.in_(list(DEMO_IDENTITIES)) | User.username.like(f"{BOT_PREFIX}%")).all()
        changed = 0
        for user in users:
            st = bgc.clearance(user)
            notes = []
            if not st.passed:
                notes.append(f"background check {st.state} -> clear")
                if not dry:
                    from datetime import date

                    if user.username.startswith(BOT_PREFIX):
                        n = user.username[len(BOT_PREFIX):]
                        bgc.seed_clear_check(user, package="driver", first="Dummy", last=f"Driver {n}", dob=date(1985, 1, 1),
                                             licence=f"DUMMY-DL-{int(n):04d}" if n.isdigit() else "DUMMY-DL-0000",
                                             region="Demo State")
                    else:
                        first, last = DEMO_IDENTITIES[user.username]
                        bgc.seed_clear_check(user, package="standard", first=first, last=last, dob=date(1990, 1, 1))
                    for d in user.background_disputes:
                        if d.is_open:
                            d.status, d.decided_by, d.decided_at = "approved", "reset_demo_accounts", utcnow()
                            d.decision_note = "Closed by scripts/reset_demo_accounts.py (DUMMY demo account)."
            if user.is_locked or user.failed_login_attempts:
                notes.append("unlocked")
                if not dry:
                    user.reset_login_failures()
            if notes:
                changed += 1
                print(f"  {user.username:18} {', '.join(notes)}")
        if not dry:
            db.session.commit()
            seed_demo_payment_methods()  # dummy_buyer's DUMMY test card, if it has none
            simulator.shuffle_fleet()    # bots online with fresh positions
        print(f"Would reset {changed} demo account(s)." if dry else f"Reset {changed} demo account(s); bots back online.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
