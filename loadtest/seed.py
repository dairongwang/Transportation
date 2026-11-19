#!/usr/bin/env python3
"""
Seed a SEPARATE load-test database with DUMMY riders and drivers.

    python loadtest/seed.py                       # 1000 riders + 1000 drivers -> instance/loadtest.db
    python loadtest/seed.py --riders 50 --drivers 50 --db instance/lt_small.db

Every account is a DUMMY: username dummy_lt_rider_N / dummy_lt_driver_N, an example.com e-mail,
the public password below, a fictional identity with a pre-passed background check (drivers:
driver package with a fake DUMMY-LT-... licence). Drivers get a profile and start OFFLINE at a
random point of the demo city - the load test logs them in and puts them online through the API.
No card numbers, no phone numbers. Never touches instance/uber_services.db.

To keep seeding fast, all accounts share ONE password hash (computed once with the app's normal
scrypt settings). Every login still runs the full scrypt verification.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PASSWORD = "dummyLoadPass123"  # DUMMY PASSWORD (public placeholder)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--riders", type=int, default=1000)
    ap.add_argument("--drivers", type=int, default=1000)
    ap.add_argument("--db", default="instance/loadtest.db", help="SQLite file (relative to the project folder)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--drivers-online", action="store_true",
                    help="start drivers ONLINE (quick ride-only iterations without driver logins)")
    args = ap.parse_args()

    db_path = (ROOT / args.db).resolve()
    if db_path.name == "uber_services.db":
        print("Refusing to seed the main development database.")
        return 1
    db_path.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["SEED_DEMO_DATA"] = "false"
    os.environ.setdefault("RIDE_SWEEP_INTERVAL_SECONDS", "0")

    from werkzeug.security import generate_password_hash

    from app import create_app
    from auth import crypto
    from clock import utcnow
    from extensions import db
    from models import BACKGROUND_CHECK_SCREENS, BackgroundCheck, DriverProfile, User
    from rides import geo

    app = create_app("development")
    rng = random.Random(args.seed)
    started = time.time()
    with app.app_context():
        pw_hash = generate_password_hash(PASSWORD)
        now = utcnow()
        dob_enc = crypto.encrypt_secret(date(1990, 1, 1).isoformat())
        import json

        def check_for(user_id: int, package: str, n: int) -> BackgroundCheck:
            c = BackgroundCheck(
                user_id=user_id, package=package, status="clear", provider="fake",
                provider_ref=f"bgc_DUMMY_lt_{package}_{n}", legal_first_name="Dummy",
                legal_last_name=f"Loadtest {'Driver' if package == 'driver' else 'Rider'}",
                date_of_birth_enc=dob_enc, consent_at=now, submitted_at=now, completed_at=now,
                result_note="DUMMY load-test account - seeded as clear.",
                screens_json=json.dumps({s: "clear" for s in BACKGROUND_CHECK_SCREENS[package]}),
            )
            if package == "driver":
                c.licence_number = f"DUMMY-LT-{n:05d}"
                c.licence_region = "Demo State"
            return c

        users = []
        for i in range(1, args.riders + 1):
            users.append(User(username=f"dummy_lt_rider_{i}", email=f"dummy.lt.rider{i}@example.com", role="buyer",
                              password_hash=pw_hash, password_changed_at=now, created_at=now))
        for i in range(1, args.drivers + 1):
            users.append(User(username=f"dummy_lt_driver_{i}", email=f"dummy.lt.driver{i}@example.com", role="seller",
                              password_hash=pw_hash, password_changed_at=now, created_at=now))
        db.session.add_all(users)
        db.session.flush()
        clat, clng = geo.DEMO_CITY_CENTER
        for n, u in enumerate(users, 1):
            is_driver = u.role == "seller"
            db.session.add(check_for(u.id, "driver" if is_driver else "standard", n))
            if is_driver:
                r = geo.DEMO_CITY_RADIUS_KM
                lat, lng = geo.offset_point(clat, clng, rng.uniform(-r, r), rng.uniform(-r, r))
                db.session.add(DriverProfile(
                    user_id=u.id, vehicle=rng.choice(["Dummy Sedan", "Dummy Hatchback", "Dummy SUV", "Dummy Van"]),
                    plate=f"DUMMY-L{n:04d}", base_fare=round(rng.uniform(2, 5), 2), per_km_rate=round(rng.uniform(0.9, 2.0), 2),
                    per_min_rate=round(rng.uniform(0.2, 0.45), 2), min_fare=5.0, is_online=args.drivers_online, lat=lat, lng=lng,
                    location_updated_at=now, rating_sum=0.0, rating_count=0, offers_received=0, offers_accepted=0))
        db.session.commit()
        print(f"Seeded {args.riders} riders + {args.drivers} drivers into {db_path} in {time.time() - started:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
