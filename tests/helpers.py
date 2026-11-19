"""
Test helpers shared by the test modules and tests/conftest.py (importable because pytest.ini
puts the project root and this folder's parent on sys.path; conftest adds the root too).

Every account created here is a DUMMY: example.com e-mail, public placeholder password,
fictional identity with a pre-passed background check. No phone numbers, no card numbers.
"""

from __future__ import annotations

import json
import queue
import sys
from datetime import date
from pathlib import Path

_TESTS = Path(__file__).resolve().parent
if str(_TESTS) not in sys.path:  # `from helpers import ...` works from any cwd
    sys.path.insert(0, str(_TESTS))

from clock import utcnow  # noqa: E402
from extensions import db  # noqa: E402
from models import DriverProfile, User  # noqa: E402

DUMMY_PASSWORD = "dummyTestPass123"  # DUMMY PASSWORD (public placeholder, meets PASSWORD_MIN_LENGTH)


def make_user(username: str, *, role: str = "both", password: str = DUMMY_PASSWORD, cleared: bool = True,
              package: str = "standard") -> User:
    """A user with (by default) a passed DUMMY background check. `package="driver"` may drive."""
    from background.service import seed_clear_check

    user = User(username=username, email=f"{username.replace('_', '.')}@example.com", role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    if cleared:
        seed_clear_check(user, package=package, first="Dummy", last=username.title().replace("_", " "),
                         dob=date(1990, 1, 1), licence="DUMMY-DL-9999" if package == "driver" else None,
                         region="Demo State" if package == "driver" else None)
    db.session.commit()
    return user


def make_driver(username: str, *, landmark: str = "Downtown", online: bool = True, **profile) -> DriverProfile:
    """A logged-out human driver (driver background check) parked at a demo landmark."""
    from rides import geo

    user = make_user(username, role="both", package="driver")
    lat, lng = geo.LANDMARKS[landmark]
    drv = DriverProfile(user_id=user.id, vehicle=profile.pop("vehicle", "Dummy Sedan"), plate=profile.pop("plate", "DUMMY-T01"),
                        is_online=online, lat=lat, lng=lng, location_updated_at=utcnow(), **profile)
    db.session.add(drv)
    db.session.commit()
    return drv


def login(client, username: str, password: str = DUMMY_PASSWORD):
    """Log a test client in through the real login form (CSRF is off in TestingConfig)."""
    resp = client.post("/login", data={"username": username, "password": password})
    assert resp.status_code == 302, f"login failed for {username}: {resp.status_code}"
    return resp


def logged_in_client(app, username: str, password: str = DUMMY_PASSWORD):
    c = app.test_client()
    login(c, username, password)
    return c


def subscribe(channel: str) -> queue.Queue:
    """Listen on a push channel (rides/events.py broker) like a browser's EventSource would."""
    from rides.events import broker

    return broker.subscribe(channel)


def drain(q: queue.Queue) -> list[dict]:
    """Everything published on a subscribed channel so far."""
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            return out


def json_of(resp) -> dict:
    return json.loads(resp.get_data(as_text=True))
