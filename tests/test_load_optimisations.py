"""
Guards for the performance work (see loadtest/REPORT.md): every fast path must give exactly the
answer of the code it replaces, and the SQLite writer queue must never leak its lock.
"""

import json
import multiprocessing
import os
import random
import threading
import time
from datetime import date, timedelta

import pytest

from clock import utcnow
from extensions import db
from helpers import json_of, logged_in_client, make_driver, make_user
from models import BackgroundCheck, BackgroundDispute, DriverProfile, RideOffer, RideRequest

# Platform-specific features are skipped by CAPABILITY - the same checks the app itself uses to
# decide whether to enable them - not by OS name. (Windows: no fcntl, no AF_UNIX datagram sockets;
# the app then falls back to SQLite's own locking and in-process events, which the other tests cover.)
import dbtuning  # noqa: E402
from rides import bus as event_bus  # noqa: E402

needs_writer_queue = pytest.mark.skipif(dbtuning.fcntl is None, reason="SQLite writer queue needs fcntl (POSIX)")
needs_event_bus = pytest.mark.skipif(not event_bus.available(), reason="event bus needs AF_UNIX datagram sockets (POSIX)")


# ================================================================= background-check fast paths

def _check(user, status, *, package="standard", held=False, expires_in_days=365):
    from auth import crypto

    now = utcnow()
    c = BackgroundCheck(user_id=user.id, package=package, status=status, provider="fake",
                        provider_ref=f"bgc_DUMMY_t_{user.id}_{random.random()}", legal_first_name="Dummy",
                        legal_last_name="Test", date_of_birth_enc=crypto.encrypt_secret("1990-01-01"),
                        consent_at=now, submitted_at=now, held_for_review=held,
                        completed_at=now if status != "pending" else None,
                        expires_at=(now + timedelta(days=expires_in_days)) if status == "clear" else None)
    db.session.add(c)
    db.session.flush()
    return c


STATES = {
    "no check": [],
    "pending": [("pending", "standard", False, 365)],
    "clear standard": [("clear", "standard", False, 365)],
    "clear driver": [("clear", "driver", False, 365)],
    "expired driver": [("clear", "driver", False, -1)],
    "consider": [("consider", "standard", False, 365)],
    "rejected": [("rejected", "driver", False, 365)],
    "unverified": [("unverified", "standard", False, 365)],
    "clear then newer consider": [("clear", "driver", False, 365), ("consider", "driver", False, 365)],
    "rejected then clear re-check": [("rejected", "driver", False, 365), ("clear", "driver", False, 365)],
    "clear + held dispute re-check": [("clear", "driver", False, 365), ("consider", "driver", True, 365)],
    "rejected + held clear re-check": [("rejected", "driver", False, 365), ("clear", "driver", True, 365)],
    "clear driver then pending": [("clear", "driver", False, 365), ("pending", "driver", False, 365)],
}


@pytest.mark.parametrize("required", [True, False])
def test_fast_rules_match_clearance_in_every_state(app, required):
    from background import service

    app.config["BACKGROUND_CHECK_REQUIRED"] = required
    users = {}
    for i, (name, checks) in enumerate(STATES.items()):
        u = make_user(f"dummy_state_{i}", cleared=False)
        for status, package, held, days in checks:
            _check(u, status, package=package, held=held, expires_in_days=days)
        users[name] = u
    rejected_disputed = make_user("dummy_state_disputed", cleared=False)
    c = _check(rejected_disputed, "rejected", package="driver")
    db.session.add(BackgroundDispute(user_id=rejected_disputed.id, check_id=c.id, statement="DUMMY statement " * 3))
    users["rejected + open dispute"] = rejected_disputed
    db.session.commit()
    db.session.expire_all()

    ids = [u.id for u in users.values()]
    passed, drive = service.passed_user_ids(ids), service.driving_cleared_user_ids(ids)
    for name, u in users.items():
        st = service.clearance(u)
        assert (u.id in passed) == st.passed, name
        assert (u.id in drive) == st.can_drive, name


# ================================================================= driver index

def _brute_force(lat, lng, radius, exclude=()):
    from rides import geo

    out = []
    cutoff = utcnow() - timedelta(seconds=1800)
    for d in DriverProfile.query.filter_by(is_online=True).all():
        if d.id in exclude or d.lat is None or d.location_updated_at < cutoff:
            continue
        km = geo.haversine_km(lat, lng, d.lat, d.lng)
        if km <= radius:
            out.append((round(km, 9), d.id))
    return sorted(out)


def test_index_nearest_matches_brute_force(app, fleet):
    from rides import geo
    from rides.driver_index import index

    rng = random.Random(3)
    for n in range(40):  # a denser fleet than the 8 demo bots
        d = make_driver(f"dummy_idx_{n}", landmark=rng.choice(list(geo.LANDMARKS)))
        d.lat, d.lng = geo.offset_point(d.lat, d.lng, rng.uniform(-2, 2), rng.uniform(-2, 2))
    db.session.commit()
    for _ in range(60):
        lat, lng = geo.offset_point(*geo.DEMO_CITY_CENTER, rng.uniform(-6, 6), rng.uniform(-6, 6))
        radius = rng.choice([1.5, 3.0, 10.0])
        busy = set(rng.sample([d.id for d in DriverProfile.query.all()], 5))
        expected = _brute_force(lat, lng, radius, exclude=busy)
        for limit in (0, 1, 5, 20):
            got = index.nearest(lat, lng, radius_km=radius, limit=limit, skip=lambda e: e.driver_id in busy,
                                ttl=60, stale_seconds=1800)
            want = expected if limit == 0 else expected[:limit]
            assert [(round(km, 9), e.driver_id) for km, e in got] == want


def test_index_sees_this_processs_commits_at_once(app, fleet):
    from rides import geo
    from rides.driver_index import index

    lat, lng = geo.LANDMARKS["Downtown"]

    def ids():
        return {e.driver_id for _, e in index.nearest(lat, lng, radius_km=20, limit=0, skip=lambda e: False,
                                                        ttl=3600, stale_seconds=1800)}
    before = ids()
    gone = fleet[0]
    gone.is_online = False
    db.session.commit()
    assert gone.id not in ids() and before - ids() == {gone.id}
    new = make_driver("dummy_idx_new", landmark="Downtown")
    assert new.id in ids()


def test_changes_by_other_processes_show_up_within_the_ttl_and_are_never_offered(app, fleet, rider_client):
    """Simulate another worker: change the DB without this session's hooks."""
    from sqlalchemy import text

    from rides import geo
    from rides.driver_index import index

    lat, lng = geo.LANDMARKS["Downtown"]
    index.nearest(lat, lng, radius_km=20, limit=0, skip=lambda e: False, ttl=3600, stale_seconds=1800)  # build
    victim = fleet[0]
    with db.engine.begin() as conn:  # "another process" takes the driver offline
        conn.execute(text("UPDATE driver_profile SET is_online = 0 WHERE id = :i"), {"i": victim.id})
    cached = {e.driver_id for _, e in index.nearest(lat, lng, radius_km=20, limit=0, skip=lambda e: False,
                                                     ttl=3600, stale_seconds=1800)}
    assert victim.id in cached  # still in the (TTL) cache ...
    app.config["RIDE_DRIVER_INDEX_TTL_SECONDS"] = 3600
    db.session.expire_all()
    data = json_of(rider_client.get("/api/rides/search?pickup=Downtown&dropoff=Airport"))
    assert victim.id not in [d["driver_id"] for d in data["drivers"]]  # ... but never listed: re-checked in the DB
    after = {e.driver_id for _, e in index.nearest(lat, lng, radius_km=20, limit=0, skip=lambda e: False,
                                                    ttl=0, stale_seconds=1800)}
    assert victim.id not in after  # TTL 0 / expired: rebuilt


def test_pool_limits_scoring_to_the_nearest_drivers(app, fleet, rider_client):
    url = "/api/rides/search?pickup=Downtown&dropoff=Airport"
    everyone = json_of(rider_client.get(url))["drivers"]  # pool 0: every driver within the radius
    nearest3 = {d["driver_id"] for d in sorted(everyone, key=lambda d: d["distance_km"])[:3]}
    app.config["RIDE_CANDIDATE_POOL"] = 3
    pooled = json_of(rider_client.get(url))["drivers"]
    assert {d["driver_id"] for d in pooled} == nearest3


# ================================================================= request paths

def test_post_response_equals_the_follow_up_get(rider_client, fleet):
    resp = rider_client.post("/api/rides", json={"pickup": "Downtown", "dropoff": "Airport", "payment_method_id": None})
    assert resp.status_code == 201
    created = json_of(resp)
    assert created["status"] == "offered" and created["chat"]["open"] is True
    assert json_of(rider_client.get(f"/api/rides/{created['id']}")) == created


def test_expire_all_stale_offers_only_touches_expired_rides(app, fleet):
    from rides import matching

    riders = [make_user(f"dummy_exp_{i}") for i in range(3)]
    rides = [matching.create_ride(u, "Downtown", "Airport", auto_dispatch=True, payment_method_id=None) for u in riders]
    rides[0].pending_offer.expires_at = utcnow() - timedelta(seconds=5)
    db.session.commit()
    pending_before = {r.id: r.pending_offer.id for r in rides}
    assert matching.expire_all_stale_offers() == 1
    db.session.commit()
    db.session.expire_all()
    r0 = db.session.get(RideRequest, rides[0].id)
    assert db.session.get(RideOffer, pending_before[r0.id]).status == "expired"
    assert r0.pending_offer is not None and r0.pending_offer.id != pending_before[r0.id]  # auto-dispatch moved on
    for r in rides[1:]:
        assert db.session.get(RideRequest, r.id).pending_offer.id == pending_before[r.id]  # untouched


# ================================================================= SQLite writer queue

@pytest.fixture
def file_app(tmp_path):
    from app import create_app

    # short busy timeout: a leaked writer lock makes these tests FAIL fast instead of hanging
    app = create_app("testing", {"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'wq.db'}",
                                 "SQLALCHEMY_ENGINE_OPTIONS": {"pool_size": 20, "max_overflow": 0},
                                 "SQLITE_BUSY_TIMEOUT_MS": 1000})
    app.instance_path = str(tmp_path)
    with app.app_context():
        yield app
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


def _lock_is_free(path) -> bool:
    import fcntl

    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(fd)


def test_sqlite_file_database_uses_wal_and_a_busy_timeout(file_app):
    """Every platform (Windows included): WAL + busy timeout are plain SQLite PRAGMAs."""
    from sqlalchemy import text

    assert db.session.execute(text("PRAGMA journal_mode")).scalar() == "wal"
    assert db.session.execute(text("PRAGMA busy_timeout")).scalar() == file_app.config["SQLITE_BUSY_TIMEOUT_MS"]
    make_user("dummy_wal_0")  # writes work; without the writer queue SQLite's own locking is used


@needs_writer_queue
def test_sqlite_file_database_uses_the_writer_queue(file_app):
    lock = db.engine.url.database + ".writelock"
    make_user("dummy_wq_0")
    assert os.path.exists(lock) and _lock_is_free(lock)


@needs_writer_queue
def test_writer_queue_under_concurrency_never_leaks_the_lock(file_app):
    """20 threads write at once; some transactions fail and roll back - every lock must be released."""
    from models import AuthEvent

    lock = db.engine.url.database + ".writelock"
    errors, done = [], []

    def worker(n):
        with file_app.app_context():
            try:
                for i in range(10):
                    db.session.add(AuthEvent(event="dummy_load", detail=f"{n}-{i}"))
                    if i % 5 == 4:
                        db.session.flush()
                        db.session.rollback()  # a failed request
                        continue
                    if i % 7 == 6:
                        db.session.flush()
                        raise_in_tx = True  # noqa: F841 - leave the transaction open; remove() below rolls back
                        db.session.remove()
                        continue
                    db.session.commit()
                done.append(n)
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc))
            finally:
                db.session.remove()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(20)]
    t0 = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not errors, errors[:3]
    assert len(done) == 20 and time.time() - t0 < 8, "writers waited for a lock nobody held"
    assert _lock_is_free(lock)
    # per thread: i=4,9 rolled back; i=6 abandoned -> 7 of 10 committed
    assert AuthEvent.query.filter_by(event="dummy_load").count() == 20 * 7


@needs_writer_queue
def test_second_connection_in_the_same_thread_does_not_deadlock(file_app):
    from sqlalchemy import text

    from models import AuthEvent

    db.session.add(AuthEvent(event="dummy_outer"))
    db.session.flush()  # this thread now holds the writer queue
    t0 = time.time()
    with db.engine.connect() as other:  # another connection, same thread: must not wait for itself
        other.execute(text("SELECT 1"))
    db.session.commit()
    assert time.time() - t0 < 2
    assert _lock_is_free(db.engine.url.database + ".writelock")


# ================================================================= cross-process event bus

def _child_listen(directory, channel, ready, out):
    from rides.bus import UnixBus
    from rides.events import Broker

    b = Broker()
    b.bus = UnixBus(directory, b.publish_local)
    q = b.subscribe(channel)  # binds this process's socket
    ready.set()
    try:
        out.put(q.get(timeout=10))
    except Exception as exc:  # noqa: BLE001
        out.put({"error": repr(exc)})


@needs_event_bus
def test_event_bus_delivers_to_another_process(tmp_path):
    from rides.bus import UnixBus
    from rides.events import Broker

    ctx = multiprocessing.get_context("spawn")
    ready, out = ctx.Event(), ctx.Queue()
    child = ctx.Process(target=_child_listen, args=(str(tmp_path), "user:7", ready, out))
    child.start()
    try:
        assert ready.wait(20)
        me = Broker()
        me.bus = UnixBus(str(tmp_path), me.publish_local)
        local = me.subscribe("user:7")
        deadline = time.time() + 5
        while not [n for n in os.listdir(tmp_path) if n.endswith(".sock") and not n.startswith(f"{os.getpid()}-")]:
            assert time.time() < deadline
            time.sleep(0.05)
        me.publish("user:7", {"event": "chat", "body": "DUMMY hello"})
        assert local.get(timeout=2)["body"] == "DUMMY hello"  # local subscribers still get it
        assert out.get(timeout=10) == {"event": "chat", "body": "DUMMY hello"}  # ... and the other process
    finally:
        child.join(10)
        if child.is_alive():
            child.kill()


@needs_event_bus
def test_event_bus_removes_sockets_of_dead_processes(tmp_path):
    import socket

    from rides.bus import UnixBus

    dead = tmp_path / "999999-dead.sock"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(str(dead))
    s.close()  # bound file left behind, nobody listening
    UnixBus(str(tmp_path), lambda c, p: None).send("x", {"event": "ping"})
    assert not dead.exists()


@needs_event_bus
def test_event_bus_sockets_are_private_to_the_app_user(tmp_path):
    import stat

    from rides.bus import UnixBus

    d = tmp_path / "bus"
    d.mkdir(mode=0o777)
    os.chmod(d, 0o777)  # too open: the bus must tighten it
    bus = UnixBus(str(d), lambda c, p: None)
    bus.ensure_listening()
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    socks = [n for n in os.listdir(d) if n.endswith(".sock")]
    assert socks and all(stat.S_IMODE(os.stat(d / n).st_mode) & 0o077 == 0 for n in socks)
