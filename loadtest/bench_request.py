#!/usr/bin/env python3
"""
Per-request CPU cost of the ride-request API, measured in-process (Flask test client, no network),
on a copy of the seeded load-test database with every driver online.

    python loadtest/bench_request.py                 # 200 sequential POST /api/rides + GET /api/rides/<id>
    python loadtest/bench_request.py --profile       # + cProfile of the POSTs (top functions)
    python loadtest/bench_request.py --queries       # + SQL statements per request

A cheap way to see the effect of a code change before running the full load test (run.py).
"""

from __future__ import annotations

import argparse
import cProfile
import io
import os
import pstats
import random
import shutil
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-db", default="instance/loadtest.db")
    ap.add_argument("-n", type=int, default=200)
    ap.add_argument("--profile", action="store_true")
    ap.add_argument("--queries", action="store_true")
    ap.add_argument("--env", action="append", default=[], help="KEY=VALUE config override")
    ap.add_argument("--repeat", type=int, default=3, help="report the best of N passes (VM CPU steal makes single passes noisy)")
    args = ap.parse_args()

    work = ROOT / "instance" / "bench_request.db"
    for suffix in ("", "-wal", "-shm"):
        Path(str(work) + suffix).unlink(missing_ok=True)
    shutil.copy(ROOT / args.seed_db, work)
    os.environ.update({"DATABASE_URL": f"sqlite:///{work}", "SEED_DEMO_DATA": "false", "DEBUG": "false",
                       "RIDE_SWEEP_INTERVAL_SECONDS": "0"})
    os.environ.update(dict(kv.split("=", 1) for kv in args.env))
    import logging

    logging.disable(logging.INFO)
    from app import create_app
    from clock import utcnow
    from extensions import db
    from models import DriverProfile

    app = create_app("development")
    app.config.update(CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
    from extensions import login_manager

    login_manager.session_protection = None  # planted sessions below carry no IP / user-agent fingerprint
    with app.app_context():
        DriverProfile.query.update({"is_online": True, "location_updated_at": utcnow()})
        db.session.commit()

    # Log riders in by planting a session (the scrypt login is measured by run.py, not here).
    from models import User

    clients = []
    with app.app_context():
        users = User.query.filter(User.username.like("dummy_lt_rider_%")).order_by(User.id).limit(args.n + 5).all()
        idents = [u.get_id() for u in users]
    for ident in idents:
        c = app.test_client()
        with c.session_transaction() as s:
            s["_user_id"] = ident
            s["_fresh"] = True
        clients.append(c)

    rng = random.Random(5)

    def point():
        return f"{40 + rng.uniform(-.055, .055):.5f}, {-75 + rng.uniform(-.055, .055):.5f}"

    # CPU time of this process, not wall time: on a VM the wall clock includes CPU "steal" by
    # other tenants, which makes wall-clock micro-benchmarks noisy.
    clock = time.process_time

    def one(c):
        t0 = clock()
        r = c.post("/api/rides", json={"pickup": point(), "dropoff": point(), "auto_dispatch": True, "payment_method_id": None})
        t1 = clock()
        assert r.status_code == 201, r.get_data(as_text=True)[:300]
        g = c.get(f"/api/rides/{r.get_json()['id']}")
        assert g.status_code == 200
        return (t1 - t0) * 1000, (clock() - t1) * 1000

    counts = []
    if args.queries:
        from sqlalchemy import event

        with app.app_context():
            engine = db.engine
        state = {"n": 0}
        event.listen(engine, "before_cursor_execute", lambda *a, **k: state.__setitem__("n", state["n"] + 1))

    for c in clients[:5]:  # warm-up
        one(c)
    prof = cProfile.Profile() if args.profile else None
    passes = []
    per_pass = max(1, args.n // max(1, args.repeat))
    for rep in range(max(1, args.repeat)):
        post, get = [], []
        # each pass uses its own riders (a rider can have one active ride)
        for c in clients[5 + rep * per_pass: 5 + (rep + 1) * per_pass]:
            if args.queries:
                state["n"] = 0
            if prof:
                prof.enable()
            p, g = one(c)
            if prof:
                prof.disable()
            post.append(p)
            get.append(g)
            if args.queries:
                counts.append(state["n"])
        passes.append((statistics.mean(post) + statistics.mean(get), post, get))
    _, post, get = min(passes, key=lambda x: x[0])
    q = lambda v, p: sorted(v)[int(len(v) * p / 100)]  # noqa: E731
    print(f"CPU time per request (ms), best of {len(passes)} passes x {per_pass} requests")
    print(f"POST /api/rides      mean {statistics.mean(post):6.2f} ms  p50 {q(post, 50):6.2f}  p95 {q(post, 95):6.2f}")
    print(f"GET  /api/rides/<id> mean {statistics.mean(get):6.2f} ms  p50 {q(get, 50):6.2f}  p95 {q(get, 95):6.2f}")
    if counts:
        print(f"SQL statements per POST+GET: mean {statistics.mean(counts):.1f}")
    if prof:
        s = io.StringIO()
        pstats.Stats(prof, stream=s).sort_stats("cumulative").print_stats(35)
        print(s.getvalue())
    return 0


if __name__ == "__main__":
    sys.exit(main())
