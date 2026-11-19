#!/usr/bin/env python3
"""
Load test: login burst of riders + drivers, then bursts of concurrent ride requests.

    python loadtest/seed.py                                   # once: 1000 riders + 1000 drivers
    python loadtest/run.py                                    # starts gunicorn on a COPY of the seeded DB
    python loadtest/run.py --workers 3 --label tuned --json loadtest/results/tuned.json
    python loadtest/run.py --base http://127.0.0.1:8000       # against a server you started yourself

Scenario (defaults)
  phase "login"   2000 users (1000 riders + 1000 drivers, shuffled) arrive uniformly over
                  --login-window seconds. Each does what a browser does:
                      GET /login -> POST /login (302) -> GET /dashboard
                  and every driver then goes online with its position:
                      POST /api/drivers/me/location
  phase "rides"   --rounds rounds; in each, --concurrency DIFFERENT logged-in riders are released
                  at the same instant (barrier; or evenly over --ride-window seconds) and send
                      POST /api/rides   (auto-dispatch, cash, random pickup / drop-off in the city)
                  then fetch their ride like the ride page does:  GET /api/rides/<id>

Every virtual user has its own cookie jar and its own client IP (X-Forwarded-For; the server runs
with BEHIND_PROXY=1), so CSRF, sessions, the per-IP login rate limits and the background-check gate
are all exercised exactly as with real browsers.

Measured: latency per endpoint (p50/p90/p95/p99/max), throughput, errors, and - sampled every
--sample seconds with psutil - CPU and memory of the server processes (gunicorn master + workers)
and of this load generator (it shares the machine: reported separately).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import shutil
import signal
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp
import psutil

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "dummyLoadPass123"  # DUMMY PASSWORD (matches loadtest/seed.py)
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
CITY = (40.0, -75.0)  # rides/geo.py DEMO_CITY_CENTER
CITY_DEG = 0.055  # ~6 km around the centre


# ================================================================= measurements

@dataclass
class Sample:
    t: float
    server_cpu: float  # % of ONE core, summed over server processes
    server_rss_mb: float
    loadgen_cpu: float
    system_cpu: float  # % of the whole machine
    workers: int
    steal: float = 0.0  # % of CPU time taken by the hypervisor for other tenants (VMs)


@dataclass
class Recorder:
    calls: list = field(default_factory=list)  # (phase, name, start, latency_ms, ok, status)
    samples: list = field(default_factory=list)
    phases: dict = field(default_factory=dict)  # phase -> [start, end]
    errors: list = field(default_factory=list)  # first few failures, for diagnosis
    outcomes: dict = field(default_factory=dict)  # ride status returned by POST /api/rides

    def add(self, phase, name, start, latency_ms, ok, status):
        self.calls.append((phase, name, start, latency_ms, ok, status))


def pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


class Monitor(threading.Thread):
    """Samples CPU / RSS of the server process tree and of this process."""

    def __init__(self, rec: Recorder, server_pid: int | None, interval: float):
        super().__init__(daemon=True)
        self.rec, self.interval, self.stop = rec, interval, threading.Event()
        self.server = psutil.Process(server_pid) if server_pid else None
        self.me = psutil.Process(os.getpid())
        self._known: dict[int, psutil.Process] = {}

    def _server_procs(self):
        if self.server is None:
            return []
        try:
            procs = [self.server] + self.server.children(recursive=True)
        except psutil.NoSuchProcess:
            return []
        out = []
        for p in procs:
            if p.pid not in self._known:
                self._known[p.pid] = p
                try:
                    p.cpu_percent(None)  # prime
                except psutil.Error:
                    pass
            out.append(self._known[p.pid])
        return out

    def run(self):
        self.me.cpu_percent(None)
        psutil.cpu_times_percent(None)
        self._server_procs()
        while not self.stop.wait(self.interval):
            cpu = rss = 0.0
            procs = self._server_procs()
            for p in procs:
                try:
                    cpu += p.cpu_percent(None)
                    rss += p.memory_info().rss
                except psutil.Error:
                    pass
            times = psutil.cpu_times_percent(None)
            self.rec.samples.append(Sample(time.time(), cpu, rss / 2**20, self.me.cpu_percent(None),
                                           100.0 - times.idle - getattr(times, "steal", 0.0), max(0, len(procs) - 1),
                                           getattr(times, "steal", 0.0)))


# ================================================================= virtual users

class User:
    def __init__(self, name: str, is_driver: bool, ip: str, base: str, timeout: float):
        self.name, self.is_driver, self.ip, self.base = name, is_driver, ip, base
        self.csrf: str | None = None
        self.session = aiohttp.ClientSession(
            cookie_jar=aiohttp.CookieJar(unsafe=True),  # cookies for an IP host
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"X-Forwarded-For": ip, "User-Agent": f"serviceuber-loadtest/{name}"},
            connector=aiohttp.TCPConnector(limit=0, keepalive_timeout=1.0),  # < gunicorn keepalive (2 s): no stale reuse
        )

    async def call(self, rec: Recorder, phase: str, name: str, method: str, path: str, expect: int, **kw):
        start = time.time()
        t0 = time.perf_counter()
        status, text, headers = None, "", {}
        try:
            async with self.session.request(method, self.base + path, allow_redirects=False, **kw) as resp:
                status = resp.status
                text = await resp.text()
                headers = resp.headers
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            text = f"{type(exc).__name__}: {exc}"
            status = type(exc).__name__  # reported in place of an HTTP status
        ms = (time.perf_counter() - t0) * 1000
        rec.add(phase, name, start, ms, status == expect, status)
        if status != expect and len(rec.errors) < 20:
            rec.errors.append(f"{phase} {name} -> {status}: {text[:160]!r}")
        m = CSRF_RE.search(text)
        if m:
            self.csrf = m.group(1)
        return status, text, headers

    async def close(self):
        await self.session.close()


def rand_point(rng: random.Random) -> str:
    return f"{CITY[0] + rng.uniform(-CITY_DEG, CITY_DEG):.5f}, {CITY[1] + rng.uniform(-CITY_DEG, CITY_DEG):.5f}"


async def login_flow(u: User, rec: Recorder, rng: random.Random) -> bool:
    st, _, _ = await u.call(rec, "login", "GET /login", "GET", "/login", 200)
    if st != 200:
        return False
    st, _, hdr = await u.call(rec, "login", "POST /login", "POST", "/login", 302,
                              data={"username": u.name, "password": PASSWORD, "csrf_token": u.csrf or ""})
    if st != 302 or "/dashboard" not in hdr.get("Location", ""):
        return False
    st, _, _ = await u.call(rec, "login", "GET /dashboard", "GET", "/dashboard", 200)
    if st != 200:
        return False
    if u.is_driver:
        lat, lng = (float(x) for x in rand_point(rng).split(","))
        st, _, _ = await u.call(rec, "login", "POST /api/drivers/me/location", "POST", "/api/drivers/me/location", 200,
                                json={"lat": lat, "lng": lng, "online": True}, headers={"X-CSRF-Token": u.csrf or ""})
        return st == 200
    return True


async def ride_flow(u: User, rec: Recorder, rng: random.Random, gate: asyncio.Event, phase: str,
                    delay: float = 0.0) -> None:
    body = {"pickup": rand_point(rng), "dropoff": rand_point(rng), "auto_dispatch": True, "payment_method_id": None}
    headers = {"X-CSRF-Token": u.csrf or ""}
    await gate.wait()
    if delay:
        await asyncio.sleep(delay)  # --ride-window: arrivals spread evenly instead of all at once
    st, text, _ = await u.call(rec, phase, "POST /api/rides", "POST", "/api/rides", 201, json=body, headers=headers)
    if st == 201:
        ride = json.loads(text)
        rec.outcomes[ride["status"]] = rec.outcomes.get(ride["status"], 0) + 1  # offered / no_drivers / ...
        ride_id = ride["id"]
        await u.call(rec, phase, "GET /api/rides/<id>", "GET", f"/api/rides/{ride_id}", 200)


# ================================================================= orchestration

def start_server(args) -> subprocess.Popen:
    db = ROOT / "instance" / "loadtest_run.db"
    for suffix in ("", "-wal", "-shm"):
        Path(str(db) + suffix).unlink(missing_ok=True)
    shutil.copy(ROOT / args.seed_db, db)
    if args.drivers == 0:
        # Ride-only run: the drivers do not log in, so give the seeded ones a FRESH position (a
        # position older than DRIVER_LOCATION_STALE_SECONDS is ignored - every ride would find
        # no driver and the test would measure the wrong, cheap code path).
        import sqlite3
        from datetime import datetime, timezone

        con = sqlite3.connect(db)
        con.execute("UPDATE driver_profile SET is_online = 1, location_updated_at = ?",
                    (datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" "),))
        con.commit()
        con.close()
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{db}", "APP_ENV": "development", "DEBUG": "false",
           "SEED_DEMO_DATA": "false", "BEHIND_PROXY": "1", "EMAIL_BACKEND": "memory", "SMS_BACKEND": "memory",
           **dict(kv.split("=", 1) for kv in args.env)}
    cmd = [sys.executable, "-m", "gunicorn", "wsgi:app", "-b", f"127.0.0.1:{args.port}", "-w", str(args.workers),
           "-k", args.worker_class, "--threads", str(args.threads), "--backlog", "4096", "--timeout", "120",
           "--log-level", "warning"]
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=open(ROOT / "instance" / "loadtest_server.log", "w"),
                            stderr=subprocess.STDOUT, start_new_session=True)
    deadline = time.time() + 60
    import urllib.request

    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{args.port}/healthz", timeout=2)
            time.sleep(1.5)  # let every worker finish booting
            return proc
        except OSError:
            time.sleep(0.3)
    proc.kill()
    raise SystemExit("server did not start - see instance/loadtest_server.log")


async def scenario(args, rec: Recorder) -> dict:
    rng = random.Random(args.seed)
    riders = [f"dummy_lt_rider_{i}" for i in range(1, args.riders + 1)]
    drivers = [f"dummy_lt_driver_{i}" for i in range(1, args.drivers + 1)]
    people = [(n, False) for n in riders] + [(n, True) for n in drivers]
    rng.shuffle(people)
    users = [User(n, d, f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}", args.base, args.timeout)
             for i, (n, d) in enumerate(people, start=1)]
    info = {}

    # ---------------- phase 1: login burst
    rec.phases["login"] = [time.time(), None]
    t0 = time.perf_counter()
    spacing = args.login_window / max(1, len(users))

    async def arrive(i, u):
        await asyncio.sleep(max(0.0, t0 + i * spacing - time.perf_counter()))
        return await login_flow(u, rec, rng)

    results = await asyncio.gather(*(arrive(i, u) for i, u in enumerate(users)))
    rec.phases["login"][1] = time.time()
    logged_in = [u for u, ok in zip(users, results) if ok]
    info["login_ok"], info["login_total"] = len(logged_in), len(users)
    info["login_phase_seconds"] = rec.phases["login"][1] - rec.phases["login"][0]
    print(f"  login phase: {len(logged_in)}/{len(users)} users in {info['login_phase_seconds']:.1f}s", flush=True)

    # ---------------- phase 2: concurrent ride-request bursts
    await asyncio.sleep(args.pause)
    ready_riders = [u for u in logged_in if not u.is_driver]
    rng.shuffle(ready_riders)
    for r in range(1, args.rounds + 1):
        batch = ready_riders[(r - 1) * args.concurrency: r * args.concurrency]
        if len(batch) < args.concurrency:
            print(f"  not enough logged-in riders for round {r}")
            break
        phase = f"rides#{r}"
        gate = asyncio.Event()
        spacing = args.ride_window / len(batch) if args.ride_window > 0 else 0.0
        tasks = [asyncio.create_task(ride_flow(u, rec, rng, gate, phase, i * spacing)) for i, u in enumerate(batch)]
        await asyncio.sleep(0.5)  # every task is parked at the barrier
        rec.phases[phase] = [time.time(), None]
        gate.set()
        await asyncio.gather(*tasks)
        rec.phases[phase][1] = time.time()
        rides = [c for c in rec.calls if c[0] == phase and c[1] == "POST /api/rides"]
        print(f"  {phase}: {sum(c[4] for c in rides)}/{len(rides)} ok, p95 {pct([c[3] for c in rides], 95):.0f} ms, "
              f"burst drained in {rec.phases[phase][1] - rec.phases[phase][0]:.2f}s", flush=True)
        await asyncio.sleep(args.pause)

    await asyncio.gather(*(u.close() for u in users))
    return info


def summarise(rec: Recorder, info: dict, args) -> dict:
    out = {"label": args.label, "config": {k: v for k, v in vars(args).items() if k not in ("json",)}, "info": info,
           "cpus": psutil.cpu_count(), "endpoints": {}, "phases": {}}

    def window(start, end):
        s = [x for x in rec.samples if start <= x.t <= end + args.sample]
        if not s:
            return {}
        ncpu = psutil.cpu_count()
        srv = [x.server_cpu / ncpu for x in s]
        return {"server_cpu_avg_pct": statistics.mean(srv), "server_cpu_peak_pct": max(srv),
                "system_cpu_avg_pct": statistics.mean(x.system_cpu for x in s),
                "system_cpu_peak_pct": max(x.system_cpu for x in s),
                "loadgen_cpu_avg_pct": statistics.mean(x.loadgen_cpu / ncpu for x in s),
                "server_rss_peak_mb": max(x.server_rss_mb for x in s),
                "server_rss_end_mb": s[-1].server_rss_mb, "samples": len(s),
                "steal_avg_pct": statistics.mean(x.steal for x in s), "steal_peak_pct": max(x.steal for x in s)}

    for phase, (start, end) in rec.phases.items():
        calls = [c for c in rec.calls if c[0] == phase]
        dur = max(1e-9, end - start)
        # CPU-seconds the server actually consumed in the phase (sampled %-of-a-core x interval):
        # a cost per request that does not depend on how much CPU the hypervisor stole.
        busy_cpu_s = sum(x.server_cpu / 100.0 * args.sample for x in rec.samples if start < x.t <= end + args.sample)
        out["phases"][phase] = {"seconds": dur, "requests": len(calls), "throughput_rps": len(calls) / dur,
                                "errors": sum(1 for c in calls if not c[4]),
                                "server_cpu_ms_per_request": 1000 * busy_cpu_s / max(1, len(calls)), **window(start, end)}
    ride_phases = [p for p in rec.phases if p.startswith("rides#")]
    if ride_phases:  # the bursts together (P95 over every ride request)
        calls = [c for c in rec.calls if c[0] in ride_phases]
        busy = sum(rec.phases[p][1] - rec.phases[p][0] for p in ride_phases)
        cpu = [window(*rec.phases[p]) for p in ride_phases]
        out["phases"]["rides (all rounds)"] = {
            "seconds": busy, "requests": len(calls), "throughput_rps": len(calls) / max(busy, 1e-9),
            "server_cpu_ms_per_request": statistics.mean(out["phases"][p]["server_cpu_ms_per_request"] for p in ride_phases),
            "errors": sum(1 for c in calls if not c[4]),
            "server_cpu_avg_pct": statistics.mean(c["server_cpu_avg_pct"] for c in cpu if c),
            "server_cpu_peak_pct": max(c["server_cpu_peak_pct"] for c in cpu if c),
            "system_cpu_peak_pct": max(c["system_cpu_peak_pct"] for c in cpu if c),
            "server_rss_peak_mb": max(c["server_rss_peak_mb"] for c in cpu if c),
            "steal_avg_pct": statistics.mean(c["steal_avg_pct"] for c in cpu if c),
            "steal_peak_pct": max(c["steal_peak_pct"] for c in cpu if c),
        }
    groups = {}
    for phase, name, _, ms, ok, status in rec.calls:
        key = ("rides" if phase.startswith("rides#") else phase, name)
        groups.setdefault(key, []).append((ms, ok, status))
    for (phase, name), rows in groups.items():
        lat = [r[0] for r in rows]
        statuses = {}
        for r in rows:
            statuses[str(r[2])] = statuses.get(str(r[2]), 0) + 1
        out["endpoints"][f"{phase} | {name}"] = {
            "count": len(rows), "errors": sum(1 for r in rows if not r[1]), "statuses": statuses,
            "p50_ms": pct(lat, 50), "p90_ms": pct(lat, 90), "p95_ms": pct(lat, 95), "p99_ms": pct(lat, 99),
            "max_ms": max(lat), "mean_ms": statistics.mean(lat)}
    out["timeline"] = [(round(x.t - rec.samples[0].t, 2), round(x.server_cpu / psutil.cpu_count(), 1),
                        round(x.server_rss_mb, 1), round(x.system_cpu, 1)) for x in rec.samples] if rec.samples else []
    return out


def print_report(res: dict) -> None:
    print(f"\n=== {res['label']} ===  ({res['cpus']} CPUs; server: {res['config']['workers']} x {res['config']['worker_class']}"
          f" worker(s), {res['config']['threads']} thread(s))")
    print(f"{'endpoint':58} {'n':>5} {'err':>4} {'p50':>7} {'p95':>7} {'p99':>7} {'max':>7}  ms")
    for k, e in res["endpoints"].items():
        print(f"{k:58} {e['count']:5d} {e['errors']:4d} {e['p50_ms']:7.0f} {e['p95_ms']:7.0f} {e['p99_ms']:7.0f} {e['max_ms']:7.0f}"
              + (f"  {e['statuses']}" if e["errors"] else ""))
    print(f"\n{'phase':20} {'secs':>6} {'req':>6} {'req/s':>7} {'err':>5} {'srvCPU avg':>10} {'peak':>6} {'sysCPU peak':>11} {'RSS peak MB':>11} {'steal avg':>9} {'CPU ms/req':>10}")
    for k, p in res["phases"].items():
        print(f"{k:20} {p['seconds']:6.1f} {p['requests']:6d} {p['throughput_rps']:7.1f} {p['errors']:5d} "
              f"{p.get('server_cpu_avg_pct', 0):9.0f}% {p.get('server_cpu_peak_pct', 0):5.0f}% "
              f"{p.get('system_cpu_peak_pct', 0):10.0f}% {p.get('server_rss_peak_mb', 0):11.0f} {p.get('steal_avg_pct', 0):8.1f}% "
              f"{p.get('server_cpu_ms_per_request', 0):10.1f}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", help="URL of an already running server (default: start gunicorn here)")
    ap.add_argument("--seed-db", default="instance/loadtest.db")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--threads", type=int, default=16)
    ap.add_argument("--worker-class", default="gthread")
    ap.add_argument("--env", action="append", default=[], help="extra server env var, KEY=VALUE (repeatable)")
    ap.add_argument("--riders", type=int, default=1000)
    ap.add_argument("--drivers", type=int, default=1000)
    ap.add_argument("--login-window", type=float, default=60.0)
    ap.add_argument("--concurrency", type=int, default=300)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--ride-window", type=float, default=0.0,
                    help="spread each round's requests evenly over this many seconds (0 = all at the same instant)")
    ap.add_argument("--pause", type=float, default=3.0)
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("--sample", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--label", default="run")
    ap.add_argument("--json", help="write the full results here")
    args = ap.parse_args()
    if args.worker_class == "sync" and args.threads != 1:
        # gunicorn silently turns "sync" into "gthread" when --threads > 1 - measure what we say
        print(f"  note: sync workers are single-threaded - using --threads 1 (not {args.threads})")
        args.threads = 1

    proc = None
    if not args.base:
        proc = start_server(args)
        args.base = f"http://127.0.0.1:{args.port}"
    rec = Recorder()
    mon = Monitor(rec, proc.pid if proc else None, args.sample)
    mon.start()
    try:
        print(f"load test '{args.label}' against {args.base}", flush=True)
        info = asyncio.run(scenario(args, rec))
    finally:
        mon.stop.set()
        mon.join()
        if proc:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
    res = summarise(rec, info, args)
    res["first_errors"] = rec.errors
    res["ride_outcomes"] = rec.outcomes
    print_report(res)
    for e in rec.errors[:8]:
        print("  error:", e)
    print(f"  ride outcomes: {rec.outcomes}")
    if rec.outcomes.get("no_drivers"):
        print(f"  !! WARNING: {rec.outcomes['no_drivers']} ride(s) found NO driver - the test did not exercise matching")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
