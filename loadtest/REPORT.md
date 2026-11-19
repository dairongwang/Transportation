# Load test report — login burst + 300 concurrent ride requests

**Scenario (as requested):** 2000 users log in within 1 minute (1000 riders, 1000 drivers), then
300 concurrent ride requests. Measure latency of the related API calls, throughput, CPU and memory.
Targets for ride requests under this load: **P95 < 500 ms, CPU < 80 %**.

## Update — revised target: ride request P95 < 7 s, nearest‑40 pool

Requirement changed to **ride request P95 < 7 s** (CPU < 80 % unchanged), and
**"score only the nearest 40 drivers"** was chosen: `RIDE_CANDIDATE_POOL=40` is now the default.

Full scenario (2000 logins in 60 s, then 3 × 300 simultaneous ride requests), 3 × sync workers,
`EVENT_BUS=unix`, host quiet (steal ≤ 0.1 %):

| Run | `POST /api/rides` p50 / **p95** / p99 (ms) | Errors | Rides dispatched | Throughput | Server CPU avg / **peak** | RSS peak | Verdict |
|---|---|---|---|---|---|---|---|
| `07_final_pool40_run1.json` | 1 628 / **3 057** / 3 230 | 0 | 900 / 900 | 145 req/s | 52 % / **71 %** | 267 MB | ✅ P95 < 7 s, CPU < 80 % |
| `07_final_pool40_run2.json` | 1 499 / **2 928** / 3 308 | 0 | 900 / 900 | 161 req/s | 51 % / **71 %** | 268 MB | ✅ P95 < 7 s, CPU < 80 % |
| `08_compare_pool0_quiet.json` (exact ranking, for comparison) | 1 624 / 2 996 / 3 161 | 0 | 900 / 900 | 151 req/s | 61 % / 71 % | 265 MB | ✅ |

Per round, pool 40: P95 3.0 / 3.0 / 3.2 s (run 1) and 3.2 / 2.5 / 2.4 s (run 2); each burst of
300 drained in 3.1–4.7 s. Follow-up `GET /api/rides/<id>`: p95 3.0 s. Login phase: 2000 / 2000,
0 errors, 94–99 s; `POST /login` p95 17–20 s (scrypt-bound, see 2.2).

* **Both targets are met, with about 2.3× margin on P95** (about 3 s against 7 s) on a quiet host.
* **The pool buys CPU headroom, not latency.** Under identical quiet conditions, exact ranking
  gives the same P95 (3.0 s) but needs 61 % average CPU against 51–52 %, and about 17.5 against
  14–16 ms of server CPU per request. Latency at this load is set by queueing and SQLite's single
  writer, not by the ranking itself.
* **Caveat: CPU steal.** On this shared VM the same scenario degraded badly when the hypervisor
  took CPU: pool 40 reached P95 11.5 s at 45 % steal (run 04), and exact ranking 6.2 s at 13.6 %
  (run 03). The 7 s target therefore needs a host that does not lose a large share of its CPU; the
  headroom from the pool is what keeps it under 7 s at moderate steal. Dedicated vCPUs are
  recommended for production.
* Quality cost of the pool (section 3): the same best driver in 91.8 % of requests, 91.1 % top‑8
  overlap. When they differ, full ranking would have picked a driver outside the nearest 40, who
  is further away but cheaper or better rated.

The sections below are the original investigation (target P95 < 500 ms), kept unchanged as the
record of what was measured and changed.

## TL;DR (original target: P95 < 500 ms)

| | Before | After | Target |
|---|---|---|---|
| Ride request P95 (300 simultaneous, full scenario) | **113.2 s**, 284 / 900 failed (HTTP 500 *database is locked*) | **6.2 s**, 0 / 900 failed, every ride dispatched | < 500 ms ❌ |
| Best ride request P95 measured (host quiet) | — | **4.7 – 4.9 s** | < 500 ms ❌ |
| Server CPU during ride bursts | avg 24 % / peak 34 % (1 core usable) | avg 53 % / peak **67 %** | < 80 % ✅ |
| Ride request CPU cost (POST, same host conditions) | 146 ms | 31 – 41 ms (**3.5–4.7× less**) | |
| SQL statements per ride request + status fetch | 63 | 33 | |
| Login burst: 2000 logins | 282 s, 3 errors | 217 – 257 s, **0 errors** | (no target) |
| Server memory peak | 510 MB (1 worker) – 1.7 GB (4 workers) | 340 MB | |

* **CPU < 80 %: met** in every optimized run. By design, 3 single-threaded worker processes on
  4 vCPUs cannot take more than about 75 % of the machine.
* **P95 < 500 ms for 300 *simultaneous* ride requests: not met on this machine**, improved about
  18× (113 s → 6.2 s). No errors remain. The remaining gap is raw capacity, not a bug. Draining 300
  full ride requests within 0.5 s needs roughly 5× the CPU of the 3 cores available here, plus a
  database that allows concurrent writers. [Details](#why-p95--500-ms-is-not-reachable-here) and
  [options](#options-to-reach-the-target) below.
* The host is a shared VM that **stole 0–49 % of the CPU** during the runs (hypervisor steal).
  Every result below reports it. Latency worsened with steal much more than with any code change.

---

## 1. Test setup

| | |
|---|---|
| Machine | 4 vCPU Intel Xeon @ 2.60 GHz, 16 GB RAM, shared VM (Firecracker). **CPU steal under load: 0–49 %.** |
| App | ServiceUber, Python 3.12, Flask 3.1, SQLAlchemy 2, SQLite (WAL), gunicorn 26 |
| Data | `loadtest/seed.py`: 1000 riders (`buyer`) + 1000 drivers (`seller`, driver background check), DUMMY accounts, drivers spread over the 14 × 14 km demo city |
| Load generator | `loadtest/run.py`: one asyncio/aiohttp process on the same machine. It used about 7 % of the machine, and its CPU is reported separately. |
| Sampling | psutil every 0.5 s: CPU and RSS of the server process tree (gunicorn master + workers), system CPU and steal |

**Every virtual user behaves like a browser.** Each has its own cookie jar and its own client IP
(`X-Forwarded-For`, server runs with `BEHIND_PROXY=1`), so CSRF, sessions, Flask-Login "strong"
session protection, the per-IP login rate limits and the background-check gate are all active and
measured, not bypassed.

**Login phase.** 2000 users (shuffled riders and drivers) arrive uniformly over 60 s (33 per
second). Each one:
* `GET /login` (CSRF token)
* `POST /login` (302)
* `GET /dashboard`

Each driver then goes online with its GPS position: `POST /api/drivers/me/location`.

**Ride phase.** 3 rounds. In each round, 300 *different* logged-in riders are released at the
same instant (an asyncio barrier) and send `POST /api/rides`: auto-dispatch, cash, random pickup
and drop-off in the city. Each rider then fetches its ride once, like the ride page does:
`GET /api/rides/<id>`. The harness checks that every ride was really dispatched
(`status: offered`). A ride that finds no driver would measure the cheap code path.

**Ride work per request.** Background-check gate, rider checks, geocode and route, search and
rank the drivers around the pickup, create the ride and 8 ranked offers, dispatch the best driver
(and place a hold on card rides), open the rider ↔ driver chat room, queue push events, and
return the ride as JSON.

## 2. Results

All runs: 2000 logins, then 3 × 300 simultaneous ride requests, unless stated otherwise. Latency
is in milliseconds, measured by the client. Raw data is in `loadtest/results/*.json`.

### 2.1 Ride requests (`POST /api/rides`, 900 per run)

| Run | Server | p50 | **p95** | p99 | Errors | Throughput* | Server CPU avg / peak | Steal |
|---|---|---|---|---|---|---|---|---|
| 01 baseline | 1 × gthread 16 threads (the documented deployment), original code | 46 974 | **113 228** | 120 112 | **284 (32 %)** | 4.7 req/s | 24 % / 34 % | 0 % |
| 02 baseline | 4 × gthread 16 threads, original code | 19 155 | 56 399 | 66 446 | **548 (61 %)** | 6.9 req/s | 29 % / 93 % | 0 % |
| **03 optimized** | 3 × sync, exact ranking (default) | 3 188 | **6 195** | 6 869 | **0** | 75.4 req/s | 53 % / **67 %** | 13.6 % |
| 04 optimized | 3 × sync, nearest‑40 pool | 5 820 | 11 541 | 12 926 | 0 | 39.7 req/s | 27 % / 48 % | **45.4 %** |

\* Requests per second over the burst windows, POST + GET together.

Follow-up `GET /api/rides/<id>`: run 03 p50 3 866 / p95 5 797 ms, run 01 p95 98 955 ms (failed
rides had nothing to fetch).

**Ride-only bursts** (drivers pre-online, 300 simultaneous, 1 round, console output of the tuning
runs):

| Server | p50 | p95 | Burst drained in | Server CPU avg / peak | Steal |
|---|---|---|---|---|---|
| 3 × gthread 1 thread, nearest‑40 | 1 917 | **4 704** | 6.9 s | 40 % / 69 % | 0.1 % |
| 3 × sync, nearest‑40 | 2 876 | 4 808 | 6.4 s | 47 % / 65 % | 9.1 % |
| 3 × sync, exact ranking | 2 836 | 4 863 | 6.6 s | 58 % / 67 % | 6.2 % |
| 3 × gthread 1 thread, exact ranking | 5 827 | 10 023 | 13.4 s | 34 % / 69 % | 26.8 % |
| 3 × sync, exact ranking, 3 rounds (`06_…json`) | 5 864 | 14 034 | 14.7–20.9 s | 35 % / 59 % | 38.4 % |

**Spreading the 300 requests over 2–10 s** (`05_window_*.json`) did not help in these runs,
because all of them ran at 40–49 % steal: P95 was 11–13 s even at 30 requests/s. At that steal
level the server processed only 24–32 requests/s, using about 43 ms of CPU per request, against
about 18 ms when the host is quiet. I could not get a clean low-steal capacity curve on this host.

### 2.2 Login burst (2000 users, arrivals over 60 s)

| Run | Phase took | `POST /login` p50 / p95 | `GET /dashboard` p95 | `POST /api/drivers/me/location` p95 | Errors | Server CPU avg / peak | RSS peak | Steal |
|---|---|---|---|---|---|---|---|---|
| 01 baseline 1 worker | 282 s | 26 494 / 42 450 | 50 366 | 49 401 | 3 | 48 % / 97 % | 510 MB | 0 % |
| 02 baseline 4 workers | 145 s | 26 254 / 65 011 | 48 755 | 47 842 | **242** | 78 % / 99 % | **1 728 MB** | 0 % |
| 03 optimized | 257 s | 51 261 / 128 704 | 127 985 | 127 994 | **0** | 44 % / 70 % | 342 MB | 35.8 % |
| 04 optimized | 217 s | 36 478 / 95 302 | 99 801 | 98 926 | **0** | 50 % / 73 % | 342 MB | 28.4 % |

**Logins are CPU-bound by design.** Passwords are hashed with Werkzeug's default
`scrypt:32768:8:1`. One check costs about **187 ms of CPU and 32 MB of memory**, so 2000 logins
need about **374 CPU-seconds**. Fitting them into 60 s would take about 6.2 fully busy cores
(about 8 at < 80 %); this machine has 4. The burst therefore queues. With 3 workers and no steal,
the floor is about 2000 × 0.187 s ÷ 3 ≈ **125 s**; the runs took 217–257 s because of 28–36 %
steal. The baseline's 4 × 16-thread server ran up to 64 scrypt computations at once (1.7 GB RSS)
and failed 200 of 2000 logins (10 %) and 42 location updates with *database is locked*.

## 3. What was wrong, and what changed

Each finding was measured before it was fixed (`loadtest/bench_request.py`, per-request CPU in
process; `SQLITE_WRITE_LOCK_STATS=1`, writer-queue timings; statement timelines).

| # | Finding (measured) | Change | Effect (measured) |
|---|---|---|---|
| 1 | **"database is locked"**: SQLite in rollback-journal mode. Readers block the writer; the default 5 s wait expires under load (32–61 % of ride requests failed). | `dbtuning.py`: WAL, `synchronous=NORMAL`, 15 s busy timeout (`SQLITE_WAL`, `SQLITE_BUSY_TIMEOUT_MS`) | 0 errors in every optimized run |
| 2 | **More processes made it slower**: 3 processes drained a burst in 9.0 s, 1 process in 7.5 s. SQLite's busy handler *sleeps* 1→100 ms while the lock is free. | Writer queue: an exclusive `flock` on `<db>.writelock` before the first write, retried every 0.5–2 ms, bounded by the busy timeout (`SQLITE_WRITE_LOCK`, POSIX) | 9.0 s → 5.9 s at that stage |
| 3 | **Driver search loaded all 1000 drivers and their background checks as ORM objects per request** (about 100 ms) | `rides/driver_index.py`: per-process in-memory index with a 1 km grid, rebuilt every 2 s (`RIDE_DRIVER_INDEX_TTL_SECONDS`) and right after this process commits a relevant change. Listed drivers are re-checked in the database before being shown; dispatch re-checks again | search 13 ms → 1.3–1.7 ms |
| 4 | **N+1 queries**: a commit expires every object, so serializing the ride reloaded each offer, driver and user one by one (19 + 16 single-row SELECTs). The identity map's weak references also dropped loaded drivers. | `_ride_loaded()` eager loading; the POST serializes the objects it just committed; offers keep a reference to their driver | SQL per POST + GET 70 → 33 |
| 5 | Hot "yes/no" reads went through the ORM at about 1 ms each | Plain SQL for busy drivers, the can-drive check, the open-ride check, the existing-chat check and the chat summary. Gate fast path `passed_user_ids()`: the usual "passed" case is one light query | `clearance()` 3 → 1 per POST + GET. Fast rules proven identical to `clearance()` / `can_drive()` in every background-check state (tests) |
| 6 | The offer sweeper (every 10 s, in every worker) loaded **every** ride in "offered" state with all its offers | Loads only rides that have an expired pending offer | exact same result, O(expired) |
| 7 | **Threads in a CPU-bound worker cost throughput** (GIL contention: 8 threads 22 s drain vs 1 thread 9 s) | API workers single-threaded (`sync`, or `gthread --threads 1`) | see 2.1 |
| 8 | Score only the nearest N drivers | `RIDE_CANDIDATE_POOL` (now **default 40**, chosen; 0 = every driver) | −25 % CPU per POST at N = 40 (quality below) |
| 9 | **Correctness with several workers**: live updates (ride status, chat, background checks) only reached streams in the *same* process. Measured: the driver received 0–7 of 10 chat messages. | `rides/bus.py`: `EVENT_BUS=unix`, a Unix-datagram fan-out between the worker processes of a host | 10 / 10 on every run; also between two separate servers (API + SSE) |

Per-request CPU under the same host conditions: **original POST 146 ms / GET 15 ms → optimized
POST 41 ms (exact ranking) or 31 ms (nearest‑40) / GET 11–12 ms.**

**Quality of the optional nearest‑N pool.** Over 400 random requests with 1000 online drivers,
compared with ranking every driver:

| Pool size | Same best driver | Top-8 overlap |
|---|---|---|
| 10 | 75.0 % | 47.8 % |
| 20 | 88.5 % | 71.6 % |
| **40** | **91.8 %** | **91.1 %** |
| 80 | 94.0 % | 94.0 % |
| 160 | 97.0 % | 95.8 % |

When they differ, full ranking preferred a driver outside the nearest 40, who is further away (a
longer pickup) but cheaper or better rated. This is a product decision: **40 was chosen and is now the default**
(`RIDE_CANDIDATE_POOL=0` restores exact ranking).

## 4. Why P95 < 500 ms is not reachable here

For P95 < 500 ms, 285 of 300 simultaneous ride requests must complete within 0.5 s.

* **CPU.** One ride request (POST) costs 31–41 ms of CPU on this host when it is quiet, and about
  43 ms under contention; its GET costs 11–12 ms. So 285 POSTs are about **9–12 core-seconds of
  work**. On the 3 cores the server may use (CPU < 80 %), that is **at least 3–4 s**, which matches
  the measured 4.7–6.2 s P95 once queueing is added. Meeting 0.5 s would take roughly **18–24
  cores busy** (285 × 31–41 ms ÷ 0.5 s), or about 22–29 vCPU at < 80 %, before the follow-up GETs.
* **SQLite has one writer.** Every ride request writes (ride, 8 offers, chat room and message,
  driver counter) under a database-wide lock, held while the ORM flushes: about **7–11 ms** per
  ride request even in a single process (statement timeline), and p50 7–10 ms / p95 56–60 ms
  under load on this VM, where the lock holder is often descheduled. 300 ride requests therefore
  serialize for **about 2–3 s on SQLite alone, whatever the CPU.** This load needs a database
  with concurrent writers (PostgreSQL).
* **The work per request is legitimate.** Ranking, dispatch, holds, chat and events are what
  makes a ride request a ride request. I did not remove work to make the number look better: no
  skipped GET, no disabled checks, no weakened security.

## 5. Options to reach the target

1. **Asynchronous dispatch (how ride-hailing systems typically work).** `POST /api/rides` would
   validate and store the ride (`searching`) and return at once, about 5 ms. A background
   dispatcher ranks drivers, asks the best one and opens the chat; the rider's page already
   receives these steps as push events. Rough estimate: about 10 vCPU for this burst including the
   follow-up GET, and fewer without it.
   The time until a driver is asked would still be bounded by CPU: seconds for the last rider of
   a 300-burst on this box. **It changes the API contract** (the POST response would no longer
   contain the ranked drivers) **and the ride page flow, so it needs your decision.**
2. **More capacity:** roughly 22–29 vCPU (API workers) for the simultaneous 300-burst with the
   current synchronous design, plus **PostgreSQL** instead of SQLite, on **dedicated CPUs** (this
   VM lost up to 49 % to steal). Multi-host deployments need Redis pub/sub instead of the
   single-host `EVENT_BUS=unix`.
3. **`RIDE_CANDIDATE_POOL=40`:** 25 % cheaper ride requests, with the ranking trade-off above. *(Chosen; now the default.)*
4. **Logins:** 2000 per minute needs about 8 vCPU with the current scrypt settings. Alternatives
   are a tuned Argon2id, which keeps memory-hardness at a lower CPU cost per login, or accepting a
   ~2 minute drain. That is a security decision, so **password hashing was not changed.**

## 6. Limits of this test

* **Host noise.** A synthetic check (3 busy processes, no app) lost 18 % of the machine to steal
  at the time. During runs, steal was 0–49 % and rose with our own load. Latency varied up to 3×
  between identical runs. Compare runs only together with their steal column.
* **No SSE streams held open.** Real browsers keep `/events/account` (and for drivers
  `/events/driver`) open. Thread-per-connection servers need one thread per stream. Recommended:
  run the API and the streams as separate servers, sharing events through `EVENT_BUS=unix`
  (verified, see the README). 2000 concurrent streams on one host would be better served by an
  asynchronous worker (gevent). Neither was load tested.
* **In-memory rate-limit storage is per worker** (limits are effectively × workers). Use Redis
  (`RATELIMIT_STORAGE_URI`) in production. Under concurrency the `limits` library's memory storage
  logged a harmless `KeyError` in its expiry thread.
* **The load generator shares the machine** (about 7 % CPU).

## 7. Reproduce

```bash
pip install -r requirements.txt -r loadtest/requirements.txt
python loadtest/seed.py                                      # 1000 riders + 1000 drivers (instance/loadtest.db)
python loadtest/run.py --workers 3 --worker-class sync --env EVENT_BUS=unix \
       --label optimised --json loadtest/results/mine.json   # full scenario (~5 min)
python loadtest/run.py --workers 1 --threads 16 ...          # the documented deployment, for comparison
python loadtest/bench_request.py --queries                   # CPU per ride request, in-process
```

Useful options:
* `--ride-window S`: spread each round over S seconds.
* `--rounds`, `--concurrency`, `--login-window`.
* `--env KEY=VALUE`: any server setting, e.g. `RIDE_CANDIDATE_POOL=40` or `SQLITE_WRITE_LOCK_STATS=1`.
* `python loadtest/seed.py --drivers-online` plus `run.py --drivers 0`: quick ride-only runs.
