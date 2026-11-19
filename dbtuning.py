"""
SQLite under concurrent load (several threads and/or gunicorn worker processes).

1. Connection PRAGMAs (SQLITE_WAL, SQLITE_BUSY_TIMEOUT_MS)
     journal_mode=WAL      readers never block the writer and vice versa
     synchronous=NORMAL    no fsync on every commit (still crash-safe in WAL mode)
     busy_timeout          a writer waits for the lock instead of failing with "database is locked"

2. Writer queue (SQLITE_WRITE_LOCK, POSIX only)
   SQLite allows one writer at a time. A connection that finds the write lock taken waits in
   SQLite's busy handler, which SLEEPS in growing steps (1, 2, 5, 10 ... 100 ms) and re-checks.
   Under a burst of concurrent writes the lock is often free while every waiter is still asleep:
   measured with 3 worker processes, 300 concurrent ride requests drained SLOWER than with one
   process. So before a connection's first write statement it takes an exclusive flock() on
   "<database>.writelock", re-trying every 0.5-2 ms (instead of up to 100 ms), so the next writer
   starts almost as soon as the holder commits. The flock is released when the connection
   returns to the pool, i.e. right after its COMMIT / ROLLBACK. Readers are never affected.
   Bounded like SQLite's own wait: after SQLITE_BUSY_TIMEOUT_MS the writer stops queueing and
   falls back to SQLite's locking (so a stuck transaction can never freeze every writer).

   A thread that already holds the flock (a second connection in the same thread) does not take
   it again, so it cannot deadlock on itself; it simply falls back to SQLite's own locking.

   Diagnostics: SQLITE_WRITE_LOCK_STATS=1 logs, per process at exit, how long writers waited for
   and held the lock, plus a statement timeline of the first few holds over 50 ms.

Nothing here applies to other databases (use PostgreSQL for real deployments).
"""

from __future__ import annotations

import logging
import os
import threading
import time

log = logging.getLogger("dbtuning")

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]

_DML = ("INSERT", "UPDATE", "DELETE", "REPLACE")
_held = threading.local()  # .count: flocks held by this thread

# SQLITE_WRITE_LOCK_STATS=1: record how long writers wait for / hold the lock (logged at exit).
STATS = {"waits": [], "holds": []} if os.environ.get("SQLITE_WRITE_LOCK_STATS") == "1" else None


def _log_stats() -> None:
    if not STATS or not STATS["holds"]:
        return
    def pct(v, p):
        v = sorted(v)
        return v[min(len(v) - 1, int(len(v) * p / 100))]
    w, h = STATS["waits"], STATS["holds"]
    log.warning("writer queue pid=%s: %d writes, hold p50 %.2f p95 %.2f max %.2f ms, wait p50 %.2f p95 %.2f max %.2f ms",
                os.getpid(), len(h), pct(h, 50), pct(h, 95), max(h), pct(w, 50), pct(w, 95), max(w))


if STATS is not None:
    import atexit

    atexit.register(_log_stats)


def _acquire(fd: int, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    delay = 0.0005
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(delay)  # GIL released while waiting
            delay = min(delay * 1.5, 0.002)


def configure_sqlite(app, engine) -> None:
    from sqlalchemy import event

    if engine.dialect.name != "sqlite" or engine.url.database in (None, "", ":memory:"):
        return
    busy_ms = int(app.config.get("SQLITE_BUSY_TIMEOUT_MS", 15000))
    wal = bool(app.config.get("SQLITE_WAL", True))
    write_lock = bool(app.config.get("SQLITE_WRITE_LOCK", True)) and fcntl is not None
    lock_path = os.path.abspath(engine.url.database) + ".writelock"

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn, record):
        cur = dbapi_conn.cursor()
        cur.execute(f"PRAGMA busy_timeout = {busy_ms}")  # first, so switching the journal mode may wait too
        if wal:
            cur.execute("PRAGMA journal_mode = WAL")
            cur.execute("PRAGMA synchronous = NORMAL")
        cur.close()
        if write_lock:
            record.info["writelock_fd"] = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)

    if not write_lock:
        return

    @event.listens_for(engine, "before_cursor_execute")
    def _take(conn, cursor, statement, parameters, context, executemany):
        info = conn.connection._connection_record.info if conn.connection._connection_record else {}
        if STATS is not None and info.get("writelock_held"):
            info.setdefault("writelock_trace", []).append((time.perf_counter(), " ".join(statement.split())[:60]))
        if info.get("writelock_held") or not statement.lstrip()[:7].upper().startswith(_DML):
            return
        fd = info.get("writelock_fd")
        if fd is None or getattr(_held, "count", 0):
            return  # no lock file, or this thread already queued through another connection
        t0 = time.perf_counter()
        if not _acquire(fd, busy_ms / 1000.0):
            log.warning("SQLite writer queue: no turn within %d ms - falling back to SQLite locking", busy_ms)
            return
        if STATS is not None:
            info["writelock_t"] = time.perf_counter()
            STATS["waits"].append((info["writelock_t"] - t0) * 1000)
        info["writelock_held"] = True
        _held.count = getattr(_held, "count", 0) + 1

    def _release(record) -> None:
        if STATS is not None and record is not None and "writelock_t" in record.info and record.info.get("writelock_held"):
            t0 = record.info.pop("writelock_t")
            held = (time.perf_counter() - t0) * 1000
            STATS["holds"].append(held)
            trace = record.info.pop("writelock_trace", [])
            if held > 50 and STATS.setdefault("slow_logged", 0) < 4:
                STATS["slow_logged"] += 1
                log.warning("slow write hold %.1f ms (pid %s): %s | released +%.1f", held, os.getpid(),
                            " | ".join(f"+{(t - t0) * 1000:.1f} {s}" for t, s in trace), held)
        if record is not None and record.info.pop("writelock_held", False):
            fcntl.flock(record.info["writelock_fd"], fcntl.LOCK_UN)
            _held.count = max(0, getattr(_held, "count", 1) - 1)

    # The pool resets (rolls back) / receives a connection after COMMIT or ROLLBACK: release there.
    event.listen(engine.pool, "checkin", lambda dbapi_conn, record: _release(record))
    event.listen(engine.pool, "close", lambda dbapi_conn, record: _release(record))
    log.info("SQLite writer queue enabled (%s)", lock_path)
