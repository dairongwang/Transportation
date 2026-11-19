"""
Push notifications for rides: an in-process event bus + Server-Sent Events (SSE).

Nothing polls. State changes in rides/matching.py call `notify_*()`; the events are queued
on the database session and published ONLY after the transaction commits (so a client that
reacts by fetching fresh data never sees the pre-commit state). Browsers subscribe with
`EventSource` to

    GET /events/driver           the logged-in driver's channel  ("offer", "withdrawn", ...)
    GET /events/rides/<id>       a ride's channel                ("offered", "accepted", "declined",
                                                                  "expired", "cancelled", ...)

Every message is a JSON object {"event": ..., "ride_id": ..., "status": ..., "driver": ...}.
A comment line is sent every KEEPALIVE_SECONDS so proxies keep the connection open.

Deployment note: the broker keeps its subscribers per process. One process with threads (the dev
server, `waitress`, `gunicorn -k gthread -w 1`) needs nothing else. With SEVERAL worker processes set
EVENT_BUS=unix: every event is also fanned out to the other processes on the host (rides/bus.py).
"""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
from collections import defaultdict

from sqlalchemy import event as sa_event

log = logging.getLogger("rides.events")

KEEPALIVE_SECONDS = 15
PENDING_KEY = "ride_events"  # db.session.info[...] -> list[(channel, payload)]


class Broker:
    """Thread-safe fan-out of messages to subscriber queues, per channel."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: dict[str, list[queue.Queue]] = defaultdict(list)
        self.bus = None  # rides.bus.UnixBus when EVENT_BUS=unix (several worker processes)

    def subscribe(self, channel: str) -> queue.Queue:
        if self.bus is not None:
            self.bus.ensure_listening()  # this process has streams now: receive the other workers' events
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._subscribers[channel].append(q)
        return q

    def unsubscribe(self, channel: str, q: queue.Queue) -> None:
        with self._lock:
            subs = self._subscribers.get(channel, [])
            if q in subs:
                subs.remove(q)
            if not subs:
                self._subscribers.pop(channel, None)

    def publish(self, channel: str, payload: dict) -> int:
        """Deliver to this process's subscribers and, with a bus, to every other worker process."""
        if self.bus is not None:
            self.bus.send(channel, payload)
        return self.publish_local(channel, payload)

    def publish_local(self, channel: str, payload: dict) -> int:
        with self._lock:
            subs = list(self._subscribers.get(channel, []))
        for q in subs:
            q.put(payload)
        return len(subs)

    def clear(self) -> None:
        """Drop every subscriber (tests)."""
        with self._lock:
            self._subscribers.clear()

    def subscriber_count(self, channel: str | None = None) -> int:
        with self._lock:
            if channel is not None:
                return len(self._subscribers.get(channel, []))
            return sum(len(s) for s in self._subscribers.values())


broker = Broker()


# ----------------------------------------------------------------- channels

def driver_channel(driver_id: int) -> str:
    return f"driver:{driver_id}"


def ride_channel(ride_id: int) -> str:
    return f"ride:{ride_id}"


# ----------------------------------------------------------------- queuing (commit-safe)

def _session():
    from extensions import db

    return db.session


def queue_event(channel: str, payload: dict) -> None:
    """Publish `payload` on `channel` once the current transaction commits."""
    session = _session()()  # the scoped_session's current Session
    if not session.in_transaction():
        # Tie the event to a transaction so a rollback() discards it (without one, rollback
        # fires no event at all and the payload would go out with some later commit).
        session.begin()
    session.info.setdefault(PENDING_KEY, []).append((channel, payload))


def _flush_after_commit(session) -> None:
    pending = session.info.pop(PENDING_KEY, None)
    for channel, payload in pending or []:
        n = broker.publish(channel, payload)
        log.debug("event %s on %s -> %d subscriber(s)", payload.get("event"), channel, n)


def _drop_after_rollback(session, previous_transaction) -> None:
    # `after_soft_rollback` fires on EVERY rollback() - also when the transaction never touched
    # the database (plain `after_rollback` does not, which let queued events survive and go out
    # with a later commit). Only the outermost transaction drops the queue: rolling back a
    # SAVEPOINT must not discard events of the enclosing transaction.
    if previous_transaction.parent is None and not previous_transaction.nested:
        session.info.pop(PENDING_KEY, None)


def configure_bus(app) -> None:
    """EVENT_BUS=unix: fan events out to the other worker processes of this host (rides/bus.py)."""
    mode = str(app.config.get("EVENT_BUS", "local")).lower()
    if mode != "unix" or app.testing:
        return
    from . import bus

    if not bus.available():
        log.warning("EVENT_BUS=unix needs AF_UNIX datagram sockets (not on this OS) - events stay in-process")
        return
    directory = app.config.get("EVENT_BUS_DIR") or os.path.join(app.instance_path, "eventbus")
    if broker.bus is None or broker.bus.directory != os.path.abspath(directory):
        broker.bus = bus.UnixBus(directory, broker.publish_local)


_installed = False


def install(db) -> None:
    """Hook the after-commit flush into the Flask-SQLAlchemy session (idempotent)."""
    global _installed
    if _installed:
        return
    sa_event.listen(db.session, "after_commit", _flush_after_commit)
    sa_event.listen(db.session, "after_soft_rollback", _drop_after_rollback)
    _installed = True


# ----------------------------------------------------------------- what matching.py calls

def _ride_payload(ride, event: str, driver=None, **extra) -> dict:
    return {
        "event": event, "ride_id": ride.id, "status": ride.status,
        "driver": driver.user.username if driver is not None else (ride.driver.user.username if ride.driver else None),
        **extra,
    }


def notify_ride(ride, event: str, driver=None, **extra) -> None:
    """Tell everyone watching this ride (the rider's page) what just happened."""
    queue_event(ride_channel(ride.id), _ride_payload(ride, event, driver, **extra))


def notify_driver(driver_id: int, ride, event: str, **extra) -> None:
    """Tell a driver's dashboard that their list of requests changed."""
    queue_event(driver_channel(driver_id), _ride_payload(ride, event, **extra))


# ----------------------------------------------------------------- SSE response

def sse_format(payload: dict, event: str | None = None) -> str:
    data = json.dumps(payload, separators=(",", ":"))
    return (f"event: {event}\n" if event else "") + f"data: {data}\n\n"


def stream(channel: str, hello: dict):
    """
    Generator for a text/event-stream response. Yields a `hello` message right away (so the
    client knows it is connected and with which server-side version), then every published
    payload, with keepalive comments in between. Runs outside any request/app context: it
    must not touch the database.
    """
    q = broker.subscribe(channel)
    try:
        yield sse_format({"event": "hello", **hello}, "hello")
        while True:
            try:
                payload = q.get(timeout=KEEPALIVE_SECONDS)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            yield sse_format(payload, payload.get("event"))
    finally:
        broker.unsubscribe(channel, q)
