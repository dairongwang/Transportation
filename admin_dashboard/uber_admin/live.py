"""
Live updates for the dashboard's browsers - push, no polling, no refresh.

  ServiceUber  GET /admin-api/v1/events  (SSE, bearer token)
        │  one RELAY thread per dashboard process reads it (server side: the token never reaches
        │  a browser), reconnects with backoff, and republishes every event on a local broker
        ▼
  dashboard    GET /events  (SSE, operator session)  ->  static/live.js re-renders the page's live
                                                          regions in place and shows a toast

Extra events produced here:
  relay   {"connected": bool, "error": str|None}  - shown as the "● live" indicator
  resync  after a (re)connection: events may have been missed, browsers re-render once
Own Broker implementation on purpose: this application shares no code with ServiceUber.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from collections import defaultdict

log = logging.getLogger("uber_admin.live")

KEEPALIVE_SECONDS = 15
CHANNEL = "dashboard"
BACKOFF = (1, 2, 4, 8, 15)


class Broker:
    """Thread-safe fan-out to the open browser streams."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subs: dict[str, list[queue.Queue]] = defaultdict(list)

    def subscribe(self, channel: str = CHANNEL) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._lock:
            self._subs[channel].append(q)
        return q

    def unsubscribe(self, q: queue.Queue, channel: str = CHANNEL) -> None:
        with self._lock:
            if q in self._subs.get(channel, []):
                self._subs[channel].remove(q)

    def publish(self, payload: dict, channel: str = CHANNEL) -> int:
        with self._lock:
            subs = list(self._subs.get(channel, []))
        for q in subs:
            q.put(payload)
        return len(subs)

    def clear(self) -> None:
        with self._lock:
            self._subs.clear()


broker = Broker()


def sse(payload: dict, event: str | None = None) -> str:
    return (f"event: {event}\n" if event else "") + "data: " + json.dumps(payload, separators=(",", ":")) + "\n\n"


def stream(hello: dict):
    """Generator for the browsers' text/event-stream (no app context needed)."""
    q = broker.subscribe()
    try:
        yield sse({"event": "hello", **hello}, "hello")
        while True:
            try:
                payload = q.get(timeout=KEEPALIVE_SECONDS)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue
            yield sse(payload, payload.get("event"))
    finally:
        broker.unsubscribe(q)


def parse_sse(lines):
    """Yield (event, data-dict) from an iterable of SSE text lines (comments / keepalives skipped)."""
    event, data = None, []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            if data:
                try:
                    yield event or "message", json.loads("\n".join(data))
                except ValueError:
                    log.warning("relay: ignored a malformed event")
            event, data = None, []
        elif line.startswith(":"):
            continue
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())


class Relay:
    """Keeps one connection to ServiceUber's event stream and republishes it."""

    def __init__(self, client) -> None:
        self.client = client
        self.connected = False
        self.error: str | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def status(self) -> dict:
        return {"connected": self.connected, "error": self.error}

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="admin-api-event-relay", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _set(self, connected: bool, error: str | None) -> None:
        changed = (connected, error) != (self.connected, self.error)
        self.connected, self.error = connected, error
        if changed:
            broker.publish({"event": "relay", **self.status})

    def _run(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            try:
                resp = self.client.open_events()
                with resp:
                    lines = (raw.decode("utf-8", "replace") for raw in iter(resp.readline, b""))
                    for event, data in parse_sse(lines):
                        if self._stop.is_set():
                            return
                        if event == "hello":
                            attempt = 0
                            self._set(True, None)
                            broker.publish({"event": "resync"})  # anything missed while disconnected
                            continue
                        broker.publish({**data, "event": event})
                self._set(False, "the ServiceUber event stream ended")
            except Exception as exc:  # noqa: BLE001 - keep relaying whatever happens
                self._set(False, getattr(exc, "message", None) or str(exc) or type(exc).__name__)
            delay = BACKOFF[min(attempt, len(BACKOFF) - 1)]
            attempt += 1
            self._stop.wait(delay)


def ensure_relay(app) -> Relay | None:
    """The process-wide relay (started lazily by the first browser that subscribes)."""
    if not app.config.get("LIVE_UPDATES", True):
        return None
    relay = app.extensions.get("live_relay")
    if relay is None:
        relay = app.extensions["live_relay"] = Relay(app.extensions["main_api"])
    relay.start()
    return relay
