"""
Cross-process fan-out for the push-event broker (rides/events.py) - EVENT_BUS=unix.

The broker keeps its subscribers (open SSE streams) in process memory. With several worker
processes (gunicorn -w N) an event published in worker A must also reach the streams held by
workers B, C, ... - otherwise a rider and a driver served by different workers would not see each
other's updates (ride status, chat messages, ...).

How: every process that has subscribers binds a Unix DATAGRAM socket "<pid>-<random>.sock" in
EVENT_BUS_DIR (default instance/eventbus). publish() delivers locally and sends the JSON event as one
datagram to every other socket in the directory; a receiver thread in each process hands incoming
events to its local subscribers. No broker server, no dependency; same-host only (several hosts:
use Redis pub/sub behind the same three calls).

  * lazy, per process id: the socket is bound on the first subscribe() in a process, so it works
    with or without gunicorn --preload (a forked child binds its own);
  * best effort like any pub/sub: a peer whose buffer is full drops the event (logged); sockets of
    dead processes (connection refused / file gone) are removed by the senders;
  * the directory is 0700 and every socket 0600: only the app's own OS user can send events;
  * POSIX only (Windows has no AF_UNIX datagrams): falls back to in-process delivery, with a warning.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import secrets
import socket
import threading

log = logging.getLogger("rides.bus")

MAX_DATAGRAM = 64 * 1024


class UnixBus:
    def __init__(self, directory: str, deliver) -> None:
        self.directory = os.path.abspath(directory)
        self._deliver = deliver  # callable(channel, payload): local fan-out
        self._lock = threading.Lock()
        self._pid: int | None = None
        self._path: str | None = None
        self._recv: socket.socket | None = None
        self._send: socket.socket | None = None
        self.sent = self.received = self.dropped = 0

    # ------------------------------------------------------------ lifecycle
    def _ensure_sender(self) -> socket.socket:
        if self._send is None or self._pid != os.getpid():
            self._send = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self._send.setblocking(False)
        return self._send

    def ensure_listening(self) -> None:
        """Bind this process's socket + start its receiver thread (idempotent, fork-aware)."""
        if self._pid == os.getpid() and self._recv is not None:
            return
        with self._lock:
            if self._pid == os.getpid() and self._recv is not None:
                return
            # Only this OS user may reach the sockets: anyone who can write to them could inject
            # events (e.g. fake chat messages) into users' live streams.
            os.makedirs(self.directory, mode=0o700, exist_ok=True)
            if os.stat(self.directory).st_uid == os.getuid():
                os.chmod(self.directory, 0o700)
            path = os.path.join(self.directory, f"{os.getpid()}-{secrets.token_hex(3)}.sock")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            old_umask = os.umask(0o177)  # the socket file is created 0600
            try:
                sock.bind(path)
            finally:
                os.umask(old_umask)
            self._recv, self._path, self._pid, self._send = sock, path, os.getpid(), None
            threading.Thread(target=self._receive_loop, args=(sock,), name="event-bus-receiver", daemon=True).start()
            atexit.register(self._cleanup, path)
            log.info("event bus listening on %s", path)

    @staticmethod
    def _cleanup(path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass

    def _receive_loop(self, sock: socket.socket) -> None:
        while True:
            try:
                data = sock.recv(MAX_DATAGRAM)
            except OSError:
                return
            try:
                msg = json.loads(data)
                self.received += 1
                self._deliver(msg["c"], msg["p"])
            except Exception:  # noqa: BLE001 - a bad datagram must not kill the receiver
                log.exception("event bus: bad message")

    # ------------------------------------------------------------ sending
    def _peer_paths(self) -> list[str]:
        # Listed on EVERY send (a few entries: microseconds). A cached list missed a process that
        # had just subscribed - its first events were lost (measured: 3 of 10 chat messages).
        try:
            names = os.listdir(self.directory)
        except FileNotFoundError:
            return []
        return [p for p in (os.path.join(self.directory, n) for n in names if n.endswith(".sock")) if p != self._path]

    def send(self, channel: str, payload: dict) -> None:
        data = json.dumps({"c": channel, "p": payload}, separators=(",", ":")).encode()
        if len(data) > MAX_DATAGRAM:
            log.warning("event bus: %d-byte event on %s too large - delivered locally only", len(data), channel)
            return
        sock = self._ensure_sender()
        for path in self._peer_paths():
            try:
                sock.sendto(data, path)
                self.sent += 1
            except (ConnectionRefusedError, FileNotFoundError):
                self._cleanup(path)  # the process behind it is gone
            except BlockingIOError:
                self.dropped += 1
                log.warning("event bus: peer %s is not keeping up - event dropped", os.path.basename(path))
            except OSError as exc:
                self.dropped += 1
                log.warning("event bus: send to %s failed: %s", os.path.basename(path), exc)


def available() -> bool:
    return hasattr(socket, "AF_UNIX") and os.name == "posix"
