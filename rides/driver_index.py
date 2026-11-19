"""
In-memory index of the drivers who can be matched right now (one per worker process).

Why: every ride request searches the drivers around the pickup. Scanning every online driver in the
database and loading their background checks costs ~10 ms per request with 1000 drivers - the
largest part of a ride request. Real dispatch systems keep live driver positions in memory; so do we:

  * a SNAPSHOT of every online driver with a fresh position who is cleared to drive: position,
    prices, rating / acceptance counters - plain tuples, no ORM objects;
  * a GRID of ~1 km cells over it, so "the N nearest drivers" looks at a few cells, not all drivers.

Freshness
  * rebuilt when older than RIDE_DRIVER_INDEX_TTL_SECONDS (default 2 s), so changes made by OTHER
    worker processes show up within that time;
  * rebuilt at once after THIS process commits a change to a driver's availability, position or
    prices, or to a background check (session hooks -> mark_dirty()) - so within one process the
    index is never stale (tests, single-process servers);
  * the index only NARROWS the search. The drivers finally listed are loaded from the database in
    the same request and re-checked (online, fresh position, background check), and dispatch checks
    busy / online / cleared again at the moment a driver is asked - so a stale entry can never be
    offered a ride. Ratings / acceptance rates used for ranking may be up to the TTL old.

Set RIDE_DRIVER_INDEX_TTL_SECONDS=0 to rebuild on every search (no caching).
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass
from datetime import timedelta

from clock import utcnow

CELL_KM = 1.0
KM_PER_DEG_LAT = 111.32


@dataclass(frozen=True, slots=True)
class Entry:
    driver_id: int
    user_id: int
    lat: float
    lng: float
    base_fare: float
    per_km_rate: float
    per_min_rate: float
    min_fare: float
    rating: float
    acceptance_rate: float

    def quote(self, distance_km: float, duration_min: float) -> float:
        """Same formula as DriverProfile.quote()."""
        fare = self.base_fare + self.per_km_rate * distance_km + self.per_min_rate * duration_min
        return round(max(fare, self.min_fare), 2)


class DriverIndex:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._built_at = 0.0
        self._dirty = True
        self._entries: list[Entry] = []
        self._grid: dict[tuple[int, int], list[Entry]] = {}
        self._lng_km = KM_PER_DEG_LAT  # km per degree of longitude at the fleet's latitude
        self.builds = 0  # (observability / tests)

    # ------------------------------------------------------------ building
    def mark_dirty(self) -> None:
        self._dirty = True

    def _cell(self, lat: float, lng: float) -> tuple[int, int]:
        return int(math.floor(lat * KM_PER_DEG_LAT / CELL_KM)), int(math.floor(lng * self._lng_km / CELL_KM))

    def _build(self, stale_seconds: int) -> None:
        from sqlalchemy import select

        from background.service import driving_cleared_user_ids
        from extensions import db
        from models import DriverProfile

        t = DriverProfile.__table__
        cutoff = utcnow() - timedelta(seconds=stale_seconds)
        rows = db.session.execute(
            select(t.c.id, t.c.user_id, t.c.lat, t.c.lng, t.c.base_fare, t.c.per_km_rate, t.c.per_min_rate,
                   t.c.min_fare, t.c.rating_sum, t.c.rating_count, t.c.offers_received, t.c.offers_accepted)
            .where(t.c.is_online.is_(True), t.c.lat.isnot(None), t.c.lng.isnot(None),
                   t.c.location_updated_at >= cutoff)
        ).all()
        cleared = driving_cleared_user_ids(r.user_id for r in rows)
        entries = []
        for r in rows:
            if r.user_id not in cleared:
                continue
            rating = r.rating_sum / r.rating_count if r.rating_count else DriverProfile.DEFAULT_RATING
            acceptance = r.offers_accepted / r.offers_received if r.offers_received else DriverProfile.DEFAULT_ACCEPTANCE
            entries.append(Entry(r.id, r.user_id, r.lat, r.lng, r.base_fare, r.per_km_rate, r.per_min_rate,
                                 r.min_fare, rating, acceptance))
        mean_lat = sum(e.lat for e in entries) / len(entries) if entries else 0.0
        self._lng_km = max(1e-6, KM_PER_DEG_LAT * math.cos(math.radians(mean_lat)))
        grid: dict[tuple[int, int], list[Entry]] = {}
        for e in entries:
            grid.setdefault(self._cell(e.lat, e.lng), []).append(e)
        self._entries, self._grid = entries, grid
        self._built_at = time.monotonic()
        self._dirty = False
        self.builds += 1
        # Reference point for the staleness cut-off: entries were fresh at build time; a position
        # that turns stale within the TTL is caught by the re-check of the listed drivers.

    def _ensure(self, ttl: float, stale_seconds: int) -> None:
        if not self._dirty and ttl > 0 and time.monotonic() - self._built_at < ttl:
            return
        with self._lock:
            if not self._dirty and ttl > 0 and time.monotonic() - self._built_at < ttl:
                return  # another thread rebuilt it meanwhile
            self._build(stale_seconds)

    # ------------------------------------------------------------ queries
    def nearest(self, lat: float, lng: float, *, radius_km: float, limit: int, skip,
                ttl: float, stale_seconds: int) -> list[tuple[float, Entry]]:
        """
        [(straight-line km, entry)] of the nearest drivers within radius_km, nearest first; at most
        `limit` of them (0 = all). `skip(entry)` -> True excludes an entry (busy, the rider, ...).
        """
        from .geo import haversine_km

        self._ensure(ttl, stale_seconds)
        grid, entries = self._grid, self._entries
        found: list[tuple[float, Entry]] = []
        if limit <= 0:  # everyone within the radius
            for e in entries:
                if not skip(e):
                    km = haversine_km(lat, lng, e.lat, e.lng)
                    if km <= radius_km:
                        found.append((km, e))
            found.sort(key=lambda x: (x[0], x[1].driver_id))
            return found
        cy, cx = self._cell(lat, lng)
        max_ring = int(radius_km / CELL_KM) + 2
        for ring in range(max_ring + 1):
            for y in range(cy - ring, cy + ring + 1):
                xs = range(cx - ring, cx + ring + 1) if y in (cy - ring, cy + ring) else (cx - ring, cx + ring)
                for x in xs:
                    for e in grid.get((y, x), ()):
                        if skip(e):
                            continue
                        km = haversine_km(lat, lng, e.lat, e.lng)
                        if km <= radius_km:
                            found.append((km, e))
            if len(found) >= limit:
                found.sort(key=lambda x: (x[0], x[1].driver_id))
                # everything in ring+1 or beyond is at least `ring` whole cells away
                if found[limit - 1][0] <= ring * CELL_KM * 0.95:  # 5 % margin: lng scale, curvature
                    break
        found.sort(key=lambda x: (x[0], x[1].driver_id))
        return found[:limit]


index = DriverIndex()

# Columns whose change must be visible to the matcher at once (in this process).
_WATCHED = {"is_online", "lat", "lng", "location_updated_at", "base_fare", "per_km_rate", "per_min_rate", "min_fare"}


_FLAG = "driver_index_dirty"


def _after_flush(session, _ctx) -> None:
    """Note on the session that this transaction changes what the matcher must see."""
    from sqlalchemy import inspect as sa_inspect

    from models import BackgroundCheck, DriverProfile

    if session.info.get(_FLAG):
        return
    for obj in list(session.new) + list(session.dirty) + list(session.deleted):
        if isinstance(obj, BackgroundCheck):
            session.info[_FLAG] = True
            return
        if isinstance(obj, DriverProfile):
            if obj in session.new or obj in session.deleted:
                session.info[_FLAG] = True
                return
            state = sa_inspect(obj)
            if any(state.attrs[c].history.has_changes() for c in _WATCHED):
                session.info[_FLAG] = True
                return


def _after_commit(session) -> None:
    # Only once the change is committed (a rebuild in between would read the old state and forget it).
    if session.info.pop(_FLAG, False):
        index.mark_dirty()


def _after_rollback(session) -> None:
    session.info.pop(_FLAG, None)


_installed = False


def install(db) -> None:
    global _installed
    if _installed:
        return
    from sqlalchemy import event

    event.listen(db.session, "after_flush", _after_flush)
    event.listen(db.session, "after_commit", _after_commit)
    event.listen(db.session, "after_soft_rollback", lambda session, _prev: _after_rollback(session))
    _installed = True
