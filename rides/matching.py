"""
Driver search, ranking and dispatch.

Flow
----
  1. rider submits pickup + drop-off                      -> create_ride()
  2. geocode both, estimate the trip                      -> geo.py
  3. find online drivers near the pickup                  -> find_candidates()
  4. score every candidate on distance, rating, price,
     acceptance rate and sort                             -> rank_candidates()
  5. store the ranked list as RideOffer rows. The rider SELECTS a driver from the list
     (changeable, select_driver) and presses ORDER (place_order) - that is the moment the
     order is final: the driver is asked and the hold is placed. With auto-dispatch the best
     driver is asked right away and a decline / timeout cascades to the next -> offer_next()
     Whenever a driver is asked (picked by the rider or by auto-dispatch) the rider's payment
     method is PRE-AUTHORISED for RIDE_PREAUTH_FACTOR x that driver's quote (default 1.5 =
     the estimate + 50 %). A refused hold stops dispatch until the rider fixes the payment
     method; the hold is released if the ride does not happen.   -> payments.service
  6. driver accepts -> ride accepted -> start -> complete (hold captured for the actual fare)
     -> rider rates
  Chat: the moment a driver is asked (the rider pressed Order, or auto-dispatch), a chat room
  between the rider and that driver opens so they can agree on where to meet; it closes when
  that driver drops out or the ride ends.                 -> rides/chat.py

Ranking
-------
Each criterion is turned into a 0..1 "goodness" (1 = best) and combined with the weights
in RIDE_RANK_WEIGHTS (defaults 0.40 / 0.25 / 0.20 / 0.15):

  distance    1 - distance_to_pickup / search_radius          (0 km -> 1, at the edge -> 0)
  rating      (rating - 1) / 4                                (1 star -> 0, 5 stars -> 1)
  price       min-max within the candidate set                (cheapest -> 1, priciest -> 0;
                                                               all equal -> 1)
  acceptance  the driver's historical acceptance rate         (already 0..1)

Ties are broken in the same order: closer, then better rated, then cheaper, then higher
acceptance rate. `rank_candidates()` is pure (no DB, no Flask) so it is easy to unit test.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from flask import current_app

from clock import utcnow
from extensions import db
from models import DriverProfile, RideOffer, RideRequest, User

from . import chat, events, geo
from .geo import GeoError, GeoPoint, RouteEstimate

log = logging.getLogger("rides.matching")

CRITERIA = ("distance", "rating", "price", "acceptance")
DEFAULT_WEIGHTS = {"distance": 0.40, "rating": 0.25, "price": 0.20, "acceptance": 0.15}
BUSY_STATUSES = ("accepted", "in_progress")


class RideError(Exception):
    """User-facing problem with a ride operation."""


@dataclass
class Candidate:
    driver_id: int
    distance_km: float  # driver -> pickup
    eta_min: float
    price: float  # quoted fare for the trip
    rating: float
    acceptance_rate: float
    score: float = 0.0
    components: dict[str, float] = field(default_factory=dict)  # normalised 0..1 per criterion
    driver: DriverProfile | None = None  # attached when built from the DB

    def as_dict(self) -> dict:
        d = {
            "driver_id": self.driver_id,
            "distance_km": round(self.distance_km, 2),
            "eta_min": round(self.eta_min, 1),
            "price": round(self.price, 2),
            "rating": round(self.rating, 2),
            "acceptance_rate": round(self.acceptance_rate, 3),
            "score": round(self.score, 4),
            "components": {k: round(v, 3) for k, v in self.components.items()},
        }
        if self.driver is not None:
            d["driver"] = {"username": self.driver.user.username, "vehicle": self.driver.vehicle}
        return d


# ================================================================== ranking (pure)

def _clamp(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def normalise_weights(weights: dict[str, float] | None) -> dict[str, float]:
    w = {k: max(0.0, float((weights or {}).get(k, DEFAULT_WEIGHTS[k]))) for k in CRITERIA}
    total = sum(w.values())
    if total <= 0:
        w = dict(DEFAULT_WEIGHTS)
        total = sum(w.values())
    return {k: v / total for k, v in w.items()}


def score_candidates(candidates: list[Candidate], radius_km: float, weights: dict[str, float] | None = None) -> None:
    """Fill `score` and `components` in place."""
    if not candidates:
        return
    w = normalise_weights(weights)
    radius = max(float(radius_km), 0.001)
    prices = [c.price for c in candidates]
    lo, hi = min(prices), max(prices)
    for c in candidates:
        comp = {
            "distance": _clamp(1.0 - c.distance_km / radius),
            "rating": _clamp((c.rating - 1.0) / 4.0),
            "price": 1.0 if hi <= lo else _clamp((hi - c.price) / (hi - lo)),
            "acceptance": _clamp(c.acceptance_rate),
        }
        c.components = comp
        c.score = sum(w[k] * comp[k] for k in CRITERIA)


def rank_candidates(candidates: list[Candidate], radius_km: float, weights: dict[str, float] | None = None,
                    limit: int | None = None) -> list[Candidate]:
    """Score and sort: best first. Ties -> closer, better rated, cheaper, higher acceptance."""
    score_candidates(candidates, radius_km, weights)
    ranked = sorted(candidates, key=lambda c: (-round(c.score, 9), c.distance_km, -c.rating, c.price, -c.acceptance_rate))
    return ranked[:limit] if limit else ranked


# ================================================================== candidate search (DB)

def _cfg(key: str, default):
    try:
        return current_app.config.get(key, default)
    except RuntimeError:  # pragma: no cover - outside app context
        return default


def busy_driver_ids() -> set[int]:
    from sqlalchemy import select

    t = RideRequest.__table__
    rows = db.session.execute(select(t.c.driver_id).where(t.c.status.in_(BUSY_STATUSES))).all()
    return {r[0] for r in rows if r[0] is not None}


def _driver_cleared(driver: DriverProfile) -> bool:
    """
    The driver's background check is passed AND covers driving - the can_drive() rule, evaluated
    with one light query (driving_cleared_user_ids; identical results, see tests/test_load_optimisations.py).
    """
    from background.service import driving_cleared_user_ids

    return driver.user_id in driving_cleared_user_ids([driver.user_id])


def _unavailable(offer: RideOffer, busy: set[int]) -> bool:
    return offer.driver_id in busy or not offer.driver.is_online or not _driver_cleared(offer.driver)


def find_candidates(pickup: GeoPoint, trip: RouteEstimate, exclude_user_id: int | None = None,
                    radius_km: float | None = None, pool: int | None = None,
                    busy: set[int] | None = None) -> list[Candidate]:
    """
    Online, background-checked drivers with a fresh position within the search radius, each with a
    fare quote - read from the in-memory driver index (rides/driver_index.py), so no ORM objects are
    built here (Candidate.driver is None; search_drivers() attaches and re-checks the listed ones).
    Only the `pool` (RIDE_CANDIDATE_POOL) NEAREST drivers are scored; 0 = every driver in range.
    """
    from .driver_index import index

    radius = float(radius_km if radius_km is not None else _cfg("RIDE_SEARCH_RADIUS_KM", 10.0))
    stale = int(_cfg("DRIVER_LOCATION_STALE_SECONDS", 1800))
    pool = int(pool if pool is not None else _cfg("RIDE_CANDIDATE_POOL", 0))
    busy = busy_driver_ids() if busy is None else busy
    near = index.nearest(pickup.lat, pickup.lng, radius_km=radius, limit=pool,
                         skip=lambda e: e.driver_id in busy or e.user_id == exclude_user_id,
                         ttl=float(_cfg("RIDE_DRIVER_INDEX_TTL_SECONDS", 2.0)), stale_seconds=stale)
    router = geo.get_router()
    candidates: list[Candidate] = []
    for _, e in near:
        approach = router.route(GeoPoint(e.lat, e.lng), pickup)
        if approach.distance_km > radius:  # the road is longer than the straight line
            continue
        candidates.append(Candidate(
            driver_id=e.driver_id, distance_km=approach.distance_km, eta_min=approach.duration_min,
            price=e.quote(trip.distance_km, trip.duration_min), rating=e.rating, acceptance_rate=e.acceptance_rate,
        ))
    return candidates


def _attach_listed(ranked: list[Candidate], limit: int, busy: set[int]) -> list[Candidate]:
    """
    The best `limit` candidates that are STILL available according to the database (the index may
    be up to its TTL old): loaded with user, background checks and disputes - so dispatch later in
    this request needs no more queries - and re-checked: online, fresh position, not busy, cleared
    to drive. Loads in small batches down the ranking until `limit` pass.
    """
    from sqlalchemy.orm import joinedload

    from background.service import driving_cleared_user_ids

    stale = int(_cfg("DRIVER_LOCATION_STALE_SECONDS", 1800))
    listed: list[Candidate] = []
    i = 0
    while len(listed) < limit and i < len(ranked):
        batch = ranked[i: i + max(limit - len(listed), 1) + 2]
        i += len(batch)
        loaded = {d.id: d for d in DriverProfile.query.options(joinedload(DriverProfile.user))
                  .filter(DriverProfile.id.in_([c.driver_id for c in batch])).all()}
        cleared = driving_cleared_user_ids(d.user_id for d in loaded.values())  # the can_drive() rule
        for c in batch:
            d = loaded.get(c.driver_id)
            if (d is not None and len(listed) < limit and d.is_online and d.id not in busy
                    and d.location_is_fresh(stale) and d.user_id in cleared):
                c.driver = d
                listed.append(c)
    return listed


def search_drivers(pickup: GeoPoint, dropoff: GeoPoint, exclude_user_id: int | None = None) -> tuple[RouteEstimate, list[Candidate]]:
    """Search + rank without creating anything (also used by the preview API)."""
    trip = geo.get_router().route(pickup, dropoff)
    busy = busy_driver_ids()
    candidates = find_candidates(pickup, trip, exclude_user_id=exclude_user_id, busy=busy)
    ranked = rank_candidates(
        candidates,
        radius_km=float(_cfg("RIDE_SEARCH_RADIUS_KM", 10.0)),
        weights=_cfg("RIDE_RANK_WEIGHTS", DEFAULT_WEIGHTS),
    )
    return trip, _attach_listed(ranked, int(_cfg("RIDE_MAX_CANDIDATES", 8)), busy)


# ================================================================== dispatch state machine

def _dummy_payment_token() -> str:
    return f"DUMMY_RIDE_PAY_{uuid.uuid4().hex[:16].upper()}"


DEFAULT_PAYMENT = "default"


def create_ride(rider: User, pickup_text: str, dropoff_text: str, auto_dispatch: bool = True,
                payment_method_id: int | str | None = DEFAULT_PAYMENT) -> RideRequest:
    """
    Geocode, search, rank, persist. Raises RideError / GeoError with a user-facing message.
    payment_method_id: id of one of the rider's stored PaymentMethods, None for cash, or
    DEFAULT_PAYMENT to use the rider's default method (cash if they have none).
    """
    if rider.role == "seller":
        raise RideError("Your account is seller-only and cannot request rides.")
    from background.service import is_cleared

    if not is_cleared(rider):
        raise RideError("Complete your background check before requesting rides.")
    from payments import service as payments

    method = None
    if payment_method_id == DEFAULT_PAYMENT:
        method = payments.default_method(rider)
    elif payment_method_id is not None:
        try:
            method = payments.get_owned(rider, payment_method_id)
        except payments.PaymentMethodError as exc:
            raise RideError(str(exc)) from None
        if method.is_expired:
            raise RideError(f"{method.display} has expired. Update it in your Account tab.")
    from sqlalchemy import select

    rt = RideRequest.__table__
    open_ride = db.session.execute(select(rt.c.id).where(
        rt.c.rider_id == rider.id, rt.c.status.in_(("searching", "offered", "accepted", "in_progress"))).limit(1)
    ).scalar()
    if open_ride:
        raise RideError(f"You already have an active ride (#{open_ride}). Finish or cancel it first.")

    geocoder = geo.get_geocoder()
    pickup = geocoder.geocode(pickup_text)
    dropoff = geocoder.geocode(dropoff_text)
    if geo.haversine_km(pickup.lat, pickup.lng, dropoff.lat, dropoff.lng) < 0.05:
        raise GeoError("Pickup and drop-off are the same place.")

    trip, ranked = search_drivers(pickup, dropoff, exclude_user_id=rider.id)

    ride = RideRequest(
        rider_id=rider.id,
        pickup_address=pickup.label[:200],
        pickup_lat=pickup.lat,
        pickup_lng=pickup.lng,
        dropoff_address=dropoff.label[:200],
        dropoff_lat=dropoff.lat,
        dropoff_lng=dropoff.lng,
        trip_distance_km=round(trip.distance_km, 3),
        trip_duration_min=round(trip.duration_min, 1),
        auto_dispatch=auto_dispatch,
        status="searching",
        payment_method_id=method.id if method else None,
    )
    db.session.add(ride)
    for i, c in enumerate(ranked, start=1):
        # Attach the loaded driver object (not only its id) so it - and its user - stay in the
        # session's identity map: otherwise they are garbage-collected and reloaded one by one.
        attach = {"driver": c.driver} if c.driver is not None else {}
        ride.offers.append(
            RideOffer(
                driver_id=c.driver_id,
                **attach,
                rank=i,
                score=round(c.score, 4),
                distance_km=round(c.distance_km, 3),
                eta_min=round(c.eta_min, 1),
                price=c.price,
                rating=round(c.rating, 2),
                acceptance_rate=round(c.acceptance_rate, 3),
            )
        )
    db.session.flush()

    if not ranked:
        ride.status = "no_drivers"
    elif auto_dispatch:
        offer_next(ride, raise_on_payment_error=True)  # refused hold -> no ride is created
    db.session.commit()
    log.info("ride=%s rider=%s candidates=%s status=%s preauth=%s", ride.id, rider.id, len(ranked), ride.status,
             f"{ride.preauth_amount:.2f}" if ride.preauth_amount else "cash/none")
    return ride


def _preauthorise(ride: RideRequest, estimate: float) -> None:
    """Reserve the pre-authorisation for `estimate` on the ride's payment method (no-op for cash)."""
    if ride.payment_method is None:
        return
    from payments import service as payments
    from payments.gateway import PaymentError

    try:
        payments.hold_for_ride(ride, estimate)
    except PaymentError as exc:
        raise RideError(f"{exc} Change the payment method for this ride (or pay cash) and pick a driver again.") from exc


def _send_offer(ride: RideRequest, offer: RideOffer) -> None:
    """Ask a driver. Raises RideError - with the offer left 'ranked' - if the hold is refused."""
    _preauthorise(ride, offer.price)
    now = utcnow()
    offer.status = "pending"
    offer.offered_at = now
    offer.expires_at = now + timedelta(seconds=int(_cfg("RIDE_OFFER_TTL_SECONDS", 120)))
    offer.driver.offers_received += 1
    ride.status = "offered"
    chat.open_room(ride, offer.driver)  # the order is placed: rider and driver can talk about meeting
    events.notify_driver(offer.driver_id, ride, "offer", offer_id=offer.id, expires_at=offer.expires_at.isoformat())
    events.notify_ride(ride, "offered", driver=offer.driver, offer_id=offer.id)


def offer_next(ride: RideRequest, raise_on_payment_error: bool = False) -> RideOffer | None:
    """
    Offer the ride to the best driver who has not been asked yet. None -> nobody left (the
    ride becomes no_drivers and any hold is released) or the pre-authorisation was refused
    (the ride stays 'searching' with preauth_status='failed' so the rider can fix the payment
    method; with raise_on_payment_error the RideError propagates instead).
    """
    if ride.status not in ("searching", "offered"):
        return None
    if ride.pending_offer is not None:
        return ride.pending_offer
    busy = busy_driver_ids()
    for offer in ride.offers:  # already ordered by rank
        if offer.status != "ranked":
            continue
        if _unavailable(offer, busy):
            offer.status = "skipped"
            continue
        try:
            _send_offer(ride, offer)
        except RideError:
            ride.status = "searching"
            log.info("ride=%s dispatch paused: pre-authorisation refused", ride.id)
            if raise_on_payment_error:
                raise
            return None
        return offer
    ride.status = "no_drivers"
    _release(ride, "no driver available")
    chat.close_all(ride, chat.REASON_NO_DRIVERS)
    events.notify_ride(ride, "no_drivers")
    return None


def _release(ride: RideRequest, reason: str) -> None:
    from payments import service as payments

    payments.release_hold(ride, reason)


def _check_orderable(ride: RideRequest, offer: RideOffer) -> None:
    """Raise unless `offer` is a ranked driver of this open ride that nobody is being asked for."""
    if not ride.is_open:
        raise RideError("This ride is no longer open.")
    if ride.pending_offer is not None:
        raise RideError("Your order is already placed: a driver is being asked. Wait for the answer or cancel the ride.")
    if offer.ride_id != ride.id or offer.status != "ranked":
        raise RideError("That driver can no longer be selected.")
    if _unavailable(offer, busy_driver_ids()):
        offer.status = "skipped"
        if ride.selected_offer_id == offer.id:
            ride.selected_offer_id = None
        raise RideError("That driver just became unavailable. Select another one.")


def select_driver(ride: RideRequest, offer: RideOffer) -> RideOffer:
    """
    Step 1 - the rider picks a driver from the ranked list. Nothing is sent and nothing is
    reserved yet; the rider can select a different driver any number of times.
    """
    _check_orderable(ride, offer)
    ride.selected_offer_id = offer.id
    return offer


def place_order(ride: RideRequest) -> RideOffer:
    """
    Step 2 - "Order": the selection becomes final. The pre-authorisation hold is placed and
    the selected driver is asked. Raises RideError (selection kept) if the hold is refused.
    """
    offer = ride.selected_offer
    if offer is None:
        if ride.pending_offer is not None:
            raise RideError("Your order is already placed: a driver is being asked.")
        raise RideError("Select a driver from the list first, then press Order.")
    return offer_to(ride, offer)


def offer_to(ride: RideRequest, offer: RideOffer) -> RideOffer:
    """Ask a specific driver (select + order in one step; used by place_order and the JSON API)."""
    _check_orderable(ride, offer)
    ride.selected_offer_id = offer.id
    _send_offer(ride, offer)  # raises RideError if the hold is refused; selection is kept
    return offer


def expire_stale_offers(ride: RideRequest) -> bool:
    """Time out pending offers; with auto-dispatch move on to the next driver. True if changed."""
    changed = False
    for offer in ride.offers:
        if offer.is_expired:
            offer.status = "expired"
            offer.responded_at = utcnow()
            changed = True
            chat.close_for_driver(ride, offer.driver_id, chat.REASON_EXPIRED)
            events.notify_driver(offer.driver_id, ride, "withdrawn", offer_id=offer.id, reason="expired")
            events.notify_ride(ride, "expired", driver=offer.driver, offer_id=offer.id)
    if changed and ride.is_open:
        ride.status = "searching"
        if ride.auto_dispatch:
            offer_next(ride)
    return changed


def expire_all_stale_offers() -> int:
    """
    Time out every unanswered offer (background sweeper, driver pages, dev simulator). Only rides
    that HAVE a pending offer past its deadline are loaded - expire_stale_offers() cannot change any
    other ride - instead of every ride in the "offered" state with all of its offers.
    """
    from sqlalchemy import select

    o, r = RideOffer.__table__, RideRequest.__table__
    ride_ids = db.session.execute(
        select(o.c.ride_id).distinct().join(r, r.c.id == o.c.ride_id)
        .where(o.c.status == "pending", o.c.expires_at < utcnow(), r.c.status == "offered")
    ).scalars().all()
    n = 0
    for ride in RideRequest.query.filter(RideRequest.id.in_(ride_ids)).all() if ride_ids else []:
        if expire_stale_offers(ride):
            n += 1
    return n


def accept_offer(offer: RideOffer, driver: DriverProfile) -> RideRequest:
    ride = offer.ride
    if offer.driver_id != driver.id:
        raise RideError("This offer is not yours.")
    if offer.is_expired:
        expire_stale_offers(ride)
        raise RideError("The offer has expired.")
    if offer.status != "pending" or not ride.is_open:
        raise RideError("This offer is no longer open.")
    if driver.id in busy_driver_ids():
        raise RideError("Finish your current ride first.")
    if not _driver_cleared(driver):
        raise RideError("Your background check does not cover driving (or is no longer valid).")
    now = utcnow()
    offer.status = "accepted"
    offer.responded_at = now
    driver.offers_accepted += 1
    # Candidates who were never asked stay "ranked": if this driver later hands the ride
    # back, dispatch can continue down the list.
    ride.driver_id = driver.id
    ride.fare = offer.price
    ride.payment_token = _dummy_payment_token()
    ride.status = "accepted"
    chat.note(ride, f"{driver.user.username} accepted the ride and is heading to the pickup point.")
    events.notify_ride(ride, "accepted", driver=driver, offer_id=offer.id, fare=ride.fare)
    events.notify_driver(driver.id, ride, "answered", offer_id=offer.id)
    return ride


def decline_offer(offer: RideOffer, driver: DriverProfile) -> RideRequest:
    ride = offer.ride
    if offer.driver_id != driver.id:
        raise RideError("This offer is not yours.")
    if offer.status != "pending":
        raise RideError("This offer is no longer open.")
    offer.status = "declined"
    offer.responded_at = utcnow()
    ride.status = "searching"
    chat.close_for_driver(ride, driver.id, chat.REASON_DECLINED)
    events.notify_ride(ride, "declined", driver=driver, offer_id=offer.id)
    events.notify_driver(driver.id, ride, "answered", offer_id=offer.id)
    if ride.auto_dispatch:
        offer_next(ride)
    return ride


def start_ride(ride: RideRequest, driver: DriverProfile) -> None:
    if ride.driver_id != driver.id or ride.status != "accepted":
        raise RideError("This ride cannot be started.")
    ride.status = "in_progress"
    chat.note(ride, "Ride started - the rider has been picked up.")
    events.notify_ride(ride, "started")


def complete_ride(ride: RideRequest, driver: DriverProfile) -> None:
    if ride.driver_id != driver.id or ride.status != "in_progress":
        raise RideError("This ride cannot be completed.")
    ride.status = "completed"
    from payments.service import charge_ride  # the gateway is only touched here

    charge_ride(ride)  # cash -> nothing; card/wallet -> PaymentTransaction (may fail, never blocks)
    chat.close_all(ride, chat.REASON_COMPLETED)
    events.notify_ride(ride, "completed", fare=ride.fare, payment_status=ride.payment_status)


def cancel_ride(ride: RideRequest, by_user: User) -> None:
    if ride.is_terminal:
        raise RideError("This ride is already closed.")
    is_rider = ride.rider_id == by_user.id
    is_driver = ride.driver is not None and ride.driver.user_id == by_user.id
    if not (is_rider or is_driver):
        raise RideError("Unauthorized.")
    if ride.status == "in_progress" and not is_driver:
        raise RideError("A ride in progress can only be ended by the driver.")
    if is_driver and not is_rider:
        # Driver bails after accepting: hand the ride back to the search so the rider
        # gets the next best driver instead of a cancelled ride. The bail counts as a
        # non-acceptance for the driver's acceptance rate. The rider's pre-authorisation
        # stays in place for the next driver (topped up if they quote more).
        for offer in ride.offers:
            if offer.driver_id == ride.driver_id and offer.status == "accepted":
                offer.status = "declined"
                offer.responded_at = utcnow()
                ride.driver.offers_accepted = max(0, ride.driver.offers_accepted - 1)
        bailed = ride.driver
        chat.close_for_driver(ride, bailed.id, chat.REASON_DRIVER_LEFT)
        ride.driver_id = None
        ride.fare = None
        ride.payment_token = None
        ride.status = "searching"
        events.notify_ride(ride, "driver_left", driver=bailed)
        if ride.auto_dispatch:
            offer_next(ride)
        return
    for offer in ride.offers:
        if offer.status == "pending":
            events.notify_driver(offer.driver_id, ride, "withdrawn", offer_id=offer.id, reason="cancelled")
        if offer.status in ("ranked", "pending"):
            offer.status = "skipped"
    ride.status = "cancelled"
    _release(ride, "ride cancelled")
    chat.close_all(ride, chat.REASON_CANCELLED)
    events.notify_ride(ride, "cancelled")


def change_payment(ride: RideRequest, rider: User, payment_method_id) -> RideRequest:
    """
    Rider switches how an OPEN ride is paid (e.g. after a refused pre-authorisation).
    `payment_method_id`: None -> cash, DEFAULT_PAYMENT -> default method, int -> that method.
    Only while nobody is being asked; any existing hold is released, and with auto-dispatch
    the search resumes immediately (placing a new hold for the next driver).
    """
    if ride.rider_id != rider.id:
        raise RideError("Unauthorized.")
    if not ride.is_open:
        raise RideError("The payment method can only be changed while the ride is still open.")
    if ride.pending_offer is not None:
        raise RideError("A driver is being asked right now. Wait for the answer (or cancel) before changing the payment method.")
    from payments import service as payments

    method = None
    if payment_method_id == DEFAULT_PAYMENT:
        method = payments.default_method(rider)
    elif payment_method_id is not None:
        try:
            method = payments.get_owned(rider, payment_method_id)
        except payments.PaymentMethodError as exc:
            raise RideError(str(exc)) from None
        if method.is_expired:
            raise RideError(f"{method.display} has expired. Update it in your Account tab.")
    _release(ride, "payment method changed")
    ride.payment_method = method
    ride.preauth_status = None
    ride.preauth_amount = None
    ride.preauth_ref = None
    if ride.auto_dispatch:
        offer_next(ride, raise_on_payment_error=True)
    return ride


def rate_ride(ride: RideRequest, rider: User, stars: int) -> None:
    if ride.rider_id != rider.id:
        raise RideError("Unauthorized.")
    if ride.status != "completed":
        raise RideError("You can rate a ride once it is completed.")
    if ride.rider_rating is not None:
        raise RideError("You already rated this ride.")
    if stars not in (1, 2, 3, 4, 5):
        raise RideError("Rating must be between 1 and 5 stars.")
    ride.rider_rating = stars
    ride.driver.add_rating(stars)
