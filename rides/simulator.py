"""
Demo driver fleet ("driver bots") - a stub for real drivers with phones.

Real drivers would keep their position fresh and answer offers from the driver page or
the JSON API. In development nobody is logged in as six different drivers at once, so:

  seed_demo_drivers()   creates DUMMY driver accounts (dummy_driver_1..N) spread over the
                        demo city with different prices, ratings and acceptance histories
  auto_respond()        every bot with a pending offer answers it: it accepts with the
                        probability of its own acceptance rate, otherwise declines (and
                        auto-dispatch moves on to the next ranked driver)
  advance_rides()       bots move their accepted rides to in_progress, then to completed
  shuffle_fleet()       re-randomise bot positions and put every bot online again
  chat_reply()          what a bot answers in the rider <-> driver chat (rides/chat.py)

All of this is reachable from the dev tools (POST /dev/rides/...) and the ride page.
"""

from __future__ import annotations

import random

from clock import utcnow
from extensions import db
from models import DriverProfile, RideOffer, RideRequest, User

from . import geo, matching

BOT_PREFIX = "dummy_driver_"
DUMMY_DRIVER_PASSWORD = "dummyDriverPass123"  # DUMMY PASSWORD (public placeholder)

# (vehicle, plate, base_fare, per_km, per_min, rating_sum, rating_count, offers_received, offers_accepted, landmark)
DEMO_FLEET = [
    ("Toyota Prius", "DUMMY-001", 2.0, 1.00, 0.20, 4.9 * 120, 120, 200, 190, "Downtown"),
    ("Honda Civic", "DUMMY-002", 2.5, 1.10, 0.25, 4.6 * 80, 80, 150, 110, "Central Station"),
    ("Tesla Model 3", "DUMMY-003", 4.0, 1.60, 0.35, 4.8 * 300, 300, 400, 380, "Old Town"),
    ("Ford Transit (XL)", "DUMMY-004", 5.0, 1.90, 0.40, 4.3 * 40, 40, 90, 45, "Stadium"),
    ("VW Golf", "DUMMY-005", 2.2, 0.95, 0.20, 3.9 * 25, 25, 60, 58, "University"),
    ("Hyundai Ioniq", "DUMMY-006", 3.0, 1.30, 0.30, 0.0, 0, 0, 0, "Mall"),  # brand-new driver
    ("Kia Niro", "DUMMY-007", 2.8, 1.20, 0.25, 4.7 * 60, 60, 100, 70, "Harbor"),
    ("Mercedes E-Class", "DUMMY-008", 6.0, 2.20, 0.50, 5.0 * 15, 15, 30, 29, "Airport"),
]


def is_bot(driver: DriverProfile) -> bool:
    return driver.user.username.startswith(BOT_PREFIX)


def bots() -> list[DriverProfile]:
    return [d for d in DriverProfile.query.join(User).filter(User.username.like(f"{BOT_PREFIX}%")).all()]


def seed_demo_drivers(rng: random.Random | None = None) -> int:
    """Create the demo fleet if it does not exist yet. Returns the number created."""
    rng = rng or random.Random(42)
    created = 0
    for i, (vehicle, plate, base, per_km, per_min, rsum, rcount, offered, accepted, landmark) in enumerate(DEMO_FLEET, 1):
        username = f"{BOT_PREFIX}{i}"
        if User.query.filter_by(username=username).first():
            continue
        user = User(username=username, email=f"dummy.driver{i}@example.com", role="seller",
                    display_name=f"Dummy Driver {i}")
        user.set_password(DUMMY_DRIVER_PASSWORD)
        db.session.add(user)
        db.session.flush()
        lat, lng = geo.LANDMARKS[landmark]
        lat, lng = geo.offset_point(lat, lng, rng.uniform(-0.8, 0.8), rng.uniform(-0.8, 0.8))
        db.session.add(
            DriverProfile(
                user_id=user.id, vehicle=vehicle, plate=plate, base_fare=base, per_km_rate=per_km,
                per_min_rate=per_min, min_fare=5.0, is_online=True, lat=lat, lng=lng,
                location_updated_at=utcnow(), rating_sum=rsum, rating_count=rcount,
                offers_received=offered, offers_accepted=accepted,
            )
        )
        # Bots are DUMMY people with a passed driver background check (licence numbers are fake).
        from datetime import date

        from background.service import seed_clear_check

        seed_clear_check(user, package="driver", first="Dummy", last=f"Driver {i}", dob=date(1985, 1, 1),
                         licence=f"DUMMY-DL-{i:04d}", region="Demo State")
        created += 1
    db.session.commit()
    return created


def refresh_fleet_positions() -> int:
    """Keep bot positions 'fresh' so they are not filtered out as stale. Returns count."""
    n = 0
    for d in bots():
        if d.is_online and d.has_location:
            d.location_updated_at = utcnow()
            n += 1
    db.session.commit()
    return n


def shuffle_fleet(rng: random.Random | None = None) -> int:
    rng = rng or random.Random()
    n = 0
    for d in bots():
        lat, lng = geo.DEMO_CITY_CENTER
        r = rng.uniform(0, geo.DEMO_CITY_RADIUS_KM)
        d.lat, d.lng = geo.offset_point(lat, lng, rng.uniform(-r, r), rng.uniform(-r, r))
        d.location_updated_at = utcnow()
        d.is_online = True
        n += 1
    db.session.commit()
    return n


def auto_respond(ride_id: int | None = None, rng: random.Random | None = None) -> dict:
    """Bots answer their pending offers. Returns a summary for flashing / JSON."""
    rng = rng or random.Random()
    matching.expire_all_stale_offers()
    summary = {"accepted": [], "declined": [], "rides_no_drivers": []}
    q = RideOffer.query.filter_by(status="pending")
    if ride_id is not None:
        q = q.filter_by(ride_id=ride_id)
    # Handle one ride at a time: a decline may create a new pending offer for the same ride.
    rides = {o.ride for o in q.all()}
    for ride in sorted(rides, key=lambda r: r.id):
        for _ in range(len(ride.offers) + 1):  # bounded cascade
            offer = ride.pending_offer
            if offer is None or not is_bot(offer.driver):
                break
            driver = offer.driver
            if rng.random() < driver.acceptance_rate:
                matching.accept_offer(offer, driver)
                _chat_greeting(ride, driver)
                summary["accepted"].append({"ride": ride.id, "driver": driver.user.username})
                break
            matching.decline_offer(offer, driver)
            summary["declined"].append({"ride": ride.id, "driver": driver.user.username})
        if ride.status == "no_drivers":
            summary["rides_no_drivers"].append(ride.id)
    db.session.commit()
    return summary


def advance_rides(ride_id: int | None = None) -> dict:
    """Bots drive: accepted -> in_progress -> completed (one step per call)."""
    summary = {"started": [], "completed": []}
    q = RideRequest.query.filter(RideRequest.status.in_(("accepted", "in_progress")))
    if ride_id is not None:
        q = q.filter_by(id=ride_id)
    for ride in q.all():
        if ride.driver is None or not is_bot(ride.driver):
            continue
        if ride.status == "accepted":
            matching.start_ride(ride, ride.driver)
            summary["started"].append(ride.id)
        elif ride.status == "in_progress":
            matching.complete_ride(ride, ride.driver)
            summary["completed"].append(ride.id)
    db.session.commit()
    return summary


# ------------------------------------------------------------------ chat (rides/chat.py)

def _chat_greeting(ride: RideRequest, driver: DriverProfile) -> None:
    """A bot that accepted says hello in the chat, like a real driver would."""
    from flask import current_app

    from . import chat

    if not current_app.config.get("RIDE_CHAT_BOT_REPLIES", True):
        return
    room = chat.room_between(ride, driver.id)
    if room is None or not room.is_open:
        return
    offer = next((o for o in ride.offers if o.driver_id == driver.id), None)
    eta = f" I'll be there in about {max(1, round(offer.eta_min))} min." if offer else ""
    plate = f" (plate {driver.plate})" if driver.plate else ""
    chat._add(room, f"Hi {ride.rider.username}! I'm on my way in a {driver.vehicle}{plate}.{eta}",
              sender=driver.user)


def chat_reply(room, msg) -> str:
    """Canned answer of a demo driver bot to the rider's chat message (keyword based, DUMMY)."""
    driver = room.driver
    text = (msg.body or "").lower()
    ride = room.ride
    plate = f", plate {driver.plate}" if driver.plate else ""
    if msg.kind == "location":
        return "Got your location, thanks! I'll pick you up right there."
    if any(w in text for w in ("where", "which car", "what car", "find you", "see you")):
        return f"I'm in a {driver.vehicle}{plate}. I'll stop right at the pickup point ({ride.pickup_address})."
    if any(w in text for w in ("late", "minute", "min ", "wait", "hold on", "coming")):
        return "No problem, I'll wait for you."
    if any(w in text for w in ("entrance", "door", "corner", "gate", "front", "outside", "meet")):
        return "Sounds good - see you there."
    if any(w in text for w in ("thank", "thx", "cheers")):
        return "You're welcome!"
    if ride.status == "offered":
        return "Hi! I've got your request - give me a moment to accept it."
    if ride.status == "in_progress":
        return "👍"
    return "OK, see you soon!"
