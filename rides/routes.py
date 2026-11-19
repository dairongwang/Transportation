"""
Ride hailing routes.

Rider                                   Driver
  GET/POST /rides/request                 GET/POST /drive              profile
  GET      /rides/<id>                    POST     /drive/location     post a position (landmark / coordinates)
                                          POST     /drive/availability  available <-> not available (+ optional GPS fix)
  POST     /rides/<id>/select/<offer>     POST     /drive/offers/<id>/accept | /decline
  POST     /rides/<id>/order              POST     /drive/rides/<id>/start | /complete
  POST     /rides/<id>/choose/<offer>     (select + order in one step)
  POST     /rides/<id>/payment            GET      /api/drivers/me/offers  pending offers (fetched by the
  POST     /rides/location-display                   dashboard when a push event arrives)
  GET      /events/rides/<id>             GET      /events/driver          Server-Sent Events (rides/events.py)
  POST     /rides/<id>/cancel
  POST     /rides/<id>/rate
  GET      /rides                         (history for both roles)
  POST     /rides/<id>/chat               rider <-> driver chat (see rides/chat_routes.py; JSON API there too)

JSON API (session cookie; POSTs need the X-CSRF-Token header)
  GET  /api/rides/search?pickup=..&dropoff=..   ranked drivers, nothing is created
  POST /api/rides                               {"pickup","dropoff","auto_dispatch"} -> ride
  GET  /api/rides/<id>                          ride + ranked offers + pre-authorisation
  POST /api/rides/<id>/select/<offer>           rider selects a driver (changeable, nothing sent)
  POST /api/rides/<id>/order                    finalise: ask the selected driver, place the hold
  POST /api/rides/<id>/choose/<offer>           select + order in one step
  GET  /api/drivers/me                          availability, position, whether riders can find me
  POST /api/drivers/me/location                 {"lat","lng","online"}   (the browser's GPS posts here)
"""

from __future__ import annotations

import hashlib

from flask import Response, abort, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from extensions import db
from models import DriverProfile, RideOffer, RideRequest

from . import bp, chat, events, geo, matching
from .geo import GeoError
from .matching import RideError


# ================================================================= helpers

def _ride_or_404(ride_id: int) -> RideRequest:
    return db.session.get(RideRequest, ride_id) or abort(404)


def _ride_loaded(ride_id: int) -> RideRequest:
    """
    The ride with everything _ride_json() touches loaded in 2 queries (ride + offers/drivers/users)
    instead of one query per offer, driver and user - which is what happens after a commit has
    expired the session's objects.
    """
    from sqlalchemy.orm import joinedload, selectinload

    opts = (selectinload(RideRequest.offers).joinedload(RideOffer.driver).joinedload(DriverProfile.user),
            joinedload(RideRequest.driver).joinedload(DriverProfile.user))
    ride = RideRequest.query.options(*opts).populate_existing().filter(RideRequest.id == ride_id).first()
    return ride or abort(404)


def _can_view(ride: RideRequest) -> bool:
    if ride.rider_id == current_user.id:
        return True
    drv = current_user.driver_profile
    if drv is None:
        return False
    return ride.driver_id == drv.id or any(o.driver_id == drv.id for o in ride.offers)


def _driver_or_none() -> DriverProfile | None:
    return current_user.driver_profile


def _require_driver() -> DriverProfile:
    drv = _driver_or_none()
    if drv is None:
        flash("Set up your driver profile first.", "info")
        abort(redirect(url_for("rides.drive")))
    return drv


def _ride_json(ride: RideRequest) -> dict:
    return {
        "id": ride.id,
        "status": ride.status,
        "auto_dispatch": ride.auto_dispatch,
        "selected_offer_id": ride.selected_offer.id if ride.selected_offer else None,
        "awaiting_order": ride.awaiting_order,
        "pickup": {"address": ride.pickup_address, "lat": ride.pickup_lat, "lng": ride.pickup_lng},
        "dropoff": {"address": ride.dropoff_address, "lat": ride.dropoff_lat, "lng": ride.dropoff_lng},
        "trip": {"distance_km": ride.trip_distance_km, "duration_min": ride.trip_duration_min},
        "fare": ride.fare,
        "estimated_fare": ride.estimated_fare,
        "payment_token": ride.payment_token,
        "payment": {
            "status": ride.payment_status,
            "method": None if ride.payment_method is None else {
                "id": ride.payment_method.id, "kind": ride.payment_method.kind, "display": ride.payment_method.display,
            },
            # Money reserved when the driver was picked (RIDE_PREAUTH_FACTOR x the quote, default +50 %)
            "preauth": None if ride.preauth_status is None else {
                "amount": ride.preauth_amount, "status": ride.preauth_status, "ref": ride.preauth_ref,
                "at": ride.preauth_at.isoformat() if ride.preauth_at else None,
            },
        },
        "driver": None if ride.driver is None else {
            "id": ride.driver.id, "username": ride.driver.user.username, "vehicle": ride.driver.vehicle,
        },
        "offers": [
            {
                "id": o.id, "rank": o.rank, "status": o.status, "score": o.score,
                "driver": {"id": o.driver.id, "username": o.driver.user.username, "vehicle": o.driver.vehicle},
                "distance_km": o.distance_km, "eta_min": o.eta_min, "price": o.price,
                "preauth_amount": _preauth_amount(o.price),
                "rating": o.rating, "acceptance_rate": o.acceptance_rate,
            }
            for o in ride.offers
        ],
        "chat": _chat_summary(ride),
        "created_at": ride.created_at.isoformat(),
    }


def _chat_summary(ride: RideRequest) -> dict | None:
    """The caller's chat room on this ride (None before the order is placed)."""
    s = chat.summary(ride, current_user)
    if s is None:
        return None
    return {**s, "url": url_for("rides.api_chat", ride_id=ride.id)}


def _preauth_amount(estimate: float) -> float:
    from payments import service as payments

    return payments.preauth_amount(estimate)


def _preauth_factor() -> float:
    from payments import service as payments

    return payments.preauth_factor()


def driver_status(drv: DriverProfile | None) -> dict:
    """Everything the driver card (dashboard / Drive page) needs to show and to decide."""
    stale = int(current_app.config["DRIVER_LOCATION_STALE_SECONDS"])
    pending = 0
    if drv is not None:
        pending = RideOffer.query.filter_by(driver_id=drv.id, status="pending").count()
    visible, reason = drv.availability(stale) if drv is not None else (False, "no driver profile")
    return {
        "driver": drv, "stale_seconds": stale, "radius_km": current_app.config["RIDE_SEARCH_RADIUS_KM"],
        "visible": visible, "reason": reason, "pending_count": pending,
        "location_age": drv.location_age_seconds if drv is not None else None,
    }


LOCATION_DISPLAY_KEY = "location_display"  # session: "landmark" (default) | "gps"


def location_display() -> str:
    return "gps" if session.get(LOCATION_DISPLAY_KEY) == "gps" else "landmark"


def place(label: str | None, lat: float | None, lng: float | None) -> str:
    """Template helper: a place rendered the way the user chose (landmark name or GPS coordinates)."""
    return geo.describe(label, lat, lng, location_display())


def pending_offers_for(drv: DriverProfile | None) -> list[RideOffer]:
    """The driver's open ride requests, after timing out stale ones."""
    if drv is None:
        return []
    if matching.expire_all_stale_offers():
        db.session.commit()
    return (RideOffer.query.filter_by(driver_id=drv.id, status="pending")
            .order_by(RideOffer.offered_at.asc()).all())


def offers_version(offers: list[RideOffer]) -> str:
    """Changes whenever the set of pending offers changes (what the poller compares)."""
    raw = "|".join(f"{o.id}:{o.ride.status}:{o.expires_at.isoformat() if o.expires_at else ''}" for o in offers)
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


@bp.app_context_processor
def _inject():
    return {"landmark_names": geo.landmark_names, "maps_backend": geo.backend_name,
            "preauth_amount": _preauth_amount, "preauth_factor": _preauth_factor, "driver_status": driver_status,
            "place": place, "location_display": location_display, "pending_offers_for": pending_offers_for,
            "offers_version": offers_version, "is_coords": geo.looks_like_coords, "chat_unread": _chat_unread}


def _chat_unread(ride: RideRequest) -> int:
    """Template helper: unread chat messages for the logged-in user on this ride."""
    return chat.unread_for_ride(ride, current_user) if current_user.is_authenticated else 0


@bp.route("/rides/location-display", methods=["POST"])
@login_required
def set_location_display():
    """'Show places as' preference: landmark names or GPS coordinates (kept in the session)."""
    mode = request.form.get("mode", "landmark")
    session[LOCATION_DISPLAY_KEY] = "gps" if mode == "gps" else "landmark"
    nxt = request.form.get("next", "")
    if not (nxt.startswith("/") and not nxt.startswith("//")):
        nxt = url_for("dashboard")
    return redirect(nxt)


# ================================================================= rider pages

def _hold_note(ride: RideRequest) -> str:
    if not ride.has_hold:
        return ""
    return (f" {current_app.config.get('PAYMENT_CURRENCY', 'USD')} {ride.preauth_amount:.2f} "
            f"(estimate + {_preauth_factor() * 100 - 100:.0f}%) has been reserved on {ride.payment_method.display}.")


def _parse_payment_choice(raw: str | None):
    """Form value -> create_ride() argument: '' / 'default' -> default method, 'cash' -> None, '<id>' -> id."""
    raw = (raw or "").strip().lower()
    if raw in ("", "default"):
        return matching.DEFAULT_PAYMENT
    if raw == "cash":
        return None
    try:
        return int(raw)
    except ValueError:
        raise RideError("Invalid payment method.") from None


@bp.route("/rides/request", methods=["GET", "POST"])
@login_required
def request_ride():
    from payments import service as payments

    if not current_user.can_ride:
        flash("Your account is seller-only and cannot request rides.", "error")
        return redirect(url_for("dashboard"))

    methods = payments.active_methods(current_user)
    default = next((m for m in methods if m.is_default), None)
    form = {"pickup": "", "dropoff": "", "auto_dispatch": "", "payment": str(default.id) if default else "cash"}
    if request.method == "POST":
        form = {
            "pickup": request.form.get("pickup", "").strip()[:200],
            "dropoff": request.form.get("dropoff", "").strip()[:200],
            "auto_dispatch": request.form.get("auto_dispatch", ""),
            "payment": request.form.get("payment", "").strip()[:20],
        }
        try:
            ride = matching.create_ride(
                current_user, form["pickup"], form["dropoff"], auto_dispatch=bool(form["auto_dispatch"]),
                payment_method_id=_parse_payment_choice(form["payment"]),
            )
        except (RideError, GeoError) as exc:
            db.session.rollback()
            flash(str(exc), "error")
            return render_template("rides/request.html", form=form, methods=methods), 400
        n = len(ride.offers)
        if ride.status == "no_drivers":
            flash("No drivers are available near your pickup right now. Try again in a moment.", "warning")
        elif ride.auto_dispatch:
            flash(f"Found {n} driver(s) nearby. Asking the best match first...{_hold_note(ride)}", "success")
        else:
            flash(f"Found {n} driver(s) nearby, ranked for you. Select one, then press Order"
                  + (f" - {_preauth_factor() * 100 - 100:.0f}% above their quote will be reserved on "
                     f"{ride.payment_method.display} until the ride ends." if ride.payment_method else "."), "success")
        return redirect(url_for("rides.ride_detail", ride_id=ride.id))
    return render_template("rides/request.html", form=form, methods=methods)


@bp.route("/rides/<int:ride_id>")
@login_required
def ride_detail(ride_id: int):
    ride = _ride_or_404(ride_id)
    if not _can_view(ride):
        abort(403)
    if matching.expire_stale_offers(ride):
        db.session.commit()
    from .simulator import is_bot

    bots_pending = ride.pending_offer is not None and is_bot(ride.pending_offer.driver)
    bot_driving = ride.driver is not None and is_bot(ride.driver) and ride.status in ("accepted", "in_progress")
    rider_methods = []
    if ride.rider_id == current_user.id and (ride.payment_status == "failed" or ride.is_open):
        from payments import service as payments

        rider_methods = payments.active_methods(current_user)
    room = chat.room_for(ride, current_user)
    chat_messages = []
    if room is not None:
        chat_messages = chat.history(room)
        chat.mark_read(room, current_user)  # opening the page = reading the chat
        db.session.commit()
    return render_template(
        "rides/detail.html", ride=ride, is_rider=ride.rider_id == current_user.id,
        bots_pending=bots_pending, bot_driving=bot_driving, rider_methods=rider_methods,
        can_change_payment=ride.rider_id == current_user.id and ride.is_open and ride.pending_offer is None,
        chat_room=room, chat_messages=chat_messages,
        chat_quick_replies=chat.quick_replies(room.role_of(current_user)) if room is not None and room.is_open else (),
        chat_max_length=chat.max_length(),
    )


def _own_open_offer(ride_id: int, offer_id: int) -> tuple[RideRequest, RideOffer]:
    ride = _ride_or_404(ride_id)
    if ride.rider_id != current_user.id:
        abort(403)
    offer = db.session.get(RideOffer, offer_id) or abort(404)
    return ride, offer


@bp.route("/rides/<int:ride_id>/select/<int:offer_id>", methods=["POST"])
@login_required
def select_driver(ride_id: int, offer_id: int):
    """Step 1: pick (or re-pick) a driver. Nothing is sent or reserved until Order."""
    ride, offer = _own_open_offer(ride_id, offer_id)
    try:
        matching.select_driver(ride, offer)
        db.session.commit()
        reserve = (f" Ordering will reserve ${_preauth_amount(offer.price):.2f} on {ride.payment_method.display}."
                   if ride.payment_method else "")
        flash(f"Selected {offer.driver.user.username} ({offer.driver.vehicle}, ${offer.price:.2f}). "
              f"Press Order to confirm, or select a different driver.{reserve}", "info")
    except RideError as exc:
        db.session.commit()  # may have marked the driver as skipped
        flash(str(exc), "error")
    return redirect(url_for("rides.ride_detail", ride_id=ride.id))


@bp.route("/rides/<int:ride_id>/order", methods=["POST"])
@login_required
def place_order(ride_id: int):
    """Step 2: finalise the order with the selected driver (places the hold, asks the driver)."""
    ride = _ride_or_404(ride_id)
    if ride.rider_id != current_user.id:
        abort(403)
    try:
        offer = matching.place_order(ride)
        db.session.commit()
        flash(f"Order placed with {offer.driver.user.username}. Waiting for them to accept...{_hold_note(ride)}", "success")
    except RideError as exc:
        db.session.commit()  # keeps a refused-hold record / skipped driver
        flash(str(exc), "error")
    return redirect(url_for("rides.ride_detail", ride_id=ride.id))


@bp.route("/rides/<int:ride_id>/choose/<int:offer_id>", methods=["POST"])
@login_required
def choose_driver(ride_id: int, offer_id: int):
    """Select + order in one step."""
    ride, offer = _own_open_offer(ride_id, offer_id)
    try:
        matching.offer_to(ride, offer)
        db.session.commit()
        flash(f"Order placed with {offer.driver.user.username}. Waiting for them to accept...{_hold_note(ride)}", "success")
    except RideError as exc:
        db.session.commit()  # offer_to may have marked the driver as skipped / recorded the refused hold
        flash(str(exc), "error")
    return redirect(url_for("rides.ride_detail", ride_id=ride.id))


@bp.route("/rides/<int:ride_id>/payment", methods=["POST"])
@login_required
def change_payment(ride_id: int):
    """Switch how an open ride is paid (used after a refused pre-authorisation)."""
    ride = _ride_or_404(ride_id)
    if ride.rider_id != current_user.id:
        abort(403)
    try:
        matching.change_payment(ride, current_user, _parse_payment_choice(request.form.get("payment")))
        db.session.commit()
        what = ride.payment_method.display if ride.payment_method else "cash"
        flash(f"This ride will be paid with {what}.{_hold_note(ride)}"
              + (" Pick a driver from the list." if ride.pending_offer is None and ride.is_open else ""), "success")
    except RideError as exc:
        db.session.commit()  # keep the refused-hold record
        flash(str(exc), "error")
    return redirect(url_for("rides.ride_detail", ride_id=ride.id))


@bp.route("/rides/<int:ride_id>/cancel", methods=["POST"])
@login_required
def cancel_ride(ride_id: int):
    ride = _ride_or_404(ride_id)
    if not _can_view(ride):
        abort(403)
    try:
        matching.cancel_ride(ride, current_user)
        db.session.commit()
        flash("Ride cancelled." if ride.status == "cancelled" else "You left the ride; it is being re-dispatched.", "info")
    except RideError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("rides.ride_detail", ride_id=ride.id))


@bp.route("/rides/<int:ride_id>/rate", methods=["POST"])
@login_required
def rate_ride(ride_id: int):
    ride = _ride_or_404(ride_id)
    try:
        stars = int(request.form.get("stars", ""))
    except ValueError:
        stars = 0
    try:
        matching.rate_ride(ride, current_user, stars)
        db.session.commit()
        flash(f"Thanks! You rated {ride.driver.user.username} {stars} star(s).", "success")
    except RideError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("rides.ride_detail", ride_id=ride.id))


@bp.route("/rides")
@login_required
def my_rides():
    as_rider = RideRequest.query.filter_by(rider_id=current_user.id).order_by(RideRequest.created_at.desc()).all()
    drv = _driver_or_none()
    as_driver = []
    if drv is not None:
        as_driver = RideRequest.query.filter_by(driver_id=drv.id).order_by(RideRequest.created_at.desc()).all()
    return render_template("rides/list.html", as_rider=as_rider, as_driver=as_driver)


# ================================================================= driver pages

@bp.route("/drive", methods=["GET", "POST"])
@login_required
def drive():
    if current_user.role == "buyer":
        flash("Your account is buyer-only and cannot drive. Register a seller/both account to drive.", "error")
        return redirect(url_for("dashboard"))
    drv = _driver_or_none()
    if request.method == "POST":  # create / update profile
        from background.service import can_drive

        if not can_drive(current_user):
            flash("Driving needs a driver background check: add your driving licence on the Background check page.", "warning")
            return redirect(url_for("background.check"))
        try:
            vehicle = request.form.get("vehicle", "").strip()[:80] or "Sedan"
            plate = request.form.get("plate", "").strip()[:20] or None
            base_fare = float(request.form.get("base_fare", 2.5))
            per_km = float(request.form.get("per_km_rate", 1.2))
            per_min = float(request.form.get("per_min_rate", 0.25))
            min_fare = float(request.form.get("min_fare", 5.0))
            if min(base_fare, per_km, per_min, min_fare) < 0 or max(base_fare, per_km, per_min, min_fare) > 1000:
                raise ValueError
        except ValueError:
            flash("Please enter valid, non-negative prices.", "error")
            return redirect(url_for("rides.drive"))
        if drv is None:
            drv = DriverProfile(user_id=current_user.id)
            db.session.add(drv)
        drv.vehicle, drv.plate = vehicle, plate
        drv.base_fare, drv.per_km_rate, drv.per_min_rate, drv.min_fare = base_fare, per_km, per_min, min_fare
        db.session.commit()
        flash("Driver profile saved.", "success")
        return redirect(url_for("rides.drive"))

    if matching.expire_all_stale_offers():
        db.session.commit()
    pending = active = history = []
    if drv is not None:
        pending = [o for o in RideOffer.query.filter_by(driver_id=drv.id, status="pending").all()]
        active = RideRequest.query.filter(
            RideRequest.driver_id == drv.id, RideRequest.status.in_(("accepted", "in_progress"))
        ).all()
        history = (RideRequest.query.filter_by(driver_id=drv.id)
                   .filter(RideRequest.status.in_(("completed", "cancelled")))
                   .order_by(RideRequest.created_at.desc()).limit(10).all())
    return render_template("rides/drive.html", driver=drv, pending=pending, active=active, history=history,
                           stale_seconds=current_app.config["DRIVER_LOCATION_STALE_SECONDS"])


def _apply_location(drv: DriverProfile, lat_s, lng_s, landmark: str | None, online) -> None:
    from clock import utcnow

    if landmark:
        if landmark not in geo.LANDMARKS:
            raise GeoError("Unknown landmark.")
        drv.lat, drv.lng = geo.LANDMARKS[landmark]
        drv.location_updated_at = utcnow()
    elif lat_s not in (None, "") or lng_s not in (None, ""):
        try:
            lat, lng = float(lat_s), float(lng_s)
        except (TypeError, ValueError):
            raise GeoError("Latitude / longitude must be numbers.") from None
        if not (-90 <= lat <= 90 and -180 <= lng <= 180):
            raise GeoError("Coordinates are out of range.")
        drv.lat, drv.lng = lat, lng
        drv.location_updated_at = utcnow()
    if online is not None:
        from background.service import can_drive

        if online and not can_drive(drv.user):
            raise GeoError("Your background check does not cover driving yet - add your driving licence on the Background check page.")
        if online and not drv.has_location:
            raise GeoError("Post a position before going online.")
        drv.is_online = bool(online)


@bp.route("/drive/location", methods=["POST"])
@login_required
def drive_location():
    drv = _require_driver()
    online_raw = request.form.get("online")
    online = None if online_raw is None else online_raw in ("1", "true", "on", "yes")
    try:
        _apply_location(drv, request.form.get("lat"), request.form.get("lng"), request.form.get("landmark") or None, online)
        db.session.commit()
        flash("Position updated." + (" You are available to drive." if drv.is_online else " You are not available."), "success")
    except GeoError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(_back_to())


def _back_to(default: str = "rides.drive"):
    """Redirect target for the driver card, which lives on the dashboard and on the Drive page."""
    return url_for("dashboard") if request.form.get("next") == "dashboard" else url_for(default)


@bp.route("/drive/availability", methods=["POST"])
@login_required
def drive_availability():
    """
    The "Available to drive" switch. `online=1|0`; an optional GPS fix (lat/lng, filled in by
    static/geolocation.js) or a landmark can come along so one click does both.
    """
    drv = _require_driver()
    online = request.form.get("online", "") in ("1", "true", "on", "yes")
    try:
        _apply_location(drv, request.form.get("lat"), request.form.get("lng"), request.form.get("landmark") or None, online)
        db.session.commit()
        if online:
            flash("You are available to drive. Riders searching within "
                  f"{current_app.config['RIDE_SEARCH_RADIUS_KM']:g} km of your position will see you in their list.", "success")
        else:
            flash("You are no longer available to drive.", "info")
    except GeoError as exc:
        db.session.rollback()
        flash(f"{exc} Use the GPS button or pick a landmark first.", "error")
    return redirect(_back_to())


@bp.route("/drive/offers/<int:offer_id>/<action>", methods=["POST"])
@login_required
def respond_offer(offer_id: int, action: str):
    drv = _require_driver()
    offer = db.session.get(RideOffer, offer_id) or abort(404)
    if action not in ("accept", "decline"):
        abort(404)
    try:
        if action == "accept":
            ride = matching.accept_offer(offer, drv)
            db.session.commit()
            flash(f"Ride #{ride.id} accepted. Dummy payment token: {ride.payment_token}", "success")
            return redirect(url_for("rides.ride_detail", ride_id=ride.id))
        matching.decline_offer(offer, drv)
        db.session.commit()
        flash(f"Ride request #{offer.ride_id} declined.", "info")
    except RideError as exc:
        db.session.commit()  # accept_offer may have expired offers before raising
        flash(str(exc), "error")
    return redirect(_back_to())


@bp.route("/drive/rides/<int:ride_id>/<action>", methods=["POST"])
@login_required
def driver_ride_action(ride_id: int, action: str):
    drv = _require_driver()
    ride = _ride_or_404(ride_id)
    try:
        if action == "start":
            matching.start_ride(ride, drv)
            flash("Ride started. Drive safely!", "success")
        elif action == "complete":
            matching.complete_ride(ride, drv)
            flash(f"Ride completed. ${ride.fare:.2f} settled with dummy token {ride.payment_token}.", "success")
        else:
            abort(404)
        db.session.commit()
    except RideError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("rides.ride_detail", ride_id=ride.id))


# ================================================================= JSON API

@bp.route("/api/rides/search")
@login_required
def api_search():
    pickup_text = request.args.get("pickup", "")
    dropoff_text = request.args.get("dropoff", "")
    try:
        geocoder = geo.get_geocoder()
        pickup, dropoff = geocoder.geocode(pickup_text), geocoder.geocode(dropoff_text)
    except GeoError as exc:
        return jsonify(error=str(exc)), 400
    trip, ranked = matching.search_drivers(pickup, dropoff, exclude_user_id=current_user.id)
    return jsonify(
        pickup=pickup.as_dict(), dropoff=dropoff.as_dict(), trip=trip.as_dict(),
        weights=matching.normalise_weights(current_app.config.get("RIDE_RANK_WEIGHTS")),
        radius_km=current_app.config["RIDE_SEARCH_RADIUS_KM"],
        drivers=[{"rank": i, **c.as_dict()} for i, c in enumerate(ranked, start=1)],
    )


@bp.route("/api/rides", methods=["POST"])
@login_required
def api_create_ride():
    data = request.get_json(silent=True) or {}
    try:
        # payment_method_id: omitted -> default method (cash if none), null/"cash" -> cash, int -> that method
        pm = data.get("payment_method_id", matching.DEFAULT_PAYMENT)
        if pm in (None, "cash"):
            pm = None
        elif pm != matching.DEFAULT_PAYMENT:
            pm = int(pm)
        # The response is built from the objects just created and committed: keep them loaded
        # instead of letting the commit expire them (which would reload every offer, driver and
        # user one by one). Nothing else can have changed these brand-new rows in between.
        session = db.session()
        keep, session.expire_on_commit = session.expire_on_commit, False
        try:
            ride = matching.create_ride(
                current_user, str(data.get("pickup", "")), str(data.get("dropoff", "")),
                auto_dispatch=bool(data.get("auto_dispatch", True)), payment_method_id=pm,
            )
        finally:
            session.expire_on_commit = keep
    except (TypeError, ValueError):
        return jsonify(error="payment_method_id must be an integer, null or \"cash\"."), 400
    except (RideError, GeoError) as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 400
    return jsonify(_ride_json(ride)), 201


def _api_ride_action(ride: RideRequest, action):
    try:
        action()
        db.session.commit()
    except RideError as exc:
        db.session.commit()
        return jsonify(error=str(exc), ride=_ride_json(ride)), 409
    return jsonify(_ride_json(ride))


@bp.route("/api/rides/<int:ride_id>/select/<int:offer_id>", methods=["POST"])
@login_required
def api_select_driver(ride_id: int, offer_id: int):
    ride, offer = _own_open_offer(ride_id, offer_id)
    return _api_ride_action(ride, lambda: matching.select_driver(ride, offer))


@bp.route("/api/rides/<int:ride_id>/order", methods=["POST"])
@login_required
def api_place_order(ride_id: int):
    ride = _ride_or_404(ride_id)
    if ride.rider_id != current_user.id:
        abort(403)
    return _api_ride_action(ride, lambda: matching.place_order(ride))


@bp.route("/api/rides/<int:ride_id>/choose/<int:offer_id>", methods=["POST"])
@login_required
def api_choose_driver(ride_id: int, offer_id: int):
    ride, offer = _own_open_offer(ride_id, offer_id)
    return _api_ride_action(ride, lambda: matching.offer_to(ride, offer))


@bp.route("/api/rides/<int:ride_id>")
@login_required
def api_ride(ride_id: int):
    ride = _ride_loaded(ride_id)
    if not _can_view(ride):
        abort(403)
    if matching.expire_stale_offers(ride):
        db.session.commit()
        ride = _ride_loaded(ride_id)
    return jsonify(_ride_json(ride))


def _driver_json(drv: DriverProfile) -> dict:
    st = driver_status(drv)
    return {
        "driver_id": drv.id, "online": drv.is_online, "lat": drv.lat, "lng": drv.lng,
        "location_updated_at": drv.location_updated_at.isoformat() if drv.location_updated_at else None,
        "location_age_seconds": st["location_age"], "visible_to_riders": st["visible"], "reason": st["reason"],
        "pending_offers": st["pending_count"], "search_radius_km": st["radius_km"], "stale_after_seconds": st["stale_seconds"],
    }


@bp.route("/api/drivers/me")
@login_required
def api_driver_me():
    drv = _driver_or_none()
    if drv is None:
        return jsonify(error="No driver profile. Create one at /drive first."), 404
    return jsonify(_driver_json(drv))


# ================================================================= push (SSE)

def _sse(channel: str, hello: dict) -> Response:
    resp = Response(events.stream(channel, hello), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"  # nginx: do not buffer the stream
    resp.headers["Connection"] = "keep-alive"
    return resp


@bp.route("/events/driver")
@login_required
def events_driver():
    """Push channel for the logged-in driver: new / withdrawn ride requests."""
    drv = _driver_or_none()
    if drv is None:
        return jsonify(error="No driver profile. Create one at /drive first."), 404
    offers = pending_offers_for(drv)
    return _sse(events.driver_channel(drv.id), {"driver_id": drv.id, "version": offers_version(offers), "count": len(offers)})


@bp.route("/events/rides/<int:ride_id>")
@login_required
def events_ride(ride_id: int):
    """Push channel for one ride: driver answered / expired / started / completed / cancelled."""
    ride = _ride_or_404(ride_id)
    if not _can_view(ride):
        abort(403)
    return _sse(events.ride_channel(ride.id), {"ride_id": ride.id, "status": ride.status})


@bp.route("/api/drivers/me/offers")
@login_required
def api_driver_offers():
    """
    Fetched by static/incoming.js when the push channel signals a change: the driver's pending
    ride requests as JSON plus the rendered fragment (templates/rides/_incoming_offers.html).
    """
    drv = _driver_or_none()
    if drv is None:
        return jsonify(error="No driver profile. Create one at /drive first."), 404
    offers = pending_offers_for(drv)
    return jsonify(
        version=offers_version(offers), count=len(offers),
        offers=[{
            "id": o.id, "ride_id": o.ride_id, "rank": o.rank, "price": o.price, "distance_km": o.distance_km,
            "eta_min": o.eta_min, "expires_at": o.expires_at.isoformat() if o.expires_at else None,
            "rider": o.ride.rider.username,
            "pickup": {"label": o.ride.pickup_address, "lat": o.ride.pickup_lat, "lng": o.ride.pickup_lng,
                       "display": place(o.ride.pickup_address, o.ride.pickup_lat, o.ride.pickup_lng)},
            "dropoff": {"label": o.ride.dropoff_address, "lat": o.ride.dropoff_lat, "lng": o.ride.dropoff_lng,
                        "display": place(o.ride.dropoff_address, o.ride.dropoff_lat, o.ride.dropoff_lng)},
        } for o in offers],
        html=render_template("rides/_incoming_offers.html", offers=offers, next_page=request.args.get("next", "dashboard")),
    )


@bp.route("/api/drivers/me/location", methods=["POST"])
@login_required
def api_driver_location():
    drv = _driver_or_none()
    if drv is None:
        return jsonify(error="No driver profile. Create one at /drive first."), 400
    data = request.get_json(silent=True) or {}
    try:
        _apply_location(drv, data.get("lat"), data.get("lng"), data.get("landmark"), data.get("online"))
        db.session.commit()
    except GeoError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 400
    return jsonify(_driver_json(drv))
