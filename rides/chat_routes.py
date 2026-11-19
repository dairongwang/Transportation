"""
Rider <-> driver chat routes (service logic in rides/chat.py).

Page (works without JavaScript; static/chat.js upgrades it to live, in-place messaging)
  POST /rides/<id>/chat                 form: body   (or lat + lng to share a location)

JSON API (session cookie; POSTs need the X-CSRF-Token header)
  GET  /api/rides/<id>/chat?after=<id>  the caller's room on this ride + messages newer than <id>
  POST /api/rides/<id>/chat             {"body": "..."}  or  {"lat": .., "lng": .., "body": optional caption}
  POST /api/rides/<id>/chat/read        {"last_id": <id>}  (omit -> everything read)

Live delivery: new messages are pushed to both participants over GET /events/account
(event "chat"), the stream every logged-in page already has open - see rides/chat.py.
"""

from __future__ import annotations

from flask import abort, current_app, flash, jsonify, redirect, request, url_for
from flask_login import current_user, login_required

from extensions import db
from throttle import limiter

from . import bp, chat
from .chat import ChatError
from .routes import _can_view, _ride_or_404


def _chat_limit():
    return current_app.config.get("RIDE_CHAT_RATE_LIMIT", "20 per minute")


def _per_user_key() -> str:
    return f"chat-user:{current_user.get_id() if current_user.is_authenticated else request.remote_addr}"


chat_send_limit = limiter.limit(_chat_limit, key_func=_per_user_key, methods=["POST"],
                                error_message="You are sending messages too quickly. Wait a moment.")


def _visible_ride(ride_id: int):
    ride = _ride_or_404(ride_id)
    if not _can_view(ride):
        abort(403)
    return ride


def _send_from(data, ride):
    lat, lng = data.get("lat"), data.get("lng")
    if lat in ("", None) and lng in ("", None):
        lat = lng = None
    return chat.send(ride, current_user, data.get("body"), lat=lat, lng=lng)


# ================================================================= page (form post)

@bp.route("/rides/<int:ride_id>/chat", methods=["POST"])
@login_required
@chat_send_limit
def chat_post(ride_id: int):
    ride = _visible_ride(ride_id)
    try:
        _send_from(request.form, ride)
        db.session.commit()
    except ChatError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("rides.ride_detail", ride_id=ride.id, _anchor="ride-chat"))


# ================================================================= JSON API

@bp.route("/api/rides/<int:ride_id>/chat")
@login_required
def api_chat(ride_id: int):
    ride = _visible_ride(ride_id)
    room = chat.room_for(ride, current_user)
    if room is None:
        return jsonify(chat=None, messages=[], quick_replies=[])
    after = request.args.get("after", 0, type=int) or 0
    return jsonify(
        chat=chat.room_json(room, current_user),
        messages=[chat.message_json(m, room, current_user) for m in chat.history(room, after_id=after)],
        quick_replies=list(chat.quick_replies(room.role_of(current_user))) if room.is_open else [],
    )


@bp.route("/api/rides/<int:ride_id>/chat", methods=["POST"])
@login_required
@chat_send_limit
def api_chat_send(ride_id: int):
    ride = _visible_ride(ride_id)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form
    try:
        msg = _send_from(data, ride)
        db.session.commit()
    except ChatError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), exc.status
    room = msg.chat
    return jsonify(message=chat.message_json(msg, room, current_user), chat=chat.room_json(room, current_user)), 201


@bp.route("/api/rides/<int:ride_id>/chat/read", methods=["POST"])
@login_required
def api_chat_read(ride_id: int):
    ride = _visible_ride(ride_id)
    room = chat.room_for(ride, current_user)
    if room is None:
        return jsonify(error="There is no chat for this ride yet."), 404
    data = request.get_json(silent=True) or {}
    try:
        upto = data.get("last_id")
        last = chat.mark_read(room, current_user, None if upto is None else int(upto))
    except (TypeError, ValueError):
        return jsonify(error="last_id must be an integer."), 400
    db.session.commit()
    return jsonify(last_read_id=last, unread=chat.unread_count(room, current_user))
