"""
Rider <-> driver chat: one room per (ride, driver), so the two can agree on how to meet.

Lifecycle (driven by rides/matching.py - every ride state change goes through it)
  open      the rider places the order with a driver (or auto-dispatch asks the next driver)
            -> open_room(); a system message explains what the room is for
  notes     the driver accepts / picks the rider up -> system messages in the open room
  close     that driver declines, does not answer in time or hands the ride back, or the ride
            is completed / cancelled / finds no driver -> close_room(); history stays readable

Privacy
  * Only the two participants can read or write a room (RideChat.is_participant).
  * When dispatch moves on to another driver, that driver gets a NEW room: they never see what
    the rider wrote to the previous driver (and vice versa).
  * Messages are delivered ONLY to the participants' own push channels (`user:<id>`, the stream
    every logged-in page already subscribes to via /events/account) - never to the ride channel,
    which every driver that was ever offered the ride may watch.
  * Contact details never need to be exchanged: no phone numbers are involved.

Delivery: messages are queued on the DB session and pushed after the commit (rides/events.py),
so a client never receives a message that was rolled back. Each participant gets their own
payload with `mine` set, so the browser can tell its own messages (echo) from the other side's.
"""

from __future__ import annotations

import logging
import re

from flask import current_app

from clock import utcnow
from extensions import db
from models import ChatMessage, DriverProfile, RideChat, RideRequest, User

from . import events, geo

log = logging.getLogger("rides.chat")

# Close reasons (shown to both participants in the closing system message).
REASON_DECLINED = "the driver declined the request"
REASON_EXPIRED = "the driver did not answer in time"
REASON_DRIVER_LEFT = "the driver handed the ride back"
REASON_CANCELLED = "the ride was cancelled"
REASON_COMPLETED = "the ride is completed"
REASON_NO_DRIVERS = "no driver is available"
REASON_WITHDRAWN = "the request was withdrawn"

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")  # keeps \t and \n
_BLANK_RUNS = re.compile(r"\n{3,}")


class ChatError(Exception):
    """User-facing problem with a chat operation. `status` is the HTTP status for the JSON API."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _cfg(key: str, default):
    try:
        return current_app.config.get(key, default)
    except RuntimeError:  # pragma: no cover - outside an app context
        return default


def max_length() -> int:
    return int(_cfg("RIDE_CHAT_MAX_LENGTH", 500))


# ================================================================= lookups

def room_between(ride: RideRequest, driver_id: int) -> RideChat | None:
    from sqlalchemy import select

    t = RideChat.__table__
    room_id = db.session.execute(select(t.c.id).where(t.c.ride_id == ride.id, t.c.driver_id == driver_id)).scalar()
    return db.session.get(RideChat, room_id) if room_id is not None else None  # light check first: usually none


def open_room_of(ride: RideRequest) -> RideChat | None:
    """The ride's open room (there is at most one: only one driver is asked at a time)."""
    return RideChat.query.filter_by(ride_id=ride.id, closed_at=None).order_by(RideChat.id.desc()).first()


def room_for(ride: RideRequest, user: User) -> RideChat | None:
    """
    The room `user` sees on this ride's page: the rider sees their latest room (the driver
    currently asked / assigned, or the last one); a driver sees only their own room.
    None when the user takes no part in any room of the ride.
    """
    if user is None or not getattr(user, "is_authenticated", True):
        return None
    if ride.rider_id == user.id:
        return RideChat.query.filter_by(ride_id=ride.id).order_by(RideChat.id.desc()).first()
    return RideChat.query.filter_by(ride_id=ride.id, driver_user_id=user.id).first()


def history(room: RideChat, after_id: int = 0, limit: int | None = None) -> list[ChatMessage]:
    """Messages of the room with id > after_id, oldest first (the most recent `limit` of them)."""
    limit = int(limit or _cfg("RIDE_CHAT_HISTORY_LIMIT", 200))
    q = ChatMessage.query.filter(ChatMessage.chat_id == room.id, ChatMessage.id > int(after_id or 0))
    rows = q.order_by(ChatMessage.id.desc()).limit(limit).all()
    return list(reversed(rows))


def unread_count(room: RideChat | None, user: User) -> int:
    """Messages from the OTHER participant (or the system) this user has not seen yet."""
    if room is None or not room.is_participant(user):
        return 0
    last = room.rider_last_read_id if user.id == room.rider_id else room.driver_last_read_id
    return (ChatMessage.query.filter(ChatMessage.chat_id == room.id, ChatMessage.id > (last or 0))
            .filter((ChatMessage.sender_id.is_(None)) | (ChatMessage.sender_id != user.id)).count())


def unread_for_ride(ride: RideRequest, user: User) -> int:
    s = summary(ride, user)
    return s["unread"] if s else 0


def summary(ride: RideRequest, user: User) -> dict | None:
    """
    {"id", "open", "unread"} of the room `user` sees on this ride (room_for() + unread_count())
    with two light queries and no ORM objects - for the ride JSON, which is fetched very often.
    """
    from sqlalchemy import and_, func, or_, select

    if user is None or not getattr(user, "is_authenticated", True):
        return None
    t, m = RideChat.__table__, ChatMessage.__table__
    q = select(t.c.id, t.c.closed_at, t.c.rider_id, t.c.rider_last_read_id, t.c.driver_last_read_id)
    if ride.rider_id == user.id:
        q = q.where(t.c.ride_id == ride.id).order_by(t.c.id.desc()).limit(1)
    else:
        q = q.where(t.c.ride_id == ride.id, t.c.driver_user_id == user.id).limit(1)
    row = db.session.execute(q).first()
    if row is None:
        return None
    last = row.rider_last_read_id if user.id == row.rider_id else row.driver_last_read_id
    unread = db.session.execute(
        select(func.count()).select_from(m).where(and_(
            m.c.chat_id == row.id, m.c.id > (last or 0), or_(m.c.sender_id.is_(None), m.c.sender_id != user.id)))
    ).scalar()
    return {"id": row.id, "open": row.closed_at is None, "unread": int(unread or 0)}


def mark_read(room: RideChat, user: User, upto_id: int | None = None) -> int:
    """Move the user's read marker forward (never backwards). Returns the new marker."""
    if not room.is_participant(user):
        raise ChatError("This chat is not yours.", 403)
    latest = db.session.query(db.func.max(ChatMessage.id)).filter(ChatMessage.chat_id == room.id).scalar() or 0
    target = latest if upto_id is None else max(0, min(int(upto_id), latest))
    if user.id == room.rider_id:
        room.rider_last_read_id = max(room.rider_last_read_id or 0, target)
        return room.rider_last_read_id
    room.driver_last_read_id = max(room.driver_last_read_id or 0, target)
    return room.driver_last_read_id


# ================================================================= serialisation

def message_json(msg: ChatMessage, room: RideChat, viewer: User | None = None) -> dict:
    role = "system" if msg.sender_id is None else ("rider" if msg.sender_id == room.rider_id else "driver")
    data = {
        "id": msg.id,
        "chat_id": room.id,
        "ride_id": room.ride_id,
        "kind": msg.kind,
        "body": msg.body,
        "sender": msg.sender.username if msg.sender is not None else None,
        "sender_role": role,
        "created_at": msg.created_at.isoformat() + "Z",
        "location": None,
    }
    if msg.kind == "location" and msg.lat is not None and msg.lng is not None:
        data["location"] = {"lat": msg.lat, "lng": msg.lng, "place": geo.describe(None, msg.lat, msg.lng, "landmark")}
    if viewer is not None:
        data["mine"] = msg.sender_id is not None and msg.sender_id == viewer.id
    return data


def room_json(room: RideChat, viewer: User) -> dict:
    other = room.other_party(viewer)
    return {
        "id": room.id,
        "ride_id": room.ride_id,
        "open": room.is_open,
        "close_reason": room.close_reason,
        "opened_at": room.opened_at.isoformat() + "Z",
        "closed_at": room.closed_at.isoformat() + "Z" if room.closed_at else None,
        "my_role": room.role_of(viewer),
        "with": {"username": other.username, "role": "driver" if viewer.id == room.rider_id else "rider"},
        "unread": unread_count(room, viewer),
        "max_length": max_length(),
    }


# ================================================================= push

def _publish(room: RideChat, msg: ChatMessage) -> None:
    """Queue the message for both participants (sent after the commit, dropped on rollback)."""
    from background.live import user_channel

    for user in (room.rider, room.driver_user):
        payload = {"event": "chat", "ride_id": room.ride_id, "chat_id": room.id, "open": room.is_open,
                   "role": room.role_of(user), "message": message_json(msg, room, user)}
        events.queue_event(user_channel(user.id), payload)


def _add(room: RideChat, body: str, *, kind: str = "text", sender: User | None = None,
         lat: float | None = None, lng: float | None = None) -> ChatMessage:
    msg = ChatMessage(chat=room, sender_id=sender.id if sender is not None else None, kind=kind,
                      body=body, lat=lat, lng=lng, created_at=utcnow())
    db.session.add(msg)
    db.session.flush()  # ids for the payload (a new room is inserted in the same flush)
    if sender is not None and sender.id == room.rider_id:  # your own message counts as read
        room.rider_last_read_id = msg.id
    elif sender is not None and sender.id == room.driver_user_id:
        room.driver_last_read_id = msg.id
    _publish(room, msg)
    return msg


# ================================================================= lifecycle (called by matching.py)

def open_room(ride: RideRequest, driver: DriverProfile) -> RideChat:
    """The rider ordered `driver` (or auto-dispatch asked them): open their room. Idempotent."""
    from sqlalchemy import inspect as sa_inspect

    # A ride that is not even flushed yet cannot have a room: skip the lookup.
    room = None if sa_inspect(ride).pending else room_between(ride, driver.id)
    if room is not None and room.is_open:
        return room
    if room is None:
        room = RideChat(ride=ride, driver=driver, ride_id=ride.id, driver_id=driver.id, rider_id=ride.rider_id,
                        driver_user_id=driver.user_id, opened_at=utcnow())
        db.session.add(room)  # inserted by the flush in _add(), together with the opening message
    else:  # defensive: a driver is only asked once per ride, but never leave a room half-closed
        room.closed_at = None
        room.close_reason = None
    vehicle = driver.vehicle + (f", plate {driver.plate}" if driver.plate else "")
    _add(room, f"Order placed with {driver.user.username} ({vehicle}). Pickup: {ride.pickup_address}. "
               "Use this chat to agree on exactly where to meet.", kind="system")
    log.info("chat=%s opened ride=%s driver=%s", room.id, ride.id, driver.id)
    return room


def close_room(room: RideChat | None, reason: str) -> None:
    if room is None or not room.is_open:
        return
    room.closed_at = utcnow()  # set BEFORE the message so its payload says open=false
    room.close_reason = reason[:120]
    _add(room, f"Chat closed: {reason}.", kind="system")
    log.info("chat=%s closed ride=%s (%s)", room.id, room.ride_id, reason)


def close_for_driver(ride: RideRequest, driver_id: int, reason: str) -> None:
    close_room(room_between(ride, driver_id), reason)


def close_all(ride: RideRequest, reason: str) -> None:
    for room in RideChat.query.filter_by(ride_id=ride.id, closed_at=None).all():
        close_room(room, reason)


def note(ride: RideRequest, text: str) -> None:
    """A system message in the ride's open room (e.g. "driver accepted"), if there is one."""
    room = open_room_of(ride)
    if room is not None:
        _add(room, text, kind="system")


# ================================================================= user messages

def clean_body(raw) -> str:
    text = str(raw or "").replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_CHARS.sub("", text)
    text = _BLANK_RUNS.sub("\n\n", text).strip()
    if not text:
        raise ChatError("Type a message first.")
    if len(text) > max_length():
        raise ChatError(f"Messages can be at most {max_length()} characters.")
    return text


def _parse_location(lat, lng) -> tuple[float, float]:
    try:
        la, ln = float(lat), float(lng)
    except (TypeError, ValueError):
        raise ChatError("Latitude / longitude must be numbers.") from None
    if not (-90 <= la <= 90 and -180 <= ln <= 180) or la != la or ln != ln:  # range + NaN
        raise ChatError("Coordinates are out of range.")
    return round(la, 6), round(ln, 6)


def _writable_room(ride: RideRequest, user: User) -> RideChat:
    room = room_for(ride, user)
    if room is None:
        raise ChatError("There is no chat for this ride yet - it opens when the rider places the order.", 404)
    if not room.is_participant(user):  # pragma: no cover - room_for only returns own rooms
        raise ChatError("This chat is not yours.", 403)
    if not room.is_open:
        raise ChatError(f"This chat is closed ({room.close_reason or 'the ride ended'}).", 409)
    return room


def send(ride: RideRequest, sender: User, body=None, *, lat=None, lng=None) -> ChatMessage:
    """
    A participant writes in their open room. Text, or a shared location (lat + lng, optional
    caption in `body`). Raises ChatError. Does not commit.
    """
    room = _writable_room(ride, sender)
    if lat is not None or lng is not None:
        la, ln = _parse_location(lat, lng)
        caption = clean_body(body) if str(body or "").strip() else "📍 I'm here"
        msg = _add(room, caption, kind="location", sender=sender, lat=la, lng=ln)
    else:
        msg = _add(room, clean_body(body), sender=sender)
    _maybe_bot_reply(room, msg)
    return msg


def _maybe_bot_reply(room: RideChat, msg: ChatMessage) -> None:
    """Dev tools: a demo driver bot answers the rider (nobody is logged in as the bots)."""
    if not (_cfg("ENABLE_DEV_TOOLS", False) and _cfg("RIDE_CHAT_BOT_REPLIES", True)):
        return
    if msg.sender_id != room.rider_id or not room.is_open:
        return
    from background.live import user_channel

    from . import simulator

    if not simulator.is_bot(room.driver):
        return
    if events.broker.subscriber_count(user_channel(room.driver_user_id)):
        return  # someone is logged in as this bot right now: let the human answer
    _add(room, simulator.chat_reply(room, msg), sender=room.driver_user)


# ================================================================= quick replies

QUICK_REPLIES = {
    "rider": ("I'm at the pickup point.", "I'll be there in 2 minutes.", "Where exactly are you?",
              "Please meet me at the main entrance."),
    "driver": ("I'm on my way.", "I've arrived at the pickup point.", "Where exactly are you?",
               "I can't stop here - I'll wait around the corner."),
}


def quick_replies(role: str | None) -> tuple[str, ...]:
    return QUICK_REPLIES.get(role or "", ())
