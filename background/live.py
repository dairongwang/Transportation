"""
Push notifications for background checks (no page refresh needed).

Uses the same commit-safe event bus as the rides (rides/events.py): events are queued on the
database session and published only AFTER the transaction commits, so a client that reacts by
re-fetching always sees the new state; nothing is sent for a rolled-back change.

Two kinds of channels:

  user:<id>   the person whose background check changed. Subscribed by EVERY page of a logged-in
              user (static/account_live.js via GET /events/account): the background-check page
              re-renders its live regions in place; on any other page the user is told at once
              (and sent to the background-check page when they just lost access).
  admin       everything managers need to see: new / completed reports, decisions, disputes.
              Exposed to the SEPARATE admin dashboard only through the token-protected Admin API
              (GET /admin-api/v1/events); the dashboard's server relays it to its browsers.

Payloads carry ids, usernames, statuses and the user-facing message - never a date of birth,
a licence number or anything from the report itself.
"""

from __future__ import annotations

import hashlib

from rides import events

ADMIN_CHANNEL = "admin"


def user_channel(user_id: int) -> str:
    return f"user:{user_id}"


def version(user) -> str:
    """Fingerprint of everything the background-check page shows; changes with every update."""
    from .service import clearance

    st = clearance(user)
    parts = [st.state, str(st.passed), str(st.can_drive), str(st.can_submit), str(st.can_dispute)]
    parts += [f"c{c.id}:{c.status}:{int(c.held_for_review)}:{c.adjudication or ''}" for c in user.background_checks]
    parts += [f"d{d.id}:{d.status}" for d in user.background_disputes]
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


def user_state(user) -> dict:
    """What the user's pages need to decide how to react (also the SSE `hello`)."""
    from .service import clearance

    st = clearance(user)
    return {"state": st.state, "passed": st.passed, "can_drive": st.can_drive, "message": st.message,
            "version": version(user)}


def push(user, reason: str, *, check=None, dispute=None, actor: str | None = None) -> None:
    """
    Queue the update for the user and for the managers. Call AFTER changing the state and
    BEFORE the commit (it is published when the commit succeeds).
      reason: check_submitted | check_completed | check_approved | check_rejected |
              dispute_opened | recheck_completed | dispute_approved | dispute_rejected
    """
    from extensions import db

    db.session.flush()  # the new rows / statuses are visible inside this transaction...
    db.session.expire(user, ["background_checks", "background_disputes"])  # ...and the collections reload
    events.queue_event(user_channel(user.id), {"event": "background", "reason": reason, **user_state(user)})
    events.queue_event(ADMIN_CHANNEL, {
        "event": reason, "username": user.username, "user_id": user.id, "actor": actor,
        "check_id": check.id if check is not None else None,
        "check_status": check.status if check is not None else None,
        "dispute_id": dispute.id if dispute is not None else None,
        "dispute_status": dispute.status if dispute is not None else None,
    })


def sse_response(channel: str, hello: dict):
    """A text/event-stream response for `channel` (keepalive comments, no proxy buffering)."""
    from flask import Response

    resp = Response(events.stream(channel, hello), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"  # nginx: do not buffer the stream
    return resp


def push_admin(event: str, user) -> None:
    """Queue a managers-only event about a user (e.g. user_registered). Call before the commit."""
    events.queue_event(ADMIN_CHANNEL, {"event": event, "username": user.username, "user_id": user.id, "actor": None,
                                       "check_id": None, "check_status": None, "dispute_id": None, "dispute_status": None})


# ------------------------------------------------------------------ financial activity feed (managers)

def _touched_users(session) -> set[int]:
    """Users whose financial report changes with this flush (column values only: no lazy loads mid-flush)."""
    from sqlalchemy import inspect as sa_inspect

    from models import Booking, DriverProfile, PaymentTransaction, RideRequest, Service

    ids: set[int] = set()
    with session.no_autoflush:
        for obj in list(session.new) + list(session.dirty):
            if isinstance(obj, PaymentTransaction):
                ids.add(obj.user_id)
            elif isinstance(obj, RideRequest) and obj.status == "completed":
                if obj in session.new or sa_inspect(obj).attrs.status.history.has_changes():
                    ids.add(obj.rider_id)
                    drv = session.get(DriverProfile, obj.driver_id) if obj.driver_id else None
                    if drv is not None:
                        ids.add(drv.user_id)
            elif isinstance(obj, Booking):
                ids.add(obj.buyer_id)
                svc = session.get(Service, obj.service_id) if obj.service_id else None
                if svc is not None:
                    ids.add(svc.seller_id)
    return {i for i in ids if i is not None}


def _after_flush(session, _flush_context) -> None:
    ids = _touched_users(session)
    if ids:
        session.info.setdefault(events.PENDING_KEY, []).append(
            (ADMIN_CHANNEL, {"event": "transactions_changed", "user_ids": sorted(ids)}))


_feed_installed = False


def install_transaction_feed(db) -> None:
    """Tell the managers' dashboards when a user's financial report changed (published after commit)."""
    global _feed_installed
    if _feed_installed:
        return
    from sqlalchemy import event as sa_event

    sa_event.listen(db.session, "after_flush", _after_flush)
    _feed_installed = True
