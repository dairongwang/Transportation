"""Rider <-> driver chat (rides/chat.py, rides/chat_routes.py): opens on order, live, private, closes with the ride."""

from datetime import timedelta

import pytest

from clock import utcnow
from extensions import db
from helpers import drain, json_of, logged_in_client, make_driver, make_user, subscribe
from models import ChatMessage, RideChat, RideOffer, RideRequest


# ================================================================= fixtures / helpers

@pytest.fixture
def driver_a(app):
    return make_driver("dummy_drv_a", landmark="Central Station", vehicle="Dummy Hatchback", plate="DUMMY-A01")


@pytest.fixture
def driver_b(app):
    return make_driver("dummy_drv_b", landmark="Downtown", vehicle="Dummy Wagon", plate="DUMMY-B02")


def _request(client, auto_dispatch=False, pickup="Central Station", dropoff="Airport") -> RideRequest:
    resp = client.post("/api/rides", json={"pickup": pickup, "dropoff": dropoff, "auto_dispatch": auto_dispatch,
                                           "payment_method_id": None})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return db.session.get(RideRequest, json_of(resp)["id"])


def _offer_of(ride: RideRequest, driver) -> RideOffer:
    db.session.refresh(ride)
    return next(o for o in ride.offers if o.driver_id == driver.id)


def _order(client, ride, driver) -> RideOffer:
    offer = _offer_of(ride, driver)
    resp = client.post(f"/api/rides/{ride.id}/choose/{offer.id}")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return offer


def _chat(client, ride) -> dict:
    resp = client.get(f"/api/rides/{ride.id}/chat")
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return json_of(resp)


def _say(client, ride, body, status=201, **extra):
    resp = client.post(f"/api/rides/{ride.id}/chat", json={"body": body, **extra})
    assert resp.status_code == status, resp.get_data(as_text=True)
    return json_of(resp)


def _bodies(data) -> list[str]:
    return [m["body"] for m in data["messages"]]


@pytest.fixture
def ordered(app, rider, rider_client, driver_a):
    """A manual-dispatch ride the rider has ORDERED with driver A (driver not answered yet)."""
    ride = _request(rider_client)
    offer = _order(rider_client, ride, driver_a)
    return ride, offer, logged_in_client(app, "dummy_drv_a")


# ================================================================= opening

def test_no_chat_before_the_order_is_placed(rider_client, driver_a):
    ride = _request(rider_client)
    assert ride.status == "searching"
    assert _chat(rider_client, ride) == {"chat": None, "messages": [], "quick_replies": []}
    resp = rider_client.post(f"/api/rides/{ride.id}/chat", json={"body": "hello?"})
    assert resp.status_code == 404
    assert "opens when the rider places the order" in json_of(resp)["error"]
    page = rider_client.get(f"/rides/{ride.id}").get_data(as_text=True)
    assert 'id="ride-chat"' not in page
    assert "a chat with the driver opens" not in page  # the hint is in the order box, which needs a selection
    offer = _offer_of(ride, driver_a)
    rider_client.post(f"/api/rides/{ride.id}/select/{offer.id}")  # selecting is NOT ordering
    assert RideChat.query.count() == 0
    assert "a chat with the driver opens on this page" in rider_client.get(f"/rides/{ride.id}").get_data(as_text=True)


def test_placing_the_order_opens_a_room_for_rider_and_driver(ordered, rider, rider_client, driver_a):
    ride, offer, driver_client = ordered
    assert offer.status == "pending"  # ordered, the driver has not answered yet - chat is already open
    room = RideChat.query.one()
    assert (room.ride_id, room.driver_id, room.rider_id, room.driver_user_id) == (ride.id, driver_a.id, rider.id, driver_a.user_id)
    assert room.is_open

    for client, role, other in ((rider_client, "rider", "dummy_drv_a"), (driver_client, "driver", "dummy_rider")):
        data = _chat(client, ride)
        assert data["chat"]["open"] is True
        assert data["chat"]["my_role"] == role
        assert data["chat"]["with"]["username"] == other
        assert data["messages"][0]["sender_role"] == "system"
        assert "agree on exactly where to meet" in data["messages"][0]["body"]
        assert "DUMMY-A01" in data["messages"][0]["body"]
        assert data["quick_replies"]  # role-specific suggestions
    assert "I'm at the pickup point." in _chat(rider_client, ride)["quick_replies"]
    assert "I've arrived at the pickup point." in _chat(driver_client, ride)["quick_replies"]

    page = rider_client.get(f"/rides/{ride.id}").get_data(as_text=True)
    assert 'id="ride-chat"' in page and 'id="chat-form"' in page and "Chat with <strong>dummy_drv_a</strong>" in page
    assert "#ride-chat" in driver_client.get("/dashboard").get_data(as_text=True)  # incoming request links to the chat


def test_auto_dispatch_opens_the_room_with_the_driver_being_asked(rider_client, driver_a):
    ride = _request(rider_client, auto_dispatch=True)
    assert ride.status == "offered"
    room = RideChat.query.one()
    assert room.driver_id == driver_a.id and room.is_open


# ================================================================= messaging + live push

def test_messages_flow_both_ways_and_are_pushed_only_to_the_participants(ordered, rider, rider_client, driver_a):
    ride, _, driver_client = ordered
    rider_q, driver_q = subscribe(f"user:{rider.id}"), subscribe(f"user:{driver_a.user_id}")
    ride_q = subscribe(f"ride:{ride.id}")

    sent = _say(rider_client, ride, "I'm by the newsstand at exit B.")
    assert sent["message"]["mine"] is True and sent["message"]["sender_role"] == "rider"
    _say(driver_client, ride, "Grey hatchback, 3 minutes away.")

    rider_events, driver_events = drain(rider_q), drain(driver_q)
    assert [e["event"] for e in rider_events] == ["chat", "chat"]
    assert [(e["message"]["body"], e["message"]["mine"]) for e in rider_events] == [
        ("I'm by the newsstand at exit B.", True), ("Grey hatchback, 3 minutes away.", False)]
    assert [(e["message"]["body"], e["message"]["mine"]) for e in driver_events] == [
        ("I'm by the newsstand at exit B.", False), ("Grey hatchback, 3 minutes away.", True)]
    assert all(e["ride_id"] == ride.id and e["open"] is True for e in rider_events + driver_events)
    assert drain(ride_q) == []  # never on the ride channel (other drivers may watch that one)

    assert _bodies(_chat(driver_client, ride))[1:] == ["I'm by the newsstand at exit B.", "Grey hatchback, 3 minutes away."]
    after = _chat(rider_client, ride)["messages"][-2]["id"]
    newer = json_of(rider_client.get(f"/api/rides/{ride.id}/chat?after={after}"))["messages"]
    assert [m["body"] for m in newer] == ["Grey hatchback, 3 minutes away."]


def test_sharing_a_location(ordered, rider_client):
    ride, _, driver_client = ordered
    msg = _say(rider_client, ride, "", lat=40.008, lng=-74.992)["message"]
    assert msg["kind"] == "location" and msg["body"] == "📍 I'm here"
    assert msg["location"] == {"lat": 40.008, "lng": -74.992, "place": "Central Station"}
    captioned = _say(driver_client, ride, "Parked here", lat="40.0", lng="-75.0")["message"]
    assert captioned["body"] == "Parked here" and captioned["location"]["place"] == "Downtown"
    for bad in ({"lat": 91, "lng": 0}, {"lat": "north", "lng": 1}, {"lat": "nan", "lng": "nan"}, {"lat": 1}):
        resp = rider_client.post(f"/api/rides/{ride.id}/chat", json=bad)
        assert resp.status_code == 400, bad
    page = driver_client.get(f"/rides/{ride.id}").get_data(as_text=True)
    assert 'href="geo:40.008000,-74.992000"' in page


@pytest.mark.parametrize("body,error", [("", "Type a message first."), ("   \n\t ", "Type a message first."),
                                        ("x" * 501, "at most 500 characters")])
def test_invalid_messages_are_refused_and_nothing_is_pushed(ordered, rider, rider_client, body, error):
    ride, _, _ = ordered
    q = subscribe(f"user:{rider.id}")
    resp = rider_client.post(f"/api/rides/{ride.id}/chat", json={"body": body})
    assert resp.status_code == 400 and error in json_of(resp)["error"]
    assert drain(q) == []
    assert ChatMessage.query.filter(ChatMessage.sender_id.isnot(None)).count() == 0


def test_message_text_is_cleaned(ordered, rider_client):
    ride, _, _ = ordered
    msg = _say(rider_client, ride, "  line one\r\n\r\n\r\n\r\nline\x00 two\x07  ")["message"]
    assert msg["body"] == "line one\n\nline two"
    assert _say(rider_client, ride, "x" * 500)["message"]["body"] == "x" * 500  # exactly the limit is fine


def test_html_in_messages_is_escaped(ordered, rider_client):
    ride, _, driver_client = ordered
    _say(rider_client, ride, "<script>alert('dummy')</script>")
    page = driver_client.get(f"/rides/{ride.id}").get_data(as_text=True)
    assert "<script>alert(" not in page
    assert "&lt;script&gt;alert(" in page


def test_form_post_works_without_javascript(ordered, rider_client):
    ride, _, driver_client = ordered
    resp = driver_client.post(f"/rides/{ride.id}/chat", data={"body": "On my way."})
    assert resp.status_code == 302 and resp.headers["Location"].endswith(f"/rides/{ride.id}#ride-chat")
    assert _bodies(_chat(rider_client, ride))[-1] == "On my way."
    resp = driver_client.post(f"/rides/{ride.id}/chat", data={"body": ""}, follow_redirects=True)
    assert "Type a message first." in resp.get_data(as_text=True)


# ================================================================= privacy / authorisation

def test_outsiders_cannot_read_or_write(app, ordered):
    ride, _, _ = ordered
    make_user("dummy_outsider")
    outsider = logged_in_client(app, "dummy_outsider")
    assert outsider.get(f"/api/rides/{ride.id}/chat").status_code == 403
    assert outsider.post(f"/api/rides/{ride.id}/chat", json={"body": "hi"}).status_code == 403
    assert outsider.post(f"/rides/{ride.id}/chat", data={"body": "hi"}).status_code == 403
    assert outsider.post(f"/api/rides/{ride.id}/chat/read", json={}).status_code == 403
    assert app.test_client().get(f"/api/rides/{ride.id}/chat").status_code == 401  # logged out


def test_next_driver_gets_a_fresh_room_and_never_sees_the_previous_conversation(app, rider, rider_client, driver_a, driver_b):
    ride = _request(rider_client, auto_dispatch=True)  # A is closest to the pickup -> asked first
    client_a, client_b = logged_in_client(app, "dummy_drv_a"), logged_in_client(app, "dummy_drv_b")
    _say(rider_client, ride, "A: I'm under the clock.")
    _say(client_a, ride, "A here, arriving soon.")
    b_events = subscribe(f"user:{driver_b.user_id}")

    offer_a = _offer_of(ride, driver_a)
    assert client_a.post(f"/drive/offers/{offer_a.id}/decline").status_code == 302
    db.session.refresh(ride)
    assert ride.pending_offer.driver_id == driver_b.id  # auto-dispatch moved on

    room_a, room_b = RideChat.query.order_by(RideChat.id).all()
    assert room_a.driver_id == driver_a.id and not room_a.is_open and room_a.close_reason == "the driver declined the request"
    assert room_b.driver_id == driver_b.id and room_b.is_open

    b_view = _chat(client_b, ride)
    assert b_view["chat"]["id"] == room_b.id
    assert not any("under the clock" in b or "A here" in b for b in _bodies(b_view))
    assert all(e["chat_id"] == room_b.id for e in drain(b_events))  # B was never pushed A's messages

    a_view = _chat(client_a, ride)  # A keeps (read-only) access to their own history only
    assert a_view["chat"]["id"] == room_a.id and a_view["chat"]["open"] is False and a_view["quick_replies"] == []
    assert _say(client_a, ride, "still there?", status=409)["error"].startswith("This chat is closed")

    assert _chat(rider_client, ride)["chat"]["id"] == room_b.id  # the rider talks to the driver now asked
    _say(rider_client, ride, "B: I'm under the clock.")
    assert "B: I'm under the clock." not in _bodies(_chat(client_a, ride))


# ================================================================= closing

def _closed(client, ride):
    data = _chat(client, ride)
    assert data["chat"]["open"] is False
    assert data["messages"][-1]["sender_role"] == "system" and data["messages"][-1]["body"].startswith("Chat closed:")
    return data["chat"]["close_reason"]


def test_full_ride_notes_accept_and_start_then_closes_on_completion(ordered, rider, rider_client, driver_a):
    ride, offer, driver_client = ordered
    q = subscribe(f"user:{rider.id}")
    driver_client.post(f"/drive/offers/{offer.id}/accept")
    driver_client.post(f"/drive/rides/{ride.id}/start")
    _say(rider_client, ride, "Could you turn the music down?")  # still open during the ride
    driver_client.post(f"/drive/rides/{ride.id}/complete")
    db.session.refresh(ride)
    assert ride.status == "completed"

    bodies = _bodies(_chat(rider_client, ride))
    assert "dummy_drv_a accepted the ride and is heading to the pickup point." in bodies
    assert "Ride started - the rider has been picked up." in bodies
    assert _closed(rider_client, ride) == "the ride is completed"
    last = drain(q)[-1]
    assert last["open"] is False and last["message"]["body"] == "Chat closed: the ride is completed."
    assert _say(rider_client, ride, "I forgot my umbrella", status=409)["error"] == "This chat is closed (the ride is completed)."
    page = rider_client.get(f"/rides/{ride.id}").get_data(as_text=True)
    assert 'id="chat-form"' not in page and "This chat is closed (the ride is completed)" in page
    assert "Could you turn the music down?" in page  # history stays readable


def test_rider_cancelling_closes_the_room(ordered, rider_client):
    ride, _, driver_client = ordered
    rider_client.post(f"/rides/{ride.id}/cancel")
    assert _closed(driver_client, ride) == "the ride was cancelled"


def test_driver_handing_the_ride_back_closes_their_room(ordered, rider_client):
    ride, offer, driver_client = ordered
    driver_client.post(f"/drive/offers/{offer.id}/accept")
    driver_client.post(f"/rides/{ride.id}/cancel")  # "Give ride back"
    db.session.refresh(ride)
    assert ride.status in ("searching", "no_drivers")
    assert _closed(driver_client, ride) == "the driver handed the ride back"


def test_unanswered_offer_times_out_and_closes_the_room(ordered, rider_client):
    from rides import matching

    ride, offer, driver_client = ordered
    offer.expires_at = utcnow() - timedelta(seconds=1)
    db.session.commit()
    assert matching.expire_all_stale_offers() == 1  # what the background sweeper runs
    db.session.commit()
    assert _closed(driver_client, ride) == "the driver did not answer in time"


def test_failed_operation_rolls_back_queued_chat_events(ordered, rider, driver_a):
    """Chat events are published only after a successful commit (rides/events.py)."""
    from rides import chat

    ride, _, _ = ordered
    q = subscribe(f"user:{rider.id}")
    chat.note(ride, "this never happened")
    db.session.rollback()
    db.session.commit()
    assert drain(q) == []
    assert ChatMessage.query.filter_by(body="this never happened").count() == 0


# ================================================================= unread markers

def test_unread_counts_and_read_markers(ordered, rider_client):
    ride, _, driver_client = ordered
    _say(rider_client, ride, "one")
    _say(rider_client, ride, "two")
    assert json_of(driver_client.get(f"/api/rides/{ride.id}"))["chat"]["unread"] == 3  # opening note + 2
    assert json_of(rider_client.get(f"/api/rides/{ride.id}"))["chat"]["unread"] == 0  # own messages are read

    first = _chat(driver_client, ride)["messages"][1]["id"]
    resp = driver_client.post(f"/api/rides/{ride.id}/chat/read", json={"last_id": first})
    assert json_of(resp)["unread"] == 1
    resp = driver_client.post(f"/api/rides/{ride.id}/chat/read", json={"last_id": 0})  # never moves backwards
    assert json_of(resp)["unread"] == 1
    assert driver_client.post(f"/api/rides/{ride.id}/chat/read", json={"last_id": "x"}).status_code == 400

    assert 'data-chat-unread-ride="%d">1<' % ride.id in driver_client.get("/dashboard").get_data(as_text=True)
    driver_client.get(f"/rides/{ride.id}")  # viewing the ride page reads the chat
    assert json_of(driver_client.get(f"/api/rides/{ride.id}"))["chat"]["unread"] == 0


# ================================================================= demo bots (dev tools)

def test_demo_bot_answers_the_rider_and_greets_on_accept(app, fleet, rider, rider_client):
    from rides import simulator

    ride = _request(rider_client, auto_dispatch=True, pickup="Downtown")
    bot_room = RideChat.query.one()
    assert simulator.is_bot(bot_room.driver)
    _say(rider_client, ride, "Where are you exactly?")
    last = _chat(rider_client, ride)["messages"][-1]
    assert last["sender_role"] == "driver" and bot_room.driver.vehicle in last["body"]

    # the bot accepts: it says hello (auto_respond may need several tries - bots can decline)
    import random

    for seed in range(50):
        if RideRequest.query.get(ride.id).status == "accepted":
            break
        simulator.auto_respond(ride.id, rng=random.Random(seed))
    db.session.refresh(ride)
    assert ride.status == "accepted"
    assert _chat(rider_client, ride)["messages"][-1]["body"].startswith("Hi dummy_rider! I'm on my way")


def test_bot_stays_quiet_when_a_human_is_logged_in_as_it_or_replies_are_off(app, fleet, rider, rider_client):
    ride = _request(rider_client, auto_dispatch=True, pickup="Downtown")
    room = RideChat.query.one()
    watcher = subscribe(f"user:{room.driver_user_id}")  # someone has the bot's account open
    _say(rider_client, ride, "hello?")
    assert _chat(rider_client, ride)["messages"][-1]["sender_role"] == "rider"
    from rides.events import broker

    broker.unsubscribe(f"user:{room.driver_user_id}", watcher)
    app.config["RIDE_CHAT_BOT_REPLIES"] = False
    _say(rider_client, ride, "anyone?")
    assert _chat(rider_client, ride)["messages"][-1]["body"] == "anyone?"


# ================================================================= limits / gate

def test_chat_is_rate_limited_per_user_with_a_json_429(tmp_path):
    from app import create_app
    from helpers import login
    from throttle import limiter

    app = create_app("testing", {"RATELIMIT_ENABLED": True, "RIDE_CHAT_RATE_LIMIT": "3 per minute",
                                 "RATELIMIT_LOGIN": "100 per minute"})
    app.instance_path = str(tmp_path)
    with app.app_context():
        try:
            limiter.reset()
            make_user("dummy_rider")
            drv = make_driver("dummy_drv_a", landmark="Central Station")
            rc = app.test_client()
            login(rc, "dummy_rider")
            ride = _request(rc)
            _order(rc, ride, drv)
            codes = [rc.post(f"/api/rides/{ride.id}/chat", json={"body": f"msg {i}"}).status_code for i in range(4)]
            assert codes == [201, 201, 201, 429]
            resp = rc.post(f"/api/rides/{ride.id}/chat", json={"body": "again"})
            assert resp.status_code == 429 and resp.is_json and "too quickly" in json_of(resp)["error"]
        finally:
            limiter.reset()
            db.session.remove()
            db.drop_all()


def test_users_without_a_passed_background_check_are_gated(app, ordered):
    ride, _, _ = ordered
    make_user("dummy_unchecked", cleared=False)
    c = logged_in_client(app, "dummy_unchecked")
    resp = c.get(f"/api/rides/{ride.id}/chat")
    assert resp.status_code == 403 and "Background check required" in json_of(resp)["error"]


def test_ride_json_reports_the_callers_chat(ordered, rider_client):
    ride, _, driver_client = ordered
    mine = json_of(rider_client.get(f"/api/rides/{ride.id}"))["chat"]
    assert mine["open"] is True and mine["url"] == f"/api/rides/{ride.id}/chat"


# ================================================================= schema upgrade

def test_upgrade_adds_chat_tables_to_an_existing_database(tmp_path):
    """An instance/uber_services.db from before the chat feature gets the tables on boot."""
    from sqlalchemy import inspect, text

    from app import create_app

    url = f"sqlite:///{tmp_path / 'old.db'}"
    app = create_app("testing", {"SQLALCHEMY_DATABASE_URI": url})
    with app.app_context():
        with db.engine.begin() as conn:
            conn.execute(text("DROP TABLE chat_message"))
            conn.execute(text("DROP TABLE ride_chat"))
        assert "ride_chat" not in inspect(db.engine).get_table_names()
        from migrations import upgrade

        upgrade()
        names = inspect(db.engine).get_table_names()
        assert {"ride_chat", "chat_message"} <= set(names)
        db.session.remove()
        db.drop_all()
