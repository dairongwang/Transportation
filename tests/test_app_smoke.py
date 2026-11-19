"""App / auth / marketplace / ride-flow smoke tests + configuration guards (in-memory SQLite, no network)."""

import re
from pathlib import Path

import pytest

from extensions import db
from helpers import DUMMY_PASSWORD, json_of, logged_in_client, make_driver, make_user
from models import Booking, PaymentTransaction, RideRequest, Service, User

ROOT = Path(__file__).resolve().parents[1]


# ================================================================= boot + pages

def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200 and json_of(resp)["status"] == "ok"


@pytest.mark.parametrize("path", ["/", "/login", "/register", "/search?q=x", "/password/forgot", "/dev/env", "/dev/outbox"])
def test_public_pages_render(client, path):
    assert client.get(path).status_code == 200


def test_security_headers(client):
    resp = client.get("/login")
    csp = resp.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert resp.headers["X-Frame-Options"] == "DENY" and resp.headers["Cache-Control"] == "no-store"


@pytest.mark.parametrize("path", ["/dashboard", "/rides", "/rides/request", "/drive", "/account", "/account/payments",
                                  "/settings/security", "/background-check"])
def test_logged_in_pages_render(rider_client, path):
    resp = rider_client.get(path)
    assert resp.status_code in (200, 302), path
    if resp.status_code == 200:
        assert "chat.js" in resp.get_data(as_text=True)  # live chat notices on every page


def test_protected_pages_redirect_to_login(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]
    assert client.get("/api/rides/1").status_code == 401


# ================================================================= auth

def test_register_login_logout(client, app):
    resp = client.post("/register", data={"username": "dummy_new", "email": "dummy.new@example.com",
                                          "password": DUMMY_PASSWORD, "role": "both"})
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/login")
    assert client.post("/login", data={"username": "dummy_new", "password": "wrong-dummy-pass"}).status_code == 401
    resp = client.post("/login", data={"username": "dummy_new", "password": DUMMY_PASSWORD})
    assert resp.status_code == 302
    # not background-checked yet: the gate sends them to the check
    assert "/background-check" in client.get("/rides/request").headers["Location"]
    client.post("/logout")
    assert "/login" in client.get("/dashboard").headers["Location"]


def test_weak_password_is_refused(client):
    resp = client.post("/register", data={"username": "dummy_weak", "email": "dummy.weak@example.com",
                                          "password": "short", "role": "both"})
    assert resp.status_code == 400 and User.query.filter_by(username="dummy_weak").count() == 0


def test_background_check_with_the_fake_provider(app):
    make_user("dummy_applicant", cleared=False)
    c = logged_in_client(app, "dummy_applicant")
    resp = c.post("/background-check", data={"legal_first_name": "Dummy", "legal_last_name": "Applicant",
                                             "date_of_birth": "1990-01-01", "consent": "on"})
    assert resp.status_code == 302
    assert json_of(c.get("/api/background-check"))["passed"] is True
    assert c.get("/rides/request").status_code == 200


# ================================================================= marketplace

def test_post_and_book_a_service(app):
    make_user("dummy_seller_t", role="both")  # only "both" accounts may post services
    make_user("dummy_buyer_t", role="buyer")
    seller, buyer = logged_in_client(app, "dummy_seller_t"), logged_in_client(app, "dummy_buyer_t")
    resp = seller.post("/post_service", data={"title": "Dummy Cleaning", "description": "d", "category": "cleaning",
                                              "price": "20", "location": "Downtown"})
    assert resp.status_code == 302
    svc = Service.query.filter_by(title="Dummy Cleaning").one()
    assert buyer.post(f"/book/{svc.id}").status_code == 302
    booking = Booking.query.filter_by(service_id=svc.id).one()
    assert booking.status == "pending" and booking.payment_token.startswith("DUMMY_PAY_")
    assert seller.post(f"/booking/{booking.id}/update", data={"status": "accepted"}).status_code == 302
    db.session.refresh(booking)
    assert booking.status == "accepted"
    assert seller.post("/post_service", data={"title": "x", "price": "-1"}).status_code == 400


# ================================================================= rides (regression for the dispatch state machine)

@pytest.fixture
def two_drivers(app):
    return (make_driver("dummy_drv_near", landmark="Central Station"),
            make_driver("dummy_drv_far", landmark="Downtown"))


def _ride(client, auto=True, payment=None):
    resp = client.post("/api/rides", json={"pickup": "Central Station", "dropoff": "Airport",
                                           "auto_dispatch": auto, "payment_method_id": payment})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return db.session.get(RideRequest, json_of(resp)["id"])


def test_search_ranks_nearby_drivers(rider_client, two_drivers):
    data = json_of(rider_client.get("/api/rides/search?pickup=Central Station&dropoff=Airport"))
    assert [d["driver"]["username"] for d in data["drivers"]] == ["dummy_drv_near", "dummy_drv_far"]
    assert data["drivers"][0]["score"] >= data["drivers"][1]["score"]


def test_manual_select_then_order(rider_client, two_drivers):
    near, far = two_drivers
    ride = _ride(rider_client, auto=False)
    assert ride.status == "searching" and all(o.status == "ranked" for o in ride.offers)
    far_offer = next(o for o in ride.offers if o.driver_id == far.id)
    assert rider_client.post(f"/api/rides/{ride.id}/select/{far_offer.id}").status_code == 200
    db.session.refresh(ride)
    assert ride.status == "searching" and ride.selected_offer_id == far_offer.id  # selecting sends nothing
    assert rider_client.post(f"/api/rides/{ride.id}/order").status_code == 200
    db.session.refresh(ride)
    assert ride.status == "offered" and ride.pending_offer.driver_id == far.id


def test_decline_cascades_accept_start_complete_rate(app, rider_client, two_drivers):
    near, far = two_drivers
    ride = _ride(rider_client)
    assert ride.pending_offer.driver_id == near.id
    near_c, far_c = logged_in_client(app, "dummy_drv_near"), logged_in_client(app, "dummy_drv_far")
    near_c.post(f"/drive/offers/{ride.pending_offer.id}/decline")
    db.session.refresh(ride)
    assert ride.pending_offer.driver_id == far.id
    far_c.post(f"/drive/offers/{ride.pending_offer.id}/accept")
    far_c.post(f"/drive/rides/{ride.id}/start")
    far_c.post(f"/drive/rides/{ride.id}/complete")
    db.session.refresh(ride)
    assert ride.status == "completed" and ride.payment_status == "cash" and ride.fare > 0
    rider_client.post(f"/rides/{ride.id}/rate", data={"stars": "4"})
    db.session.refresh(ride)
    assert ride.rider_rating == 4 and far.rating_count == 1


def test_rider_can_cancel_and_only_one_active_ride(rider_client, two_drivers):
    ride = _ride(rider_client)
    resp = rider_client.post("/api/rides", json={"pickup": "Downtown", "dropoff": "Airport"})
    assert resp.status_code == 400 and "already have an active ride" in json_of(resp)["error"]
    rider_client.post(f"/rides/{ride.id}/cancel")
    db.session.refresh(ride)
    assert ride.status == "cancelled"


def test_card_ride_holds_then_captures_the_fare(app, rider, rider_client, two_drivers):
    """Pre-authorisation on order, capture on completion (fake gateway + the public 4242 test card)."""
    from payments import service as payments
    from payments import vault

    token = vault.create_single_use_token("4242424242424242", 12, 2030, "123").token  # public test card
    method = payments.add_card(rider, card_token=token, billing_name="Dummy Rider", label="Dummy card", make_default=True)
    db.session.commit()
    ride = _ride(rider_client, payment=method.id)
    assert ride.preauth_status == "held" and ride.preauth_amount == pytest.approx(ride.pending_offer.price * 1.5, abs=0.01)
    near_c = logged_in_client(app, "dummy_drv_near")
    near_c.post(f"/drive/offers/{ride.pending_offer.id}/accept")
    near_c.post(f"/drive/rides/{ride.id}/start")
    near_c.post(f"/drive/rides/{ride.id}/complete")
    db.session.refresh(ride)
    assert ride.status == "completed" and ride.payment_status == "paid" and ride.preauth_status == "captured"
    assert PaymentTransaction.query.filter_by(ride_id=ride.id).count() >= 1
    page = rider_client.get("/account/payments").get_data(as_text=True)
    assert "4242424242424242" not in page and "4242" in page  # only the last 4 digits are ever shown


def test_no_drivers(rider_client):
    ride = _ride(rider_client)
    assert ride.status == "no_drivers"


def test_driver_profile_and_availability(app):
    make_user("dummy_new_driver", package="driver")
    c = logged_in_client(app, "dummy_new_driver")
    assert c.post("/drive", data={"vehicle": "Dummy Van", "plate": "DUMMY-777", "base_fare": "2", "per_km_rate": "1",
                                  "per_min_rate": "0.2", "min_fare": "5"}).status_code == 302
    resp = c.post("/api/drivers/me/location", json={"landmark": "Downtown", "online": True})
    assert resp.status_code == 200 and json_of(resp)["visible_to_riders"] is True


# ================================================================= configuration guards

def test_production_refuses_dummy_secrets(monkeypatch):
    import config

    monkeypatch.setattr(config.BaseConfig, "SECRET_KEY", config.DUMMY_SECRET_KEY)
    monkeypatch.setattr(config.BaseConfig, "MFA_ENCRYPTION_KEY", config.DUMMY_MFA_ENCRYPTION_KEY)
    with pytest.raises(RuntimeError, match="Refusing to start in production"):
        config.ProductionConfig()


def test_development_requires_keys(monkeypatch):
    import config

    monkeypatch.setattr(config.BaseConfig, "SECRET_KEY", None)
    with pytest.raises(RuntimeError, match="must be set in .env"):
        config.DevelopmentConfig()


def _env_example() -> dict:
    from dotenv import dotenv_values

    return dotenv_values(ROOT / ".env.example")


def test_env_example_exists_and_boots_the_app():
    values = _env_example()
    assert values["SECRET_KEY"] and values["MFA_ENCRYPTION_KEY"], "the launchers copy .env.example to .env"
    assert values["APP_ENV"] == "development"


def test_env_example_documents_every_setting_config_reads():
    source = (ROOT / "config.py").read_text(encoding="utf-8")
    read = set(re.findall(r'(?:os\.environ\.get|_env_bool|_env_int|_env_float|_env_list)\("([A-Z0-9_]+)"', source))
    missing = sorted(read - set(_env_example()))
    assert not missing, f".env.example lacks: {missing}"


def test_env_example_secrets_are_all_dummy():
    secretish = re.compile(r"(SECRET|TOKEN$|_KEY$|PASSWORD$|USERNAME$|_SID$|PRIVATE_KEY|_CLIENT_ID$|_APP_ID$|_TEAM_ID$|_KEY_ID$)")
    not_dummy = {k: v for k, v in _env_example().items()
                 if secretish.search(k) and k not in ("MFA_ENCRYPTION_KEY_PREVIOUS",) and "dummy" not in (v or "").lower()}
    assert not not_dummy, f"non-DUMMY secrets in .env.example: {not_dummy}"


def test_env_example_has_no_real_looking_card_or_phone_numbers():
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    for digits in re.findall(r"\+?\d[\d -]{11,}\d", text):
        plain = re.sub(r"\D", "", digits)
        assert plain.startswith("1555") or plain == "4242424242424242", f"suspicious number in .env.example: {digits}"


# ================================================================= role-based navigation / dashboard

# what identifies each tab / dashboard section in the rendered HTML
MARKERS = {
    "ride_tab": 'href="/rides/request"',
    "drive_tab": 'href="/drive"',
    "post_tab": 'href="/post_service"',
    "posted_services": "My Posted Services",
    "my_bookings": "My Bookings (as Buyer)",
    "recent_rides": "My Recent Rides",
    "incoming": "Incoming Booking Requests (as Seller)",
}
VISIBLE = {  # role -> what the dashboard shows
    "buyer": {"ride_tab", "my_bookings", "recent_rides"},
    "seller": {"drive_tab", "my_bookings", "incoming"},
    "both": set(MARKERS),
}


def _page(app, username, path):
    return logged_in_client(app, username).get(path).get_data(as_text=True)


@pytest.mark.parametrize("role", ["buyer", "seller", "both"])
def test_dashboard_tabs_and_sections_follow_the_role(app, role):
    make_user(f"dummy_{role}_role", role=role)
    dash = _page(app, f"dummy_{role}_role", "/dashboard")
    for name, marker in MARKERS.items():
        assert (marker in dash) == (name in VISIBLE[role]), (role, name)
    assert 'name="mode"' in dash  # the landmark / GPS toggle is on every role's dashboard
    for path in ("/", "/rides", "/account"):  # the nav is the same on every page
        html = _page(app, f"dummy_{role}_role", path)
        for tab in ("ride_tab", "drive_tab", "post_tab"):
            assert (MARKERS[tab] in html) == (tab in VISIBLE[role]), (role, path, tab)


def test_buyer_is_still_refused_when_opening_the_urls_directly(app):
    make_user("dummy_buyer_only", role="buyer")
    c = logged_in_client(app, "dummy_buyer_only")
    for path in ("/drive", "/post_service"):
        resp = c.get(path)
        assert resp.status_code == 302 and resp.headers["Location"].endswith("/dashboard"), path
    assert c.post("/post_service", data={"title": "x", "price": "1"}).status_code == 302
    assert Service.query.count() == 0


def test_seller_is_refused_rides_and_posting_when_opening_the_urls_directly(app):
    make_user("dummy_seller_only", role="seller", package="driver")
    c = logged_in_client(app, "dummy_seller_only")
    for path in ("/rides/request", "/post_service"):
        resp = c.get(path, follow_redirects=True)
        assert resp.request.path == "/dashboard", path
        assert "seller-only" in resp.get_data(as_text=True), path
    assert c.post("/post_service", data={"title": "x", "price": "1"}).status_code == 302
    assert c.post("/rides/request", data={"pickup": "Downtown", "dropoff": "Airport"}).status_code == 302
    resp = c.post("/api/rides", json={"pickup": "Downtown", "dropoff": "Airport"})
    assert resp.status_code == 400 and "seller-only" in json_of(resp)["error"]
    assert Service.query.count() == 0 and RideRequest.query.count() == 0
    assert c.get("/drive").status_code == 200  # ...but they can drive
    rides = c.get("/rides").get_data(as_text=True)
    assert "As rider" not in rides and 'href="/rides/request"' not in rides


def test_logged_out_home_page_offers_ride_and_drive(client):
    html = client.get("/").get_data(as_text=True)
    assert 'href="/drive"' in html and 'href="/rides/request"' in html
