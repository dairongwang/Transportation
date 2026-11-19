"""
Uber-like Service Marketplace App

Entry point + marketplace routes. Authentication (including two-factor
authentication via authenticator app, e-mail and SMS) lives in the `auth` package.

Configuration is read from environment variables / .env (see .env.example).
"""

import logging
import os
import uuid

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from config import get_config
from extensions import csrf, db, login_manager
from models import Booking, RideRequest, Service, User

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def create_app(config_name: str | None = None, overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(get_config(config_name))
    if overrides:
        app.config.update(overrides)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    os.makedirs(app.instance_path, exist_ok=True)  # SQLite file + outbox live here on every OS

    from auth import bp as auth_bp
    from devtools import register_devtools
    from throttle import init_throttling

    init_throttling(app)  # IP rate limiting (+ ProxyFix when BEHIND_PROXY)

    @login_manager.unauthorized_handler
    def _unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="Authentication required."), 401  # JSON clients get JSON, not a login page
        from flask_login.utils import login_url

        flash(login_manager.login_message, login_manager.login_message_category)
        return redirect(login_url(login_manager.login_view, next_url=request.url))

    if app.testing:
        # Test clients reuse an already-pushed app context, so Flask-Login's per-request
        # cache in `g` would leak between clients. Real requests always start with a fresh `g`.
        from flask import g

        @app.before_request
        def _fresh_login_cache():
            g.pop("_login_user", None)
    app.register_blueprint(auth_bp)
    from rides import bp as rides_bp  # ride hailing: request -> search nearby drivers -> rank -> dispatch

    app.register_blueprint(rides_bp)
    from rides import events as ride_events, sweeper as ride_sweeper

    ride_events.install(db)  # publish ride / driver push events after each commit
    ride_events.configure_bus(app)  # EVENT_BUS=unix: several worker processes share the events
    from rides import driver_index

    driver_index.install(db)  # the matcher's in-memory driver index sees this process's commits at once
    from payments import api_bp as account_api_bp, bp as account_bp  # Account tab: payment methods

    app.register_blueprint(account_bp)
    app.register_blueprint(account_api_bp)
    if app.config.get("PAYMENTS_MODE") == "fake" and app.config.get("ENABLE_DEV_TOOLS"):
        from payments.fake_provider import fake_payments_bp  # stub Stripe / PayPal approval pages

        app.register_blueprint(fake_payments_bp)
    if app.config.get("OAUTH_MODE") == "fake" and app.config.get("ENABLE_DEV_TOOLS"):
        from auth.fake_oauth import fake_oauth_bp  # stub identity provider at /dev/oauth/...

        app.register_blueprint(fake_oauth_bp)
    import background  # background checks: only users who passed may use the app (installs the gate)

    background.init_app(app)
    register_marketplace_routes(app)
    register_devtools(app)
    register_security_headers(app)

    with app.app_context():
        configure_sqlite(app)
        from migrations import upgrade

        upgrade()
        if app.config.get("SEED_DEMO_DATA"):
            seed_demo_data()
            seed_demo_drivers()
            seed_demo_background_checks()
            seed_demo_payment_methods()
    ride_sweeper.start(app)  # times out unanswered offers (pushes "expired" to rider + driver)

    return app


def configure_sqlite(app: Flask) -> None:
    """WAL, busy timeout and the writer queue for a SQLite FILE database (see dbtuning.py)."""
    from dbtuning import configure_sqlite as _configure

    _configure(app, db.engine)


def _tokenization_origin(app: Flask) -> str:
    """Origin of TOKENIZATION_URL when it is absolute (a real vault), '' when it is in-app."""
    from urllib.parse import urlsplit

    parts = urlsplit(app.config.get("TOKENIZATION_URL", ""))
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""


def register_security_headers(app: Flask) -> None:
    from auth import captcha

    @app.after_request
    def _headers(resp):
        extra = " ".join(captcha.csp_sources())
        frame_src = extra or "'none'"  # (computed outside the f-string: py3.10/3.11 forbid backslashes inside)
        # the browser talks to the card vault directly (card-on-file tokenisation); allow its origin
        vault_src = vault_origin if (vault_origin := _tokenization_origin(app)) else ""
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            f"style-src 'self'; script-src 'self' {extra}; manifest-src 'self'; connect-src 'self' {vault_src}; "
            f"frame-src {frame_src}; frame-ancestors 'none'",
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # Never cache authenticated / auth pages.
        if request.path.startswith(("/settings", "/2fa", "/dashboard", "/login", "/dev", "/rides", "/drive", "/api", "/account")):
            resp.headers["Cache-Control"] = "no-store"
        return resp


# ============ MARKETPLACE ROUTES ============

def register_marketplace_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        services = Service.query.filter_by(available=True).order_by(Service.created_at.desc()).limit(12).all()
        return render_template("index.html", services=services)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        # Sections depend on the role (see User.can_ride / can_sell / can_post_services).
        is_seller, can_post, can_ride = current_user.can_sell, current_user.can_post_services, current_user.can_ride
        my_services = Service.query.filter_by(seller_id=current_user.id).all() if can_post else []
        my_bookings = Booking.query.filter_by(buyer_id=current_user.id).all()
        incoming = Booking.query.join(Service).filter(Service.seller_id == current_user.id).all() if is_seller else []
        my_rides = (RideRequest.query.filter_by(rider_id=current_user.id)
                    .order_by(RideRequest.created_at.desc()).limit(5).all()) if can_ride else []
        return render_template(
            "dashboard.html", my_services=my_services, my_bookings=my_bookings, incoming=incoming, my_rides=my_rides,
            driver=current_user.driver_profile, can_drive=is_seller, is_seller=is_seller, can_post=can_post,
            can_ride=can_ride,
        )

    @app.route("/post_service", methods=["GET", "POST"])
    @login_required
    def post_service():
        if not current_user.can_post_services:
            flash("Your account is buyer-only and cannot post services." if current_user.role == "buyer" else
                  "Your account is seller-only (drive and receive bookings) and cannot post services.", "error")
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            try:
                price = float(request.form["price"])
                if price < 0:
                    raise ValueError
            except (ValueError, KeyError):
                flash("Please enter a valid price.", "error")
                return render_template("post_service.html"), 400
            service = Service(
                title=request.form["title"][:200],
                description=request.form.get("description", ""),
                category=request.form.get("category", "other"),
                price=price,
                location=request.form.get("location", "")[:200],
                seller_id=current_user.id,
            )
            db.session.add(service)
            db.session.commit()
            flash("Service posted! (Dummy listing)", "success")
            return redirect(url_for("dashboard"))
        return render_template("post_service.html")

    @app.route("/service/<int:service_id>")
    def service_detail(service_id):
        service = Service.query.get_or_404(service_id)
        return render_template("service_detail.html", service=service)

    @app.route("/book/<int:service_id>", methods=["POST"])
    @login_required
    def book_service(service_id):
        service = Service.query.get_or_404(service_id)
        if service.seller_id == current_user.id:
            flash("You cannot book your own service.", "error")
            return redirect(url_for("service_detail", service_id=service_id))
        if current_user.role == "seller":
            flash("Your account is seller-only and cannot book services.", "error")
            return redirect(url_for("service_detail", service_id=service_id))

        # DUMMY PAYMENT TOKEN GENERATION
        dummy_payment_token = f"DUMMY_PAY_{uuid.uuid4().hex[:16].upper()}"
        booking = Booking(
            service_id=service.id,
            buyer_id=current_user.id,
            amount=service.price,
            status="pending",
            payment_token=dummy_payment_token,
        )
        db.session.add(booking)
        db.session.commit()
        flash(f"Booking requested! Dummy payment token: {dummy_payment_token}. Awaiting seller acceptance.", "success")
        return redirect(url_for("dashboard"))

    # Which status transitions each party may perform.
    SELLER_TRANSITIONS = {"accepted", "in_progress", "completed", "cancelled"}
    BUYER_TRANSITIONS = {"cancelled"}

    @app.route("/booking/<int:booking_id>/update", methods=["POST"])
    @login_required
    def update_booking(booking_id):
        booking = Booking.query.get_or_404(booking_id)
        is_seller = booking.service.seller_id == current_user.id
        is_buyer = booking.buyer_id == current_user.id
        if not (is_seller or is_buyer):
            flash("Unauthorized.", "error")
            return redirect(url_for("dashboard"))

        new_status = request.form.get("status")
        allowed = SELLER_TRANSITIONS if is_seller else BUYER_TRANSITIONS
        if new_status in allowed and booking.status not in ("completed", "cancelled"):
            booking.status = new_status
            db.session.commit()
            flash(f"Booking status updated to {new_status}.", "success")
        else:
            flash("That status change is not allowed.", "error")
        return redirect(url_for("dashboard"))

    @app.route("/search")
    def search():
        q = request.args.get("q", "")[:100]
        category = request.args.get("category", "")
        query = Service.query.filter_by(available=True)
        if q:
            query = query.filter(Service.title.contains(q) | Service.description.contains(q))
        if category:
            query = query.filter_by(category=category)
        services = query.order_by(Service.created_at.desc()).all()
        return render_template("index.html", services=services, search_q=q)


# ============ DEMO DATA ============

def seed_demo_data() -> None:
    """Seed dummy users/services if the database is empty (development only)."""
    if User.query.count() != 0:
        return
    # DUMMY accounts: example.com addresses are reserved for documentation (RFC 2606),
    # passwords are public placeholders.
    seller = User(username="dummy_seller", email="dummy.seller@example.com", role="seller")
    seller.set_password("dummySellerPass123")  # DUMMY PASSWORD
    buyer = User(username="dummy_buyer", email="dummy.buyer@example.com", role="buyer")
    buyer.set_password("dummyBuyerPass123")  # DUMMY PASSWORD
    db.session.add_all([seller, buyer])
    db.session.commit()

    db.session.add_all(
        [
            Service(title="Airport Ride - Luxury", description="Comfortable ride to airport", category="ride",
                    price=45.0, location="Downtown to Airport", seller_id=seller.id),
            Service(title="Grocery Delivery", description="Same-day grocery drop-off", category="delivery",
                    price=12.0, location="Citywide", seller_id=seller.id),
            Service(title="Home Cleaning", description="2-hour deep clean", category="cleaning",
                    price=60.0, location="Local area", seller_id=seller.id),
        ]
    )
    db.session.commit()


def seed_demo_payment_methods() -> None:
    """Give dummy_buyer a DUMMY test card (fake gateway only) so the paid-ride flow is one click away."""
    from models import PaymentMethod
    from payments import service as payments

    buyer = User.query.filter_by(username="dummy_buyer").first()
    if buyer is None or PaymentMethod.query.filter_by(user_id=buyer.id).count() or not payments.can_have_payment_methods(buyer):
        return
    try:
        from payments import vault

        # In-process stand-in for the browser step: the fake vault mints the single-use token,
        # and the app (as always) only ever handles that token.
        single_use = vault.create_single_use_token("4242424242424242", 12, 2030, "123").token
        payments.add_card(buyer, card_token=single_use, billing_name="Dummy Buyer",
                          label="Demo Visa (DUMMY test card)", make_default=True)
    except Exception as exc:  # noqa: BLE001 - e.g. PAYMENTS_MODE=real: demo data is best effort
        db.session.rollback()
        logging.getLogger("app").warning("Could not seed demo payment method: %s", exc)


# DUMMY identities of the seeded demo accounts (fictional people; licence numbers are fake).
DEMO_IDENTITIES = {
    "dummy_buyer": ("Dummy", "Buyer"),
    "dummy_seller": ("Dummy", "Seller"),
}


def seed_demo_background_checks() -> None:
    """
    The seeded DUMMY accounts come with a passed background check so the demo is usable right
    away (drivers with the driver package). Idempotent; also renews an expired seeded check.
    Accounts you register yourself go through the real (fake-provider) check.
    """
    from datetime import date

    from background import service as bgc
    from rides.simulator import BOT_PREFIX

    demo_users = User.query.filter(
        User.username.in_(list(DEMO_IDENTITIES)) | User.username.like(f"{BOT_PREFIX}%")
    ).all()
    seeded = 0
    for user in demo_users:
        if bgc.clearance(user).state not in ("not_started", "expired"):
            continue
        if user.username.startswith(BOT_PREFIX):
            n = user.username[len(BOT_PREFIX):]
            bgc.seed_clear_check(user, package="driver", first="Dummy", last=f"Driver {n}", dob=date(1985, 1, 1),
                                 licence=f"DUMMY-DL-{int(n):04d}" if n.isdigit() else "DUMMY-DL-0000", region="Demo State")
        else:
            first, last = DEMO_IDENTITIES[user.username]
            bgc.seed_clear_check(user, package="standard", first=first, last=last, dob=date(1990, 1, 1))
        seeded += 1
    db.session.commit()
    if seeded:
        logging.getLogger("app").info("Seeded %s passed DUMMY background checks for the demo accounts", seeded)


def seed_demo_drivers() -> None:
    """Seed the demo driver fleet (idempotent; also works on a pre-existing database)."""
    from rides.simulator import refresh_fleet_positions, seed_demo_drivers as _seed

    created = _seed()
    if created:
        logging.getLogger("app").info("Seeded %s DUMMY demo drivers (dummy_driver_1..%s)", created, created)
    refresh_fleet_positions()  # bots never move, so keep their last-seen time current on every boot


if __name__ == "__main__":
    app = create_app()
    # Development server only. In production use gunicorn (Linux/macOS) or waitress (Windows) behind HTTPS.
    # HOST=0.0.0.0 exposes the app on your LAN so phones/tablets can reach it (see README).
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    from config import is_dummy

    app.logger.info("Secrets: SECRET_KEY=%s MFA_ENCRYPTION_KEY=%s",
                    "DUMMY" if is_dummy(app.config["SECRET_KEY"]) else "set",
                    "DUMMY" if is_dummy(app.config["MFA_ENCRYPTION_KEY"]) else "set")
    # HTTPS=1 serves a self-signed certificate (needs `cryptography`). Browsers only share GPS
    # positions on https:// or localhost, so this is what lets phones on the LAN act as drivers.
    https = os.environ.get("HTTPS", "").strip().lower() in {"1", "true", "yes", "on"}
    scheme = "https" if https else "http"
    if host == "0.0.0.0":
        from devtools import lan_addresses

        for ip in lan_addresses():
            app.logger.info("Reachable from other devices at %s://%s:%s", scheme, ip, port)
        if not https:
            app.logger.info("Tip: GPS only works over HTTPS on other devices - start with HTTPS=1 (self-signed cert)")
    app.run(debug=app.config.get("DEBUG", False), host=host, port=port, ssl_context="adhoc" if https else None)
