"""
Uber-like Service Marketplace App

Entry point + marketplace routes. Authentication (including two-factor
authentication via authenticator app, e-mail and SMS) lives in the `auth` package.

Configuration is read from environment variables / .env (see .env.example).
"""

import logging
import os
import uuid

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from config import get_config
from extensions import csrf, db, login_manager
from models import Booking, Service, User

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

    if app.testing:
        # Test clients reuse an already-pushed app context, so Flask-Login's per-request
        # cache in `g` would leak between clients. Real requests always start with a fresh `g`.
        from flask import g

        @app.before_request
        def _fresh_login_cache():
            g.pop("_login_user", None)
    app.register_blueprint(auth_bp)
    if app.config.get("OAUTH_MODE") == "fake" and app.config.get("ENABLE_DEV_TOOLS"):
        from auth.fake_oauth import fake_oauth_bp  # stub identity provider at /dev/oauth/...

        app.register_blueprint(fake_oauth_bp)
    register_marketplace_routes(app)
    register_devtools(app)
    register_security_headers(app)

    with app.app_context():
        from migrations import upgrade

        upgrade()
        if app.config.get("SEED_DEMO_DATA"):
            seed_demo_data()

    return app


def register_security_headers(app: Flask) -> None:
    from auth import captcha

    @app.after_request
    def _headers(resp):
        extra = " ".join(captcha.csp_sources())
        frame_src = extra or "'none'"  # (computed outside the f-string: py3.10/3.11 forbid backslashes inside)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; "
            f"style-src 'self' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net {extra}; "
            f"frame-src {frame_src}; frame-ancestors 'none'",
        )
        if app.config.get("SESSION_COOKIE_SECURE"):
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        # Never cache authenticated / auth pages.
        if request.path.startswith(("/settings", "/2fa", "/dashboard", "/login", "/dev")):
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
        my_services = Service.query.filter_by(seller_id=current_user.id).all()
        my_bookings = Booking.query.filter_by(buyer_id=current_user.id).all()
        incoming = Booking.query.join(Service).filter(Service.seller_id == current_user.id).all()
        return render_template(
            "dashboard.html", my_services=my_services, my_bookings=my_bookings, incoming=incoming
        )

    @app.route("/post_service", methods=["GET", "POST"])
    @login_required
    def post_service():
        if current_user.role == "buyer":
            flash("Your account is buyer-only and cannot post services.", "error")
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
    seller = User(username="demo_seller", email="demo.seller@example.com", role="seller")
    seller.set_password("dummySellerPass123")  # DUMMY PASSWORD
    buyer = User(username="demo_buyer", email="demo.buyer@example.com", role="buyer")
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


if __name__ == "__main__":
    app = create_app()
    # Development server only. In production use gunicorn (Linux/macOS) or waitress (Windows) behind HTTPS.
    # HOST=0.0.0.0 exposes the app on your LAN so phones/tablets can reach it (see README).
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    app.logger.info("Secrets: SECRET_KEY=%s MFA_ENCRYPTION_KEY=%s",
                    "DUMMY" if app.config["SECRET_KEY"].upper().startswith("DUMMY") else "set",
                    "DUMMY" if app.config["MFA_ENCRYPTION_KEY"] == "RFVNTVktTUZBLUVOQ1JZUFRJT04tS0VZLTMyQllURVM=" else "set")
    if host == "0.0.0.0":
        from devtools import lan_addresses

        for ip in lan_addresses():
            app.logger.info("Reachable from other devices at http://%s:%s", ip, port)
    app.run(debug=app.config.get("DEBUG", False), host=host, port=port)
