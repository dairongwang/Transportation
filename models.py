"""Database models."""

from datetime import timedelta

from clock import utcnow

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db, login_manager

MFA_METHODS = ("totp", "email", "sms")


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # False for accounts created through social login until the user sets a password.
    password_is_usable = db.Column(db.Boolean, default=True, nullable=False)
    display_name = db.Column(db.String(120), nullable=True)
    role = db.Column(db.String(20), default="both")  # buyer, seller, both
    created_at = db.Column(db.DateTime, default=utcnow)

    # ----- contact verification
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    phone = db.Column(db.String(20), nullable=True)  # E.164, e.g. +15551234567
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)

    # ----- two-factor authentication
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    totp_secret_enc = db.Column(db.String(255), nullable=True)  # encrypted at rest
    totp_last_counter = db.Column(db.Integer, nullable=True)  # replay protection
    email_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    sms_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    preferred_2fa_method = db.Column(db.String(10), nullable=True)  # totp | email | sms

    # ----- brute-force protection
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)

    services = db.relationship("Service", backref="seller", lazy=True)
    bookings = db.relationship("Booking", backref="buyer", lazy=True)
    recovery_codes = db.relationship(
        "RecoveryCode", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    reset_tokens = db.relationship(
        "PasswordResetToken", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    oauth_accounts = db.relationship(
        "OAuthAccount", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    trusted_devices = db.relationship(
        "TrustedDevice", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    # ---------------------------------------------------------------- roles
    # What each role may do (used by the navigation, the dashboard and the route guards):
    #                        buyer   seller   both
    #   can_ride               ✓       -       ✓     request rides (Ride tab, My Recent Rides)
    #   can_sell               -       ✓       ✓     drive, receive bookings (Drive tab, Incoming requests)
    #   can_post_services      -       -       ✓     post services (Post Service tab, My Posted Services)
    @property
    def can_ride(self) -> bool:
        return self.role != "seller"

    @property
    def can_sell(self) -> bool:
        return self.role != "buyer"

    @property
    def can_post_services(self) -> bool:
        return self.role == "both"

    # ------------------------------------------------------------ passwords
    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)
        self.password_is_usable = True
        self.password_changed_at = utcnow()

    def set_unusable_password(self) -> None:
        """For social-login accounts: a random hash nobody knows; reset flow can replace it."""
        import secrets

        self.password_hash = generate_password_hash(secrets.token_urlsafe(32))
        self.password_is_usable = False
        self.password_changed_at = utcnow()

    def check_password(self, password: str) -> bool:
        if not self.password_is_usable:
            return False
        return check_password_hash(self.password_hash, password)

    # ------------------------------------------------------------------ mfa
    @property
    def mfa_enabled(self) -> bool:
        return bool(self.totp_enabled or self.email_2fa_enabled or self.sms_2fa_enabled)

    @property
    def enabled_mfa_methods(self) -> list[str]:
        methods = []
        if self.totp_enabled:
            methods.append("totp")
        if self.email_2fa_enabled:
            methods.append("email")
        if self.sms_2fa_enabled:
            methods.append("sms")
        return methods

    @property
    def default_mfa_method(self) -> str | None:
        methods = self.enabled_mfa_methods
        if not methods:
            return None
        if self.preferred_2fa_method in methods:
            return self.preferred_2fa_method
        return methods[0]

    @property
    def unused_recovery_code_count(self) -> int:
        return sum(1 for c in self.recovery_codes if c.used_at is None)

    # -------------------------------------------------------------- lockout
    @property
    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > utcnow())

    def register_failed_login(self, max_attempts: int, lockout_seconds: int) -> bool:
        """Returns True if this failure caused the account to lock."""
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = utcnow() + timedelta(seconds=lockout_seconds)
            self.failed_login_attempts = 0
            return True
        return False

    def reset_login_failures(self) -> None:
        self.failed_login_attempts = 0
        self.locked_until = None

    # ------------------------------------------------------------ sessions
    @property
    def password_stamp(self) -> int:
        """Changes whenever the password changes; embedded in the session so old sessions die."""
        return int(self.password_changed_at.timestamp() * 1_000_000) if self.password_changed_at else 0

    def get_id(self):  # type: ignore[override]  (Flask-Login identity stored in the session)
        return f"{self.id}|{self.password_stamp}"


class OneTimeCode(db.Model):
    """Short-lived numeric codes delivered by email or SMS (hashed at rest)."""

    __tablename__ = "one_time_code"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    channel = db.Column(db.String(10), nullable=False)  # email | sms
    purpose = db.Column(db.String(30), nullable=False)  # login | verify_email | verify_phone
    destination = db.Column(db.String(120), nullable=False)  # address the code was sent to
    code_hash = db.Column(db.String(128), nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    consumed_at = db.Column(db.DateTime, nullable=True)

    @property
    def is_expired(self) -> bool:
        return utcnow() >= self.expires_at

    @property
    def is_usable(self) -> bool:
        return self.consumed_at is None and not self.is_expired


class RecoveryCode(db.Model):
    __tablename__ = "recovery_code"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)


class TrustedDevice(db.Model):
    """Browsers on which the user chose 'remember this device' after a 2FA login."""

    __tablename__ = "trusted_device"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(128), nullable=False, unique=True)
    user_agent = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)

    @property
    def is_valid(self) -> bool:
        return utcnow() < self.expires_at


class OAuthAccount(db.Model):
    """A social identity (Google / Apple / Facebook) linked to a local user."""

    __tablename__ = "oauth_account"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    provider = db.Column(db.String(20), nullable=False)  # google | apple | facebook
    provider_user_id = db.Column(db.String(255), nullable=False)  # the provider's stable subject id
    email = db.Column(db.String(120), nullable=True)  # e-mail as asserted by the provider
    display_name = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    __table_args__ = (db.UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_subject"),)


class PasswordResetToken(db.Model):
    """Single-use, time-limited password-reset tokens (hashed at rest)."""

    __tablename__ = "password_reset_token"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(128), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)

    @property
    def is_usable(self) -> bool:
        return self.used_at is None and utcnow() < self.expires_at


class AuthEvent(db.Model):
    """Security audit trail."""

    __tablename__ = "auth_event"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    event = db.Column(db.String(50), nullable=False)
    detail = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    __table_args__ = (db.Index("ix_auth_event_ip_event_time", "ip_address", "event", "created_at"),)


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # ride, delivery, cleaning, tutoring, etc.
    price = db.Column(db.Float, nullable=False)
    location = db.Column(db.String(200))
    available = db.Column(db.Boolean, default=True)
    seller_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_id = db.Column(db.Integer, db.ForeignKey("service.id"), nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(30), default="pending")
    payment_token = db.Column(db.String(100))  # DUMMY token
    amount = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    service = db.relationship("Service")


# ============================================================ ride hailing

RIDE_STATUSES = ("searching", "offered", "accepted", "in_progress", "completed", "cancelled", "no_drivers")
OFFER_STATUSES = ("ranked", "pending", "accepted", "declined", "expired", "skipped")


class DriverProfile(db.Model):
    """A user who offers rides. Location/online state is what the matcher searches."""

    __tablename__ = "driver_profile"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    vehicle = db.Column(db.String(80), nullable=False, default="Sedan")
    plate = db.Column(db.String(20), nullable=True)  # DUMMY plates in demo data
    # --- pricing (the "price" ranking criterion is the fare quoted from these)
    base_fare = db.Column(db.Float, nullable=False, default=2.5)
    per_km_rate = db.Column(db.Float, nullable=False, default=1.2)
    per_min_rate = db.Column(db.Float, nullable=False, default=0.25)
    min_fare = db.Column(db.Float, nullable=False, default=5.0)
    # --- live state (GPS stub: drivers post their position manually or via the API)
    is_online = db.Column(db.Boolean, nullable=False, default=False)
    lat = db.Column(db.Float, nullable=True)
    lng = db.Column(db.Float, nullable=True)
    location_updated_at = db.Column(db.DateTime, nullable=True)
    # --- reputation (the "rating" and "acceptance rate" ranking criteria)
    rating_sum = db.Column(db.Float, nullable=False, default=0.0)
    rating_count = db.Column(db.Integer, nullable=False, default=0)
    offers_received = db.Column(db.Integer, nullable=False, default=0)
    offers_accepted = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    user = db.relationship("User", backref=db.backref("driver_profile", uselist=False))

    DEFAULT_RATING = 4.5  # prior for drivers without ratings yet (keeps newcomers competitive)
    DEFAULT_ACCEPTANCE = 0.8  # prior for drivers who never received an offer

    @property
    def rating(self) -> float:
        if not self.rating_count:
            return self.DEFAULT_RATING
        return self.rating_sum / self.rating_count

    @property
    def acceptance_rate(self) -> float:
        if not self.offers_received:
            return self.DEFAULT_ACCEPTANCE
        return self.offers_accepted / self.offers_received

    @property
    def has_location(self) -> bool:
        return self.lat is not None and self.lng is not None

    def location_is_fresh(self, max_age_seconds: int) -> bool:
        if not self.has_location or self.location_updated_at is None:
            return False
        return (utcnow() - self.location_updated_at).total_seconds() <= max_age_seconds

    @property
    def location_age_seconds(self) -> int | None:
        if not self.has_location or self.location_updated_at is None:
            return None
        return int((utcnow() - self.location_updated_at).total_seconds())

    def availability(self, max_age_seconds: int) -> tuple[bool, str]:
        """(visible to riders?, reason) - what the matcher would decide for this driver right now."""
        from background.service import can_drive

        if not can_drive(self.user):
            return False, "your background check does not cover driving yet - add your driving licence on the Background check page"
        if not self.is_online:
            return False, "you are marked as not available"
        if not self.has_location:
            return False, "no position yet - share your GPS location"
        if not self.location_is_fresh(max_age_seconds):
            return False, f"your position is older than {max_age_seconds // 60} min - refresh it"
        return True, "riders searching within range of your position see you in their ranked list"

    def quote(self, distance_km: float, duration_min: float) -> float:
        fare = self.base_fare + self.per_km_rate * distance_km + self.per_min_rate * duration_min
        return round(max(fare, self.min_fare), 2)

    def add_rating(self, stars: int) -> None:
        self.rating_sum += float(stars)
        self.rating_count += 1


class RideRequest(db.Model):
    """A rider's request. Goes searching -> offered -> accepted -> in_progress -> completed."""

    __tablename__ = "ride_request"

    id = db.Column(db.Integer, primary_key=True)
    rider_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    driver_id = db.Column(db.Integer, db.ForeignKey("driver_profile.id"), nullable=True, index=True)
    pickup_address = db.Column(db.String(200), nullable=False)
    pickup_lat = db.Column(db.Float, nullable=False)
    pickup_lng = db.Column(db.Float, nullable=False)
    dropoff_address = db.Column(db.String(200), nullable=False)
    dropoff_lat = db.Column(db.Float, nullable=False)
    dropoff_lng = db.Column(db.Float, nullable=False)
    trip_distance_km = db.Column(db.Float, nullable=False, default=0.0)
    trip_duration_min = db.Column(db.Float, nullable=False, default=0.0)
    status = db.Column(db.String(20), nullable=False, default="searching", index=True)
    auto_dispatch = db.Column(db.Boolean, nullable=False, default=True)
    # The driver the rider has picked from the ranked list but not ordered yet (changeable).
    # Pressing "Order" turns the selection into the pending offer (and places the hold).
    selected_offer_id = db.Column(db.Integer, nullable=True)
    fare = db.Column(db.Float, nullable=True)  # fare of the accepted offer
    payment_token = db.Column(db.String(100), nullable=True)  # DUMMY authorisation token (at accept)
    # How the rider pays: a stored PaymentMethod, or cash when None. Charged on completion.
    payment_method_id = db.Column(db.Integer, db.ForeignKey("payment_method.id"), nullable=True)
    payment_status = db.Column(db.String(12), nullable=True)  # cash | paid | failed (set on completion)
    # Pre-authorisation: when the rider picks a driver, RIDE_PREAUTH_FACTOR x the driver's
    # quoted fare is held on the payment method (captured on completion, released otherwise).
    preauth_amount = db.Column(db.Float, nullable=True)
    preauth_ref = db.Column(db.String(120), nullable=True)  # auth_DUMMY.. hold reference at the gateway
    preauth_status = db.Column(db.String(12), nullable=True)  # held | captured | released | failed
    preauth_at = db.Column(db.DateTime, nullable=True)
    rider_rating = db.Column(db.Integer, nullable=True)  # 1..5, given after completion
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    rider = db.relationship("User", backref=db.backref("ride_requests", lazy=True))
    driver = db.relationship("DriverProfile", backref=db.backref("rides", lazy=True))
    payment_method = db.relationship("PaymentMethod", foreign_keys=[payment_method_id])
    offers = db.relationship(
        "RideOffer", backref="ride", lazy=True, cascade="all, delete-orphan", order_by="RideOffer.rank"
    )

    @property
    def is_open(self) -> bool:
        return self.status in ("searching", "offered")

    @property
    def is_terminal(self) -> bool:
        return self.status in ("completed", "cancelled", "no_drivers")

    @property
    def pending_offer(self):
        return next((o for o in self.offers if o.status == "pending"), None)

    @property
    def selected_offer(self):
        """The rider's current (not yet ordered) choice, if it can still be ordered."""
        if self.selected_offer_id is None:
            return None
        return next((o for o in self.offers if o.id == self.selected_offer_id and o.status == "ranked"), None)

    @property
    def awaiting_order(self) -> bool:
        """Open, nobody is being asked: the rider can select a driver and place the order."""
        return self.is_open and self.pending_offer is None

    @property
    def accepted_offer(self):
        return next((o for o in self.offers if o.status == "accepted"), None)

    @property
    def has_hold(self) -> bool:
        """An authorisation hold is outstanding on the rider's payment method."""
        return self.preauth_status == "held" and bool(self.preauth_ref)

    @property
    def estimated_fare(self) -> float | None:
        """The quote of the driver currently asked / assigned (what the hold was sized from)."""
        offer = self.accepted_offer or self.pending_offer
        return offer.price if offer else self.fare


class RideOffer(db.Model):
    """One ranked candidate driver for a ride, with the score breakdown that ranked it."""

    __tablename__ = "ride_offer"

    id = db.Column(db.Integer, primary_key=True)
    ride_id = db.Column(db.Integer, db.ForeignKey("ride_request.id"), nullable=False, index=True)
    driver_id = db.Column(db.Integer, db.ForeignKey("driver_profile.id"), nullable=False, index=True)
    rank = db.Column(db.Integer, nullable=False)  # 1 = best
    score = db.Column(db.Float, nullable=False)  # 0..1, higher is better
    distance_km = db.Column(db.Float, nullable=False)  # driver -> pickup
    eta_min = db.Column(db.Float, nullable=False)
    price = db.Column(db.Float, nullable=False)  # quoted fare for the whole trip
    rating = db.Column(db.Float, nullable=False)  # snapshot at ranking time
    acceptance_rate = db.Column(db.Float, nullable=False)  # snapshot at ranking time
    status = db.Column(db.String(20), nullable=False, default="ranked", index=True)
    offered_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    responded_at = db.Column(db.DateTime, nullable=True)

    driver = db.relationship("DriverProfile", backref=db.backref("offers", lazy=True))

    __table_args__ = (db.UniqueConstraint("ride_id", "driver_id", name="uq_ride_offer_driver"),)

    @property
    def is_expired(self) -> bool:
        return self.status == "pending" and self.expires_at is not None and utcnow() > self.expires_at


# ============================================================ rider <-> driver chat

CHAT_MESSAGE_KINDS = ("text", "location", "system")


class RideChat(db.Model):
    """
    The chat room between a rider and ONE driver for one ride (see rides/chat.py).

    It opens the moment the rider places the order with that driver (auto-dispatch: the moment
    the driver is asked), so the two can agree on how to meet. It closes when that driver
    declines / does not answer / hands the ride back, or when the ride ends (completed or
    cancelled). A closed room stays readable for both participants but takes no new messages.
    If dispatch moves on to another driver, that driver gets a NEW room: drivers never see
    what the rider wrote to a previous driver.
    """

    __tablename__ = "ride_chat"

    id = db.Column(db.Integer, primary_key=True)
    ride_id = db.Column(db.Integer, db.ForeignKey("ride_request.id"), nullable=False, index=True)
    driver_id = db.Column(db.Integer, db.ForeignKey("driver_profile.id"), nullable=False, index=True)
    # Participants (denormalised so every authorisation check is a plain comparison).
    rider_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    driver_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    opened_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    closed_at = db.Column(db.DateTime, nullable=True)
    close_reason = db.Column(db.String(120), nullable=True)
    # Read markers: id of the last message each participant has seen (unread badges).
    rider_last_read_id = db.Column(db.Integer, nullable=False, default=0)
    driver_last_read_id = db.Column(db.Integer, nullable=False, default=0)

    ride = db.relationship("RideRequest", backref=db.backref("chats", lazy=True, order_by="RideChat.id"))
    driver = db.relationship("DriverProfile")
    rider = db.relationship("User", foreign_keys=[rider_id])
    driver_user = db.relationship("User", foreign_keys=[driver_user_id])
    messages = db.relationship("ChatMessage", backref="chat", lazy=True, cascade="all, delete-orphan",
                               order_by="ChatMessage.id")

    __table_args__ = (db.UniqueConstraint("ride_id", "driver_id", name="uq_ride_chat_driver"),)

    @property
    def is_open(self) -> bool:
        return self.closed_at is None

    def is_participant(self, user) -> bool:
        return user is not None and user.id in (self.rider_id, self.driver_user_id)

    def role_of(self, user) -> str | None:
        if user is None:
            return None
        if user.id == self.rider_id:
            return "rider"
        if user.id == self.driver_user_id:
            return "driver"
        return None

    def other_party(self, user):
        return self.driver_user if user.id == self.rider_id else self.rider


class ChatMessage(db.Model):
    """One message in a RideChat. kind: text | location (lat/lng) | system (sender_id is NULL)."""

    __tablename__ = "chat_message"

    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey("ride_chat.id"), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)  # NULL = system message
    kind = db.Column(db.String(10), nullable=False, default="text")
    body = db.Column(db.Text, nullable=False)
    lat = db.Column(db.Float, nullable=True)
    lng = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    sender = db.relationship("User")


# ============================================================ payments

PAYMENT_KINDS = ("card", "stripe", "paypal")
PAYMENT_KIND_LABELS = {"card": "Credit / debit card", "stripe": "Stripe", "paypal": "PayPal"}


class PaymentMethod(db.Model):
    """
    A rider's stored way to pay - a CARD ON FILE TOKEN, never a card number.

    The browser tokenises the card with the vault; our server only receives a single-use
    token and exchanges it for a customer-bound token ID (card_DUMMY... / pm_DUMMY... /
    BA-DUMMY...). That ID is what we store - encrypted at rest with MFA_ENCRYPTION_KEY - and
    what every charge uses. Display data (brand, last4, expiry) is kept alongside.
    Rows are soft-deleted (deleted_at) so past transactions keep their reference.
    """

    __tablename__ = "payment_method"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    kind = db.Column(db.String(10), nullable=False)  # card | stripe | paypal
    label = db.Column(db.String(60), nullable=True)  # user nickname, e.g. "Work card"
    # Encrypted card-on-file token ID (column keeps its historical name "provider_token").
    token_id_enc = db.Column("provider_token", db.Text, nullable=False)
    # Vault fingerprint of the physical card (same card -> same fingerprint, reveals nothing).
    fingerprint = db.Column(db.String(64), nullable=True, index=True)
    # --- card details (display only)
    brand = db.Column(db.String(20), nullable=True)  # visa | mastercard | amex | discover | card
    last4 = db.Column(db.String(4), nullable=True)
    exp_month = db.Column(db.Integer, nullable=True)
    exp_year = db.Column(db.Integer, nullable=True)
    billing_name = db.Column(db.String(120), nullable=True)
    # --- wallet details (stripe / paypal): MASKED e-mail only (d•••r@p•••l.example). The full
    # address never reaches this app; the vault identifies the account by `fingerprint`.
    account_email_masked = db.Column("account_email", db.String(120), nullable=True)
    is_default = db.Column(db.Boolean, nullable=False, default=False)
    # --- validation: a small authorisation hold that was voided right away (see service.validate_method)
    verified_at = db.Column(db.DateTime, nullable=True)
    verification_ref = db.Column(db.String(120), nullable=True)  # auth_DUMMY.. of the voided hold
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True, index=True)

    user = db.relationship("User", backref=db.backref("payment_methods", lazy=True))

    @property
    def is_verified(self) -> bool:
        return self.verified_at is not None

    # ---- token id (encrypted at rest; decrypted only when talking to the gateway)
    @property
    def token_id(self) -> str | None:
        from auth import crypto

        return crypto.decrypt_secret(self.token_id_enc) if self.token_id_enc else None

    @token_id.setter
    def token_id(self, value: str) -> None:
        from auth import crypto

        self.token_id_enc = crypto.encrypt_secret(value)

    @property
    def token_hint(self) -> str:
        """Support-friendly identifier (prefix + last 6 chars of the token id)."""
        from payments.vault import token_hint

        return token_hint(self.token_id or "")

    @property
    def kind_label(self) -> str:
        return PAYMENT_KIND_LABELS.get(self.kind, self.kind)

    @property
    def display(self) -> str:
        if self.kind == "card":
            return f"{(self.brand or 'card').title()} •••• {self.last4}"
        return f"{self.kind_label} ({self.account_email_masked})"

    @property
    def expiry(self) -> str:
        if self.exp_month and self.exp_year:
            return f"{self.exp_month:02d}/{self.exp_year % 100:02d}"
        return ""

    @property
    def is_expired(self) -> bool:
        if self.kind != "card" or not (self.exp_month and self.exp_year):
            return False
        now = utcnow()
        return (self.exp_year, self.exp_month) < (now.year, now.month)


TRANSACTION_KINDS = ("charge", "hold", "verification", "refund")


class PaymentTransaction(db.Model):
    """
    A money operation against a payment method:
      charge        a ride payment (succeeded / failed)
      hold          the pre-authorisation placed when a driver is ordered (held / captured / released / failed)
      verification  the small hold placed and voided to validate a new payment method
      refund        money returned for a charge (refund_of_id -> that charge), issued by a manager
    """

    __tablename__ = "payment_transaction"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    payment_method_id = db.Column(db.Integer, db.ForeignKey("payment_method.id"), nullable=True, index=True)
    ride_id = db.Column(db.Integer, db.ForeignKey("ride_request.id"), nullable=True, index=True)
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), nullable=False, default="USD")
    status = db.Column(db.String(12), nullable=False)  # succeeded | failed | voided (validation hold)
    provider_ref = db.Column(db.String(120), nullable=True)  # ch_DUMMY.. from the gateway
    failure_reason = db.Column(db.String(120), nullable=True)
    description = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    kind = db.Column(db.String(14), nullable=True, index=True)  # TRANSACTION_KINDS (backfilled by migrations.py)
    refund_of_id = db.Column(db.Integer, db.ForeignKey("payment_transaction.id"), nullable=True, index=True)
    refund_reason = db.Column(db.String(300), nullable=True)
    created_by = db.Column(db.String(80), nullable=True)  # manager who issued a refund (admin dashboard)

    user = db.relationship("User", backref=db.backref("payment_transactions", lazy=True))
    refund_of = db.relationship("PaymentTransaction", remote_side=[id], backref=db.backref("refunds", lazy=True))
    payment_method = db.relationship("PaymentMethod", backref=db.backref("transactions", lazy=True))
    ride = db.relationship("RideRequest", backref=db.backref("transactions", lazy=True))


# ============================================================ background checks

BACKGROUND_CHECK_STATUSES = ("pending", "clear", "consider", "unverified", "rejected")
BACKGROUND_CHECK_PACKAGES = ("standard", "driver")
# Screens run by each package (the provider reports one result per screen).
BACKGROUND_CHECK_SCREENS = {
    "standard": ("identity", "criminal", "sex_offender", "global_watchlist"),
    "driver": ("identity", "criminal", "sex_offender", "global_watchlist", "motor_vehicle"),
}
SCREEN_LABELS = {
    "identity": "Identity verification",
    "criminal": "Criminal records",
    "sex_offender": "Sex-offender registry",
    "global_watchlist": "Global watchlists",
    "motor_vehicle": "Motor vehicle record (driving licence)",
}


class BackgroundCheck(db.Model):
    """
    One background-check report for a user (a user can have several over time: a re-check
    after expiry, an upgrade to the driver package, a corrected resubmission).

    Only what the check needs is collected - legal name, date of birth and, for drivers,
    the driving licence. NO national ID / SSN, phone number or payment data. The date of
    birth and the licence number are encrypted at rest (MFA_ENCRYPTION_KEY); only the
    licence's last 4 characters are kept in clear for display.

    status
      pending     submitted, the provider is still working on it
      clear       nothing found                       -> passed (until expires_at)
      consider    something needs review (records found, suspended licence)   -> not passed
      unverified  the identity could not be verified   -> not passed, the user may resubmit
      rejected    final adverse decision               -> not passed, no resubmission
    """

    __tablename__ = "background_check"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    package = db.Column(db.String(10), nullable=False, default="standard")  # standard | driver
    status = db.Column(db.String(12), nullable=False, default="pending", index=True)
    provider = db.Column(db.String(20), nullable=False, default="fake")
    provider_ref = db.Column(db.String(64), nullable=True, unique=True)  # bgc_DUMMY_... at the provider
    # --- applicant (minimal)
    legal_first_name = db.Column(db.String(80), nullable=False)
    legal_last_name = db.Column(db.String(80), nullable=False)
    date_of_birth_enc = db.Column(db.Text, nullable=False)  # "YYYY-MM-DD", encrypted
    licence_number_enc = db.Column(db.Text, nullable=True)  # encrypted; driver package only
    licence_last4 = db.Column(db.String(4), nullable=True)
    licence_region = db.Column(db.String(40), nullable=True)  # issuing state / region
    # --- consent (FCRA-style disclosure & authorisation)
    consent_at = db.Column(db.DateTime, nullable=False)
    consent_ip = db.Column(db.String(45), nullable=True)
    # --- result
    screens_json = db.Column(db.Text, nullable=True)  # {"identity": "clear", "criminal": "consider", ...}
    result_note = db.Column(db.String(255), nullable=True)  # user-facing explanation
    adjudication = db.Column(db.String(12), nullable=True)  # approved | rejected (manual review)
    adjudicated_at = db.Column(db.DateTime, nullable=True)
    adjudicated_by = db.Column(db.String(80), nullable=True)  # manager (admin dashboard) who decided
    # A re-check raised by a DISPUTE: its result is only advice for the manager, so it neither
    # grants nor revokes access until the manager decides the dispute (background_dispute).
    held_for_review = db.Column(db.Boolean, nullable=False, default=False)
    submitted_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)  # a clear result is valid until then

    user = db.relationship("User", backref=db.backref("background_checks", lazy=True, order_by="BackgroundCheck.id"))

    # ---- encrypted fields
    @property
    def date_of_birth(self):
        from datetime import date

        from auth import crypto

        raw = crypto.decrypt_secret(self.date_of_birth_enc) if self.date_of_birth_enc else None
        try:
            return date.fromisoformat(raw) if raw else None
        except ValueError:
            return None

    @date_of_birth.setter
    def date_of_birth(self, value) -> None:
        from auth import crypto

        self.date_of_birth_enc = crypto.encrypt_secret(value.isoformat())

    @property
    def licence_number(self) -> str | None:
        from auth import crypto

        return crypto.decrypt_secret(self.licence_number_enc) if self.licence_number_enc else None

    @licence_number.setter
    def licence_number(self, value: str | None) -> None:
        from auth import crypto

        if value:
            self.licence_number_enc = crypto.encrypt_secret(value)
            self.licence_last4 = value[-4:]
        else:
            self.licence_number_enc = None
            self.licence_last4 = None

    # ---- results
    @property
    def screens(self) -> dict:
        import json

        try:
            data = json.loads(self.screens_json or "{}")
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    @screens.setter
    def screens(self, value: dict) -> None:
        import json

        self.screens_json = json.dumps(value or {}, sort_keys=True)

    @property
    def legal_name(self) -> str:
        return f"{self.legal_first_name} {self.legal_last_name}".strip()

    @property
    def covers_driving(self) -> bool:
        return self.package == "driver"

    @property
    def is_expired(self) -> bool:
        return self.expires_at is not None and utcnow() >= self.expires_at

    @property
    def is_decisive(self) -> bool:
        """A final answer about the person (pending / unverified say nothing about them yet;
        a dispute re-check says nothing until the manager has decided)."""
        return self.status in ("clear", "consider", "rejected") and not self.held_for_review

    @property
    def is_passed(self) -> bool:
        return self.status == "clear" and not self.is_expired


DISPUTE_STATUSES = ("rechecking", "under_review", "approved", "rejected")


class BackgroundDispute(db.Model):
    """
    A rejected user disputes the decision. The dispute escalates to ANOTHER background check
    (`recheck`, possibly with corrected details) and then to a manager, who reads the user's
    statement, the original report and the re-check and decides: approve (-> clear) or reject.

    status
      rechecking    the re-check is still pending at the provider
      under_review  the re-check is back; waiting for a manager (admin dashboard)
      approved      the manager approved -> the user passes
      rejected      the manager upheld the rejection -> final
    """

    __tablename__ = "background_dispute"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    check_id = db.Column(db.Integer, db.ForeignKey("background_check.id"), nullable=False)  # the rejected report
    recheck_id = db.Column(db.Integer, db.ForeignKey("background_check.id"), nullable=True)  # the escalation
    statement = db.Column(db.Text, nullable=False)  # the user's explanation
    status = db.Column(db.String(14), nullable=False, default="rechecking", index=True)
    decision_note = db.Column(db.String(500), nullable=True)  # shown to the user
    decided_by = db.Column(db.String(80), nullable=True)  # manager username (admin dashboard)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    decided_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", backref=db.backref("background_disputes", lazy=True, order_by="BackgroundDispute.id"))
    check = db.relationship("BackgroundCheck", foreign_keys=[check_id])
    recheck = db.relationship("BackgroundCheck", foreign_keys=[recheck_id])

    @property
    def is_open(self) -> bool:
        return self.status in ("rechecking", "under_review")


@login_manager.user_loader
def load_user(identity: str):
    """Resolve the session identity; reject it if the password changed since login."""
    user_id, _, stamp = identity.partition("|")
    try:
        user = db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None
    if user is None:
        return None
    if stamp and stamp != str(user.password_stamp):
        return None  # password was changed/reset after this session was created
    return user
