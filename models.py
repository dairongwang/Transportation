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
