"""
Application configuration.

Values come from environment variables or a `.env` file in the project folder
(python-dotenv loads it). `.env.example` is the template: copy it to `.env`.

SECRET_KEY and MFA_ENCRYPTION_KEY are REQUIRED - there is no in-code fallback for
development or production. The template ships DUMMY_* values so the app starts
immediately for local testing; `APP_ENV=production` refuses any DUMMY_* value.

Key roles (so you know what a rotation affects):
  SECRET_KEY              signs the session cookie and CSRF tokens. Rotating it logs
                          everyone out - nothing else.
  MFA_ENCRYPTION_KEY      encrypts authenticator secrets and keys the HMACs of one-time
                          codes, recovery codes, trusted-device tokens and reset tokens.
                          Rotate with MFA_ENCRYPTION_KEY_PREVIOUS + scripts/rotate_keys.py
                          so nothing is invalidated.
"""

import os
import platform
import sys

from dotenv import load_dotenv

load_dotenv()

# ============ DUMMY PLACEHOLDERS (match .env.example; never use in production) ============
DUMMY_SECRET_KEY = "DUMMY_FLASK_SECRET_KEY_CHANGE_ME"
# Any string works as MFA_ENCRYPTION_KEY (auth/crypto.py derives 32 bytes from it); a real
# deployment uses 32 random bytes, base64-encoded (see README "Generate real keys").
DUMMY_MFA_ENCRYPTION_KEY = "DUMMY_MFA_ENCRYPTION_KEY_CHANGE_ME"
# Placeholder shipped by earlier builds: base64("DUMMY-MFA-ENCRYPTION-KEY-32BYTES"). Still
# treated as a dummy value (production refuses it); list it in MFA_ENCRYPTION_KEY_PREVIOUS
# to read a database created with it and run scripts/rotate_keys.py.
LEGACY_DUMMY_MFA_ENCRYPTION_KEYS = frozenset({"RFVNTVktTUZBLUVOQ1JZUFRJT04tS0VZLTMyQllURVM="})
DUMMY_PAYMENT_GATEWAY_KEY = "DUMMY_PAYMENT_KEY"
DUMMY_MAPS_API_KEY = "DUMMY_MAPS_API_KEY"
DUMMY_STRIPE_PUBLISHABLE_KEY = "DUMMY_STRIPE_PUBLISHABLE_KEY"
DUMMY_STRIPE_SECRET_KEY = "DUMMY_STRIPE_SECRET_KEY"
DUMMY_PAYPAL_CLIENT_ID = "DUMMY_PAYPAL_CLIENT_ID"
DUMMY_PAYPAL_CLIENT_SECRET = "DUMMY_PAYPAL_CLIENT_SECRET"
# Signs the tokens minted by the FAKE card vault (payments/vault.py). Dummy by design.
DUMMY_FAKE_VAULT_SIGNING_KEY = "DUMMY_FAKE_VAULT_SIGNING_KEY"
DUMMY_JWT_SECRET = "DUMMY_JWT_SECRET"
DUMMY_SMTP_USERNAME = "DUMMY_SMTP_USER"
DUMMY_SMTP_PASSWORD = "DUMMY_SMTP_PASSWORD"
DUMMY_TWILIO_ACCOUNT_SID = "DUMMY_TWILIO_ACCOUNT_SID"
DUMMY_TWILIO_AUTH_TOKEN = "DUMMY_TWILIO_AUTH_TOKEN"
DUMMY_TWILIO_FROM_NUMBER = "+15550100000"  # 555-01xx numbers are reserved for fiction
DUMMY_CAPTCHA_SITE_KEY = "DUMMY_CAPTCHA_SITE_KEY"
DUMMY_CAPTCHA_SECRET_KEY = "DUMMY_CAPTCHA_SECRET_KEY"
DUMMY_OAUTH = {
    "GOOGLE_CLIENT_ID": "DUMMY_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
    "GOOGLE_CLIENT_SECRET": "DUMMY_GOOGLE_CLIENT_SECRET",
    "FACEBOOK_APP_ID": "DUMMY_FACEBOOK_APP_ID",
    "FACEBOOK_APP_SECRET": "DUMMY_FACEBOOK_APP_SECRET",
    "APPLE_CLIENT_ID": "DUMMY_APPLE_SERVICE_ID",
    "APPLE_TEAM_ID": "DUMMY_APPLE_TEAM_ID",
    "APPLE_KEY_ID": "DUMMY_APPLE_KEY_ID",
    "APPLE_PRIVATE_KEY": "DUMMY_APPLE_PRIVATE_KEY_PEM",
}
# Shared secret the FAKE identity provider uses to sign id_tokens (HS256). Dummy by design.
DUMMY_FAKE_OAUTH_SIGNING_KEY = "DUMMY_FAKE_OAUTH_SIGNING_KEY"
# Background-check provider credentials (the FAKE provider only checks that a key is set).
DUMMY_BACKGROUND_CHECK_API_KEY = "DUMMY_BACKGROUND_CHECK_API_KEY"
DUMMY_BACKGROUND_CHECK_WEBHOOK_SECRET = "DUMMY_BACKGROUND_CHECK_WEBHOOK_SECRET"
# Shared bearer token of the service-to-service Admin API (used by the separate admin dashboard).
DUMMY_ADMIN_API_TOKEN = "DUMMY_ADMIN_API_TOKEN"

SETUP_HINT = (
    "Copy .env.example to .env (it contains DUMMY values that work for development) "
    "or export the variable in your shell."
)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_list(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def is_dummy(value: str | None) -> bool:
    return (not value or value.upper().startswith("DUMMY") or value == DUMMY_MFA_ENCRYPTION_KEY
            or value in LEGACY_DUMMY_MFA_ENCRYPTION_KEYS)


class BaseConfig:
    # ---------------------------------------------------------------- core
    SECRET_KEY = os.environ.get("SECRET_KEY")
    MFA_ENCRYPTION_KEY = os.environ.get("MFA_ENCRYPTION_KEY")
    MFA_ENCRYPTION_KEY_PREVIOUS = _env_list("MFA_ENCRYPTION_KEY_PREVIOUS")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///uber_services.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # SQLite under concurrent load (several threads / worker processes): WAL lets readers work while
    # one connection writes, synchronous=NORMAL skips the fsync on every commit (still crash-safe
    # in WAL mode), and a writer waits up to SQLITE_BUSY_TIMEOUT_MS for the lock instead of failing
    # with "database is locked". Ignored for other databases (use PostgreSQL in production).
    SQLITE_WAL = _env_bool("SQLITE_WAL", True)
    SQLITE_BUSY_TIMEOUT_MS = _env_int("SQLITE_BUSY_TIMEOUT_MS", 15000)
    # Queue writers on an OS file lock instead of SQLite's sleeping busy handler (POSIX; dbtuning.py).
    SQLITE_WRITE_LOCK = _env_bool("SQLITE_WRITE_LOCK", True)
    APP_NAME = os.environ.get("APP_NAME", "ServiceUber")
    # Absolute URL used in e-mails (password-reset links). Falls back to the request host.
    APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip("/")
    # Number of reverse proxies in front of the app (for correct client IPs). 0 = none.
    BEHIND_PROXY = _env_int("BEHIND_PROXY", 0)

    # Placeholders for future integrations (payments / JWT are unused by the demo).
    PAYMENT_GATEWAY_KEY = os.environ.get("PAYMENT_GATEWAY_KEY") or DUMMY_PAYMENT_GATEWAY_KEY
    MAPS_API_KEY = os.environ.get("MAPS_API_KEY") or DUMMY_MAPS_API_KEY
    JWT_SECRET = os.environ.get("JWT_SECRET") or DUMMY_JWT_SECRET

    # ------------------------------------------------------------ payments
    # PAYMENTS_MODE: fake -> offline gateway stub (payments/gateway.py) with Stripe-style test
    #                        cards and in-app fake Stripe / PayPal approval pages at /dev/payments/..
    #                real -> not implemented in the demo; production refuses DUMMY credentials.
    PAYMENTS_MODE = os.environ.get("PAYMENTS_MODE", "fake").lower()
    PAYMENT_CURRENCY = os.environ.get("PAYMENT_CURRENCY", "USD").upper()[:3]
    STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY") or DUMMY_STRIPE_PUBLISHABLE_KEY
    STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY") or DUMMY_STRIPE_SECRET_KEY
    PAYPAL_CLIENT_ID = os.environ.get("PAYPAL_CLIENT_ID") or DUMMY_PAYPAL_CLIENT_ID
    PAYPAL_CLIENT_SECRET = os.environ.get("PAYPAL_CLIENT_SECRET") or DUMMY_PAYPAL_CLIENT_SECRET
    PAYMENT_METHODS_MAX = _env_int("PAYMENT_METHODS_MAX", 10)
    FAKE_VAULT_SIGNING_KEY = os.environ.get("FAKE_VAULT_SIGNING_KEY") or DUMMY_FAKE_VAULT_SIGNING_KEY
    # Where the BROWSER sends card data to be tokenised (never our server). In fake mode this
    # is the in-app fake vault endpoint; with a real processor it is their JS SDK / hosted field.
    TOKENIZATION_URL = os.environ.get("TOKENIZATION_URL", "/dev/payments/tokenize")
    # Every new / re-dated payment method is validated with a temporary hold of this amount,
    # which is voided immediately. 0 disables validation.
    PAYMENT_VALIDATION_AMOUNT = _env_float("PAYMENT_VALIDATION_AMOUNT", 1.00)
    # When the rider picks a driver, this multiple of the driver's quoted (estimated) fare is
    # pre-authorised on the rider's payment method: 1.5 = the estimate + 50 %. The hold is
    # captured for the actual fare on completion and released if the ride does not happen.
    RIDE_PREAUTH_FACTOR = max(1.0, _env_float("RIDE_PREAUTH_FACTOR", 1.5))

    # ------------------------------------------------------- ride matching
    # MAPS_BACKEND: stub -> offline geocoder + router (rides/geo.py). No real provider is
    # wired in yet; MAPS_API_KEY is only a placeholder for one.
    MAPS_BACKEND = os.environ.get("MAPS_BACKEND", "stub").lower()
    RIDE_SEARCH_RADIUS_KM = _env_float("RIDE_SEARCH_RADIUS_KM", 10.0)
    RIDE_MAX_CANDIDATES = _env_int("RIDE_MAX_CANDIDATES", 8)
    # Score only the N nearest eligible drivers (0 = every driver within the radius). 40 keeps the
    # same best driver in ~92 % of requests for ~25 % less CPU per ride request (loadtest/REPORT.md).
    RIDE_CANDIDATE_POOL = max(0, _env_int("RIDE_CANDIDATE_POOL", 40))
    # In-memory driver index of each worker (rides/driver_index.py): rebuilt when older than this,
    # and at once after this process commits a driver / background-check change. 0 = no caching.
    RIDE_DRIVER_INDEX_TTL_SECONDS = max(0.0, _env_float("RIDE_DRIVER_INDEX_TTL_SECONDS", 2.0))
    RIDE_OFFER_TTL_SECONDS = _env_int("RIDE_OFFER_TTL_SECONDS", 120)
    # Push events with several worker processes (gunicorn -w N): "unix" fans every event out to the
    # other processes on this host (rides/bus.py). "local" (default) = one process.
    EVENT_BUS = os.environ.get("EVENT_BUS", "local").lower()
    EVENT_BUS_DIR = os.environ.get("EVENT_BUS_DIR", "")  # default: <instance>/eventbus
    # Background sweep that times out unanswered offers (push notifications, no client polling). 0 = off.
    RIDE_SWEEP_INTERVAL_SECONDS = _env_int("RIDE_SWEEP_INTERVAL_SECONDS", 10)
    DRIVER_LOCATION_STALE_SECONDS = _env_int("DRIVER_LOCATION_STALE_SECONDS", 1800)
    # Weights of the ranking criteria (rides/matching.py). Normalised per search.
    RIDE_RANK_WEIGHTS = {
        "distance": _env_float("RIDE_RANK_WEIGHT_DISTANCE", 0.40),
        "rating": _env_float("RIDE_RANK_WEIGHT_RATING", 0.25),
        "price": _env_float("RIDE_RANK_WEIGHT_PRICE", 0.20),
        "acceptance": _env_float("RIDE_RANK_WEIGHT_ACCEPTANCE", 0.15),
    }

    # ------------------------------------------------- rider <-> driver chat (rides/chat.py)
    # A room opens when the rider places the order and closes when the ride ends. Messages are
    # pushed live over the user's existing event stream (/events/account) - no polling.
    RIDE_CHAT_MAX_LENGTH = max(1, _env_int("RIDE_CHAT_MAX_LENGTH", 500))
    RIDE_CHAT_HISTORY_LIMIT = max(1, _env_int("RIDE_CHAT_HISTORY_LIMIT", 200))
    RIDE_CHAT_RATE_LIMIT = os.environ.get("RIDE_CHAT_RATE_LIMIT", "20 per minute")  # per logged-in user
    # Dev tools only: the demo driver bots answer chat messages with a canned reply.
    RIDE_CHAT_BOT_REPLIES = _env_bool("RIDE_CHAT_BOT_REPLIES", True)

    # ------------------------------------------------------------- sessions
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = _env_int("SESSION_LIFETIME_SECONDS", 60 * 60 * 12)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    CSRF_ENABLED = True

    # --------------------------------------------------------- MFA settings
    OTP_CODE_LENGTH = 6
    OTP_CODE_TTL_SECONDS = _env_int("OTP_CODE_TTL_SECONDS", 600)
    OTP_MAX_ATTEMPTS = _env_int("OTP_MAX_ATTEMPTS", 5)
    OTP_RESEND_COOLDOWN_SECONDS = _env_int("OTP_RESEND_COOLDOWN_SECONDS", 60)
    OTP_MAX_SENDS_PER_HOUR = _env_int("OTP_MAX_SENDS_PER_HOUR", 6)
    MFA_PENDING_TTL_SECONDS = _env_int("MFA_PENDING_TTL_SECONDS", 300)
    TRUSTED_DEVICE_DAYS = _env_int("TRUSTED_DEVICE_DAYS", 30)
    RECOVERY_CODE_COUNT = 10
    TOTP_VALID_WINDOW = 1  # accept +/- one 30s step for clock drift

    # --------------------------------------------------- passwords & reset
    PASSWORD_MIN_LENGTH = _env_int("PASSWORD_MIN_LENGTH", 10)
    PASSWORD_RESET_TTL_SECONDS = _env_int("PASSWORD_RESET_TTL_SECONDS", 3600)
    PASSWORD_RESET_MAX_PER_HOUR = _env_int("PASSWORD_RESET_MAX_PER_HOUR", 3)

    # ------------------------------------------ brute force: account lockout
    LOGIN_MAX_FAILED_ATTEMPTS = _env_int("LOGIN_MAX_FAILED_ATTEMPTS", 5)
    LOGIN_LOCKOUT_SECONDS = _env_int("LOGIN_LOCKOUT_SECONDS", 900)

    # ------------------------------------- brute force: IP rate limiting
    # memory:// is per-process (fine for one dev server). Use redis://host:6379/0
    # in production so limits are shared by all workers.
    RATELIMIT_ENABLED = _env_bool("RATELIMIT_ENABLED", True)
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_LOGIN = os.environ.get("RATELIMIT_LOGIN", "15 per minute;100 per hour")
    RATELIMIT_2FA = os.environ.get("RATELIMIT_2FA", "20 per minute;100 per hour")
    RATELIMIT_REGISTER = os.environ.get("RATELIMIT_REGISTER", "5 per minute;30 per hour")
    RATELIMIT_RESET = os.environ.get("RATELIMIT_RESET", "5 per minute;20 per hour")
    RATELIMIT_CODE_SEND = os.environ.get("RATELIMIT_CODE_SEND", "5 per minute;30 per hour")

    # ----------------------------------------------- brute force: CAPTCHA
    # none | dummy (offline arithmetic challenge, dev/test) | turnstile | hcaptcha | recaptcha
    CAPTCHA_PROVIDER = os.environ.get("CAPTCHA_PROVIDER", "dummy")
    CAPTCHA_SITE_KEY = os.environ.get("CAPTCHA_SITE_KEY") or DUMMY_CAPTCHA_SITE_KEY
    CAPTCHA_SECRET_KEY = os.environ.get("CAPTCHA_SECRET_KEY") or DUMMY_CAPTCHA_SECRET_KEY
    # Ask for a CAPTCHA once this many failures were seen from the IP or for the account
    # within CAPTCHA_WINDOW_MINUTES. Set to 0 to always require it on auth forms.
    CAPTCHA_AFTER_FAILURES = _env_int("CAPTCHA_AFTER_FAILURES", 3)
    CAPTCHA_WINDOW_MINUTES = _env_int("CAPTCHA_WINDOW_MINUTES", 15)

    # ------------------------------------------------------------ delivery
    EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND", "console")
    SMS_BACKEND = os.environ.get("SMS_BACKEND", "console")
    OUTBOX_PATH = os.environ.get("AUTH_OUTBOX_PATH", "auth_outbox.jsonl")

    MAIL_FROM = os.environ.get("MAIL_FROM", "dummy_no-reply@serviceuber.example")
    SMTP_HOST = os.environ.get("SMTP_HOST", "127.0.0.1")
    SMTP_PORT = _env_int("SMTP_PORT", 2525)
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME") or DUMMY_SMTP_USERNAME
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD") or DUMMY_SMTP_PASSWORD
    SMTP_USE_TLS = _env_bool("SMTP_USE_TLS", False)
    SMTP_USE_AUTH = _env_bool("SMTP_USE_AUTH", False)

    TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID") or DUMMY_TWILIO_ACCOUNT_SID
    TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN") or DUMMY_TWILIO_AUTH_TOKEN
    TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER") or DUMMY_TWILIO_FROM_NUMBER
    TWILIO_API_BASE = os.environ.get("TWILIO_API_BASE", "https://api.twilio.com")

    # --------------------------------------------------- OAuth 2.0 / social login
    # OAUTH_MODE: fake  -> the app hosts a stub identity provider at /dev/oauth/<provider>/...
    #                      (requires ENABLE_DEV_TOOLS); no accounts or internet needed.
    #             real  -> Google / Facebook / Apple endpoints with the credentials below.
    # OAUTH_FAKE_BASE_URL: point the client at scripts/fake_oauth_server.py instead of the
    #                      in-app stub (e.g. http://127.0.0.1:8090) - useful for another machine.
    OAUTH_MODE = os.environ.get("OAUTH_MODE", "fake").lower()
    OAUTH_FAKE_BASE_URL = os.environ.get("OAUTH_FAKE_BASE_URL", "").rstrip("/")
    OAUTH_PROVIDERS = _env_list("OAUTH_PROVIDERS") or ["google", "apple", "facebook"]
    OAUTH_GOOGLE_CLIENT_ID = os.environ.get("OAUTH_GOOGLE_CLIENT_ID") or DUMMY_OAUTH["GOOGLE_CLIENT_ID"]
    OAUTH_GOOGLE_CLIENT_SECRET = os.environ.get("OAUTH_GOOGLE_CLIENT_SECRET") or DUMMY_OAUTH["GOOGLE_CLIENT_SECRET"]
    OAUTH_FACEBOOK_APP_ID = os.environ.get("OAUTH_FACEBOOK_APP_ID") or DUMMY_OAUTH["FACEBOOK_APP_ID"]
    OAUTH_FACEBOOK_APP_SECRET = os.environ.get("OAUTH_FACEBOOK_APP_SECRET") or DUMMY_OAUTH["FACEBOOK_APP_SECRET"]
    OAUTH_APPLE_CLIENT_ID = os.environ.get("OAUTH_APPLE_CLIENT_ID") or DUMMY_OAUTH["APPLE_CLIENT_ID"]  # Services ID
    OAUTH_APPLE_TEAM_ID = os.environ.get("OAUTH_APPLE_TEAM_ID") or DUMMY_OAUTH["APPLE_TEAM_ID"]
    OAUTH_APPLE_KEY_ID = os.environ.get("OAUTH_APPLE_KEY_ID") or DUMMY_OAUTH["APPLE_KEY_ID"]
    # PEM text (\n escaped) or a path to the .p8 file downloaded from Apple
    OAUTH_APPLE_PRIVATE_KEY = os.environ.get("OAUTH_APPLE_PRIVATE_KEY") or DUMMY_OAUTH["APPLE_PRIVATE_KEY"]
    FAKE_OAUTH_SIGNING_KEY = os.environ.get("FAKE_OAUTH_SIGNING_KEY") or DUMMY_FAKE_OAUTH_SIGNING_KEY

    # --------------------------------------------------- background checks
    # Every account must pass a background check before it can use the app (request rides,
    # drive, book or post services, manage payment methods). See background/ and README.
    # BACKGROUND_CHECK_PROVIDER: fake -> offline stub (background/provider.py) with scripted
    #                                    outcomes; real -> not implemented in the demo.
    BACKGROUND_CHECK_REQUIRED = _env_bool("BACKGROUND_CHECK_REQUIRED", True)
    BACKGROUND_CHECK_PROVIDER = os.environ.get("BACKGROUND_CHECK_PROVIDER", "fake").lower()
    BACKGROUND_CHECK_API_KEY = os.environ.get("BACKGROUND_CHECK_API_KEY") or DUMMY_BACKGROUND_CHECK_API_KEY
    BACKGROUND_CHECK_WEBHOOK_SECRET = (os.environ.get("BACKGROUND_CHECK_WEBHOOK_SECRET")
                                       or DUMMY_BACKGROUND_CHECK_WEBHOOK_SECRET)
    # A passed check is valid this long; afterwards the user must be re-checked (0 = forever).
    BACKGROUND_CHECK_VALID_DAYS = _env_int("BACKGROUND_CHECK_VALID_DAYS", 365)
    BACKGROUND_CHECK_MIN_AGE = _env_int("BACKGROUND_CHECK_MIN_AGE", 18)
    # Drivers additionally need a motor-vehicle-record screen and this minimum age.
    BACKGROUND_CHECK_MIN_DRIVER_AGE = _env_int("BACKGROUND_CHECK_MIN_DRIVER_AGE", 21)
    # How many times a user may dispute a rejection (each dispute = a re-check + a manager decision).
    BACKGROUND_CHECK_MAX_DISPUTES = _env_int("BACKGROUND_CHECK_MAX_DISPUTES", 1)

    # -------------------------------------------- admin API (for admin_dashboard/)
    # The admin dashboard is a SEPARATE application (own code, database, deployment). It talks to
    # this app only through /admin-api/v1, authenticated with this bearer token.
    ADMIN_API_ENABLED = _env_bool("ADMIN_API_ENABLED", True)
    ADMIN_API_TOKEN = os.environ.get("ADMIN_API_TOKEN") or DUMMY_ADMIN_API_TOKEN
    # Where the admin dashboard runs (only used for links shown with the dev tools).
    ADMIN_DASHBOARD_URL = os.environ.get("ADMIN_DASHBOARD_URL", "http://127.0.0.1:5001").rstrip("/")

    # ------------------------------------------------------------ dev tools
    ENABLE_DEV_TOOLS = _env_bool("ENABLE_DEV_TOOLS", True)
    SEED_DEMO_DATA = _env_bool("SEED_DEMO_DATA", True)

    PLATFORM = f"{platform.system()} {platform.release()} ({platform.machine()}), Python {sys.version.split()[0]}"

    def require_keys(self) -> None:
        missing = [k for k in ("SECRET_KEY", "MFA_ENCRYPTION_KEY") if not getattr(self, k)]
        if missing:
            raise RuntimeError(f"{', '.join(missing)} must be set in .env. {SETUP_HINT}")


class DevelopmentConfig(BaseConfig):
    DEBUG = _env_bool("DEBUG", True)  # DEBUG=false: dev settings without the debugger (e.g. load tests)

    def __init__(self):
        self.require_keys()


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    ENABLE_DEV_TOOLS = False
    SEED_DEMO_DATA = False

    def __init__(self):
        self.require_keys()
        problems = []
        if is_dummy(self.SECRET_KEY):
            problems.append("SECRET_KEY is a DUMMY placeholder")
        if is_dummy(self.MFA_ENCRYPTION_KEY):
            problems.append("MFA_ENCRYPTION_KEY is a DUMMY placeholder")
        if self.EMAIL_BACKEND in ("console", "memory") or self.SMS_BACKEND in ("console", "memory"):
            problems.append("EMAIL_BACKEND / SMS_BACKEND must be a real backend (smtp / twilio)")
        if self.CAPTCHA_PROVIDER == "dummy":
            problems.append("CAPTCHA_PROVIDER=dummy is trivially solvable by bots; use turnstile/hcaptcha/recaptcha or none")
        if self.CAPTCHA_PROVIDER not in ("none", "dummy") and is_dummy(self.CAPTCHA_SECRET_KEY):
            problems.append("CAPTCHA_SECRET_KEY is a DUMMY placeholder")
        if not self.APP_BASE_URL.startswith("https://"):
            problems.append("APP_BASE_URL must be the public https:// URL (used in password-reset e-mails)")
        if self.PAYMENTS_MODE != "real":
            problems.append("PAYMENTS_MODE must be 'real' (the fake payment gateway is for development only)")
        if is_dummy(self.STRIPE_SECRET_KEY) or is_dummy(self.PAYPAL_CLIENT_SECRET):
            problems.append("STRIPE_SECRET_KEY / PAYPAL_CLIENT_SECRET are DUMMY placeholders")
        if not self.BACKGROUND_CHECK_REQUIRED:
            problems.append("BACKGROUND_CHECK_REQUIRED must stay on: only users who passed a background check may use the app")
        if self.BACKGROUND_CHECK_PROVIDER != "real":
            problems.append("BACKGROUND_CHECK_PROVIDER must be 'real' (the fake background-check provider is for development only)")
        if is_dummy(self.BACKGROUND_CHECK_API_KEY) or is_dummy(self.BACKGROUND_CHECK_WEBHOOK_SECRET):
            problems.append("BACKGROUND_CHECK_API_KEY / BACKGROUND_CHECK_WEBHOOK_SECRET are DUMMY placeholders")
        if self.ADMIN_API_ENABLED and is_dummy(self.ADMIN_API_TOKEN):
            problems.append("ADMIN_API_TOKEN is a DUMMY placeholder (or set ADMIN_API_ENABLED=false)")
        if self.OAUTH_MODE != "real" or self.OAUTH_FAKE_BASE_URL:
            problems.append("OAUTH_MODE must be 'real' (the fake identity provider is for development only)")
        dummy_oauth = [k for k, v in DUMMY_OAUTH.items() if getattr(self, "OAUTH_" + k) == v]
        for p in self.OAUTH_PROVIDERS:
            if any(k.startswith(p.upper()) for k in dummy_oauth):
                problems.append(f"OAuth credentials for '{p}' are DUMMY placeholders (or remove it from OAUTH_PROVIDERS)")
        if problems:
            raise RuntimeError("Refusing to start in production: " + "; ".join(problems))


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    SECRET_KEY = "DUMMY_TEST_SECRET_KEY"
    MFA_ENCRYPTION_KEY = DUMMY_MFA_ENCRYPTION_KEY
    MFA_ENCRYPTION_KEY_PREVIOUS = []
    SQLALCHEMY_DATABASE_URI = "sqlite://"  # in-memory, identical on every OS
    CSRF_ENABLED = False
    SEED_DEMO_DATA = False
    ENABLE_DEV_TOOLS = True
    OTP_RESEND_COOLDOWN_SECONDS = 0
    EMAIL_BACKEND = "memory"
    SMS_BACKEND = "memory"
    RATELIMIT_ENABLED = False  # individual tests switch it on
    CAPTCHA_PROVIDER = "none"  # individual tests switch to "dummy"
    APP_BASE_URL = "http://localhost"
    OAUTH_MODE = "fake"


def get_config(name: str | None = None):
    name = (name or os.environ.get("APP_ENV", "development")).lower()
    return {
        "development": DevelopmentConfig,
        "production": ProductionConfig,
        "testing": TestingConfig,
    }[name]()
