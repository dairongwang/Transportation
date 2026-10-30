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
DUMMY_MFA_ENCRYPTION_KEY = "RFVNTVktTUZBLUVOQ1JZUFRJT04tS0VZLTMyQllURVM="  # base64("DUMMY-MFA-ENCRYPTION-KEY-32BYTES")
DUMMY_PAYMENT_GATEWAY_KEY = "DUMMY_PAYMENT_KEY"
DUMMY_MAPS_API_KEY = "DUMMY_MAPS_API_KEY"
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


def _env_list(name: str) -> list[str]:
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


def is_dummy(value: str | None) -> bool:
    return not value or value.upper().startswith("DUMMY") or value == DUMMY_MFA_ENCRYPTION_KEY


class BaseConfig:
    # ---------------------------------------------------------------- core
    SECRET_KEY = os.environ.get("SECRET_KEY")
    MFA_ENCRYPTION_KEY = os.environ.get("MFA_ENCRYPTION_KEY")
    MFA_ENCRYPTION_KEY_PREVIOUS = _env_list("MFA_ENCRYPTION_KEY_PREVIOUS")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///uber_services.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    APP_NAME = os.environ.get("APP_NAME", "ServiceUber")
    # Absolute URL used in e-mails (password-reset links). Falls back to the request host.
    APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip("/")
    # Number of reverse proxies in front of the app (for correct client IPs). 0 = none.
    BEHIND_PROXY = _env_int("BEHIND_PROXY", 0)

    # Unused by the demo, kept as placeholders for future integrations.
    PAYMENT_GATEWAY_KEY = os.environ.get("PAYMENT_GATEWAY_KEY") or DUMMY_PAYMENT_GATEWAY_KEY
    MAPS_API_KEY = os.environ.get("MAPS_API_KEY") or DUMMY_MAPS_API_KEY
    JWT_SECRET = os.environ.get("JWT_SECRET") or DUMMY_JWT_SECRET

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

    MAIL_FROM = os.environ.get("MAIL_FROM", "no-reply@serviceuber.example")
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

    # ------------------------------------------------------------ dev tools
    ENABLE_DEV_TOOLS = _env_bool("ENABLE_DEV_TOOLS", True)
    SEED_DEMO_DATA = _env_bool("SEED_DEMO_DATA", True)

    PLATFORM = f"{platform.system()} {platform.release()} ({platform.machine()}), Python {sys.version.split()[0]}"

    def require_keys(self) -> None:
        missing = [k for k in ("SECRET_KEY", "MFA_ENCRYPTION_KEY") if not getattr(self, k)]
        if missing:
            raise RuntimeError(f"{', '.join(missing)} must be set in .env. {SETUP_HINT}")


class DevelopmentConfig(BaseConfig):
    DEBUG = True

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
