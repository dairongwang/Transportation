"""
Admin dashboard configuration - read from environment variables / admin_dashboard/.env.

The dashboard is a separate application: it has its own secrets, database and deployment,
and reaches the ServiceUber app only through its Admin API (MAIN_APP_API_URL) with a bearer
token (MAIN_APP_API_TOKEN). Every value in .env.example is a DUMMY placeholder; production
refuses them.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")  # this project's own .env, never the main app's

DUMMY_ADMIN_SECRET_KEY = "DUMMY_ADMIN_SECRET_KEY_CHANGE_ME"
DUMMY_MAIN_APP_API_TOKEN = "DUMMY_ADMIN_API_TOKEN"  # must equal ADMIN_API_TOKEN of the main app
# DUMMY demo managers (seeded in development only).
DEMO_USERS = (
    ("dummy_manager", "dummyManagerPass123", "manager", "Dummy Manager"),
    ("dummy_viewer", "dummyViewerPass123", "viewer", "Dummy Viewer"),
)


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def is_dummy(value: str | None) -> bool:
    return not value or "DUMMY" in value.upper()


class Config:
    ENV_NAME = "base"
    SECRET_KEY = os.environ.get("ADMIN_SECRET_KEY") or DUMMY_ADMIN_SECRET_KEY
    SQLALCHEMY_DATABASE_URI = os.environ.get("ADMIN_DATABASE_URL", "sqlite:///uber_admin.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- the ServiceUber Admin API
    MAIN_APP_API_URL = os.environ.get("MAIN_APP_API_URL", "http://127.0.0.1:5000/admin-api/v1").rstrip("/")
    MAIN_APP_API_TOKEN = os.environ.get("MAIN_APP_API_TOKEN") or DUMMY_MAIN_APP_API_TOKEN
    MAIN_APP_API_TIMEOUT = _int("MAIN_APP_API_TIMEOUT", 10)

    # --- sessions: own cookie name (browsers share cookies across ports of the same host)
    SESSION_COOKIE_NAME = "uber_admin_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = _bool("ADMIN_SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = _int("ADMIN_SESSION_LIFETIME_SECONDS", 8 * 3600)
    CSRF_ENABLED = True

    # --- brute force
    LOGIN_MAX_FAILED = _int("ADMIN_LOGIN_MAX_FAILED", 5)
    LOCKOUT_SECONDS = _int("ADMIN_LOCKOUT_SECONDS", 900)
    PASSWORD_MIN_LENGTH = _int("ADMIN_PASSWORD_MIN_LENGTH", 12)

    SEED_DEMO_USERS = _bool("ADMIN_SEED_DEMO_USERS", True)
    # Relay ServiceUber's event stream to the browsers (pages update without a refresh).
    LIVE_UPDATES = _bool("ADMIN_LIVE_UPDATES", True)
    DEBUG = False
    TESTING = False

    def problems(self) -> list[str]:
        return []


class DevelopmentConfig(Config):
    ENV_NAME = "development"
    DEBUG = True


class ProductionConfig(Config):
    ENV_NAME = "production"
    SEED_DEMO_USERS = False
    SESSION_COOKIE_SECURE = True

    def __init__(self):
        problems = []
        if is_dummy(self.SECRET_KEY):
            problems.append("ADMIN_SECRET_KEY is a DUMMY placeholder")
        if is_dummy(self.MAIN_APP_API_TOKEN):
            problems.append("MAIN_APP_API_TOKEN is a DUMMY placeholder")
        if not self.MAIN_APP_API_URL.startswith("https://"):
            problems.append("MAIN_APP_API_URL must use https:// (the bearer token must never travel in clear text)")
        if problems:
            raise RuntimeError("Refusing to start the admin dashboard in production: " + "; ".join(problems))


class TestingConfig(Config):
    ENV_NAME = "testing"
    TESTING = True
    SECRET_KEY = "DUMMY_ADMIN_TEST_SECRET_KEY"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    CSRF_ENABLED = False
    SEED_DEMO_USERS = True
    LIVE_UPDATES = False  # tests start the relay explicitly
    MAIN_APP_API_URL = "http://127.0.0.1:9/admin-api/v1"  # nothing listens there: tests inject a fake client


def get_config(name: str | None = None) -> Config:
    name = (name or os.environ.get("ADMIN_ENV", "development")).lower()
    return {"development": DevelopmentConfig, "production": ProductionConfig, "testing": TestingConfig}[name]()
