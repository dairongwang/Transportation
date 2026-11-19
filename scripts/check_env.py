#!/usr/bin/env python3
"""
Environment doctor: verifies this machine can run ServiceUber and prints what it found.

    python scripts/check_env.py            human-readable report, exit 1 on a blocking problem
    python scripts/check_env.py --json     the same data as JSON (what /dev/env.json serves)

Checks: Python version, required packages, .env presence and DUMMY secrets, database
writability, and that the app actually boots (create_app on an in-memory database).
Warnings (dummy secrets, console delivery backends, ...) are fine for development; only
missing dependencies, a non-importable app or a production misconfiguration fail the check.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

MIN_PY = (3, 10)
REQUIRED = {  # import name -> distribution name
    "flask": "Flask",
    "werkzeug": "Werkzeug",
    "flask_sqlalchemy": "Flask-SQLAlchemy",
    "sqlalchemy": "SQLAlchemy",
    "flask_login": "Flask-Login",
    "dotenv": "python-dotenv",
    "flask_limiter": "Flask-Limiter",
    "qrcode": "qrcode",
}
OPTIONAL = {"cryptography": "cryptography", "pytest": "pytest", "redis": "redis", "waitress": "waitress", "gunicorn": "gunicorn"}

OK, WARN, FAIL = "ok", "warn", "fail"


def _missing(mods: dict[str, str]) -> list[str]:
    return [dist for mod, dist in mods.items() if importlib.util.find_spec(mod) is None]


def run_checks() -> dict:
    results: list[dict] = []

    def add(level: str, name: str, detail: str) -> None:
        results.append({"level": level, "check": name, "detail": detail})

    # ---- interpreter
    py = sys.version_info
    add(OK if py >= MIN_PY else FAIL, "python", f"{py.major}.{py.minor}.{py.micro} at {sys.executable}"
        + ("" if py >= MIN_PY else f" (need {MIN_PY[0]}.{MIN_PY[1]}+)"))

    # ---- packages
    missing = _missing(REQUIRED)
    if missing:
        add(FAIL, "dependencies", f"missing: {', '.join(missing)} -> \"{sys.executable}\" -m pip install -r requirements.txt")
        return {"ok": False, "results": results}
    add(OK, "dependencies", "all required packages importable")
    opt_missing = _missing(OPTIONAL)
    add(OK if "cryptography" not in opt_missing else WARN, "optional packages",
        "all present" if not opt_missing else f"not installed: {', '.join(opt_missing)}"
        + (" (authenticator secrets use the stdlib fallback cipher)" if "cryptography" in opt_missing else ""))

    # ---- .env
    env_file = ROOT / ".env"
    if env_file.exists():
        add(OK, ".env", str(env_file))
    elif (ROOT / ".env.example").exists():
        add(WARN, ".env", "not found - copy .env.example to .env (the launchers do this automatically)")
    else:
        add(FAIL, ".env", "neither .env nor .env.example found")

    # ---- configuration + app boot
    try:
        from config import get_config, is_dummy

        cfg = get_config()
    except Exception as exc:  # noqa: BLE001
        add(FAIL, "config", f"{type(exc).__name__}: {exc}")
        return {"ok": False, "results": results}
    env_name = os.environ.get("APP_ENV", "development")
    add(OK, "config", f"APP_ENV={env_name}")
    dummy = [k for k in ("SECRET_KEY", "MFA_ENCRYPTION_KEY") if is_dummy(getattr(cfg, k))]
    add(WARN if dummy else OK, "secrets", f"DUMMY placeholders in use: {', '.join(dummy)} (fine for development)" if dummy else "real values set")
    add(OK if cfg.EMAIL_BACKEND not in ("console", "memory") else WARN, "delivery",
        f"EMAIL_BACKEND={cfg.EMAIL_BACKEND}, SMS_BACKEND={cfg.SMS_BACKEND}"
        + (" - codes appear in the console and at /dev/outbox" if cfg.EMAIL_BACKEND in ("console", "memory") else ""))
    add(OK, "payments", f"PAYMENTS_MODE={cfg.PAYMENTS_MODE}, pre-authorisation x{getattr(cfg, 'RIDE_PREAUTH_FACTOR', 1.5)} of the estimate")
    add(OK, "social login", f"OAUTH_MODE={cfg.OAUTH_MODE}, providers={','.join(cfg.OAUTH_PROVIDERS)}")
    bgc_on = getattr(cfg, "BACKGROUND_CHECK_REQUIRED", True)
    add(OK if bgc_on else WARN, "background checks",
        f"required={'yes' if bgc_on else 'NO - anyone can use the app'}, provider={getattr(cfg, 'BACKGROUND_CHECK_PROVIDER', 'fake')}"
        f", valid {getattr(cfg, 'BACKGROUND_CHECK_VALID_DAYS', 365)} days")
    if getattr(cfg, "ADMIN_API_ENABLED", True):
        add(WARN if is_dummy(getattr(cfg, "ADMIN_API_TOKEN", "")) else OK, "admin API",
            "/admin-api/v1 on for the admin dashboard (admin_dashboard/, " + getattr(cfg, "ADMIN_DASHBOARD_URL", "") + ")"
            + (" - DUMMY token (fine for development)" if is_dummy(getattr(cfg, "ADMIN_API_TOKEN", "")) else ""))
    else:
        add(OK, "admin API", "off (ADMIN_API_ENABLED=false) - the admin dashboard cannot connect")

    try:
        from app import create_app
        from extensions import db

        app = create_app(env_name, {"SQLALCHEMY_DATABASE_URI": "sqlite://", "SEED_DEMO_DATA": False, "RATELIMIT_ENABLED": False})
        with app.app_context():
            db.session.execute(db.text("SELECT 1"))
        add(OK, "app", f"create_app() booted with {len(list(app.url_map.iter_rules()))} routes")
    except Exception as exc:  # noqa: BLE001
        add(FAIL, "app", f"{type(exc).__name__}: {exc}")

    # ---- instance folder (SQLite file + outbox)
    instance = ROOT / "instance"
    try:
        instance.mkdir(exist_ok=True)
        probe = instance / ".write_test"
        probe.write_text("ok")
        probe.unlink()
        add(OK, "instance folder", f"{instance} is writable")
    except OSError as exc:
        add(FAIL, "instance folder", f"{instance}: {exc}")

    return {"ok": not any(r["level"] == FAIL for r in results), "results": results}


def main() -> int:
    report = run_checks()
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1
    icons = {OK: "✓", WARN: "!", FAIL: "✗"}
    width = max(len(r["check"]) for r in report["results"])
    for r in report["results"]:
        print(f" {icons[r['level']]} {r['check']:<{width}}  {r['detail']}")
    print("\nEnvironment OK." if report["ok"] else "\nEnvironment check FAILED - fix the ✗ items above.")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
