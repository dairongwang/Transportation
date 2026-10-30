#!/usr/bin/env python3
"""
Environment doctor — verifies this machine can run the app. Standard library only for the
checks that matter most, so it works even when `pip install` partly failed.

    python scripts/check_env.py

Exit code 0 = everything needed is present; 1 = something required is missing.
"""

from __future__ import annotations

import base64
import importlib
import importlib.metadata
import importlib.util
import logging
import os
import platform
import socket
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

OK, WARN, FAIL = "[ OK ]", "[WARN]", "[FAIL]"
failures = 0


def report(status: str, text: str) -> None:
    global failures
    if status == FAIL:
        failures += 1
    print(f"{status} {text}")


def check_python() -> None:
    v = sys.version_info
    status = OK if v >= (3, 10) else FAIL
    report(status, f"Python {v.major}.{v.minor}.{v.micro} on {platform.system()} {platform.release()} ({platform.machine()})"
           + ("" if v >= (3, 10) else " - Python 3.10+ required"))
    if sys.prefix == sys.base_prefix:
        report(WARN, "Not running inside a virtual environment (recommended: python -m venv .venv)")
    else:
        report(OK, f"Virtual environment: {sys.prefix}")


REQUIRED = {
    "flask": "Flask",
    "flask_sqlalchemy": "Flask-SQLAlchemy",
    "flask_login": "Flask-Login",
    "dotenv": "python-dotenv",
    "flask_limiter": "Flask-Limiter",
}
OPTIONAL = {
    "qrcode": "qrcode (QR code on the authenticator setup page; manual key works without it)",
    "cryptography": "cryptography (Fernet encryption of TOTP secrets; stdlib fallback is used without it)",
    "redis": "redis (shared rate-limit storage for multi-worker production)",
    "pytest": "pytest (test suite)",
}


def _version(dist: str) -> str:
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return ""


def check_dependencies() -> None:
    for mod, name in REQUIRED.items():
        try:
            importlib.import_module(mod)
            report(OK, f"{name} {_version(name)}".strip())
        except ImportError:
            report(FAIL, f"{name} missing  ->  pip install -r requirements.txt")
    for mod, name in OPTIONAL.items():
        dist = name.split(" (")[0]
        try:
            importlib.import_module(mod)
            report(OK, f"{dist} {_version(dist)}".strip())
        except ImportError:
            report(WARN, f"{name} not installed")
    for mod, note in (("PIL", "Pillow"), ("flask_wtf", "Flask-WTF"), ("pyotp", "pyotp")):
        if importlib.util.find_spec(mod) is not None:
            report(OK, f"{note} is installed but not required by this app")


def check_totp() -> None:
    from _totp_loader import load_totp

    totp = load_totp()
    secret = base64.b32encode(b"12345678901234567890").decode()
    ok = totp.totp(secret, 59, digits=8) == "94287082" and totp.hotp(secret, 0) == "755224"
    report(OK if ok else FAIL, "TOTP implementation matches RFC 6238 / RFC 4226 test vectors")


def check_sqlite() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "probe.db")
        con = sqlite3.connect(path)
        con.execute("create table t (x integer)")
        con.execute("insert into t values (1)")
        con.commit()
        con.close()
    report(OK, f"SQLite {sqlite3.sqlite_version} can create and write database files")
    inst = ROOT / "instance"
    try:
        inst.mkdir(exist_ok=True)
        probe = inst / ".write_probe"
        probe.write_text("ok")
        probe.unlink()
        report(OK, f"Instance folder writable: {inst}")
    except OSError as exc:
        report(FAIL, f"Instance folder not writable ({exc})")


def check_app() -> None:
    try:
        from app import create_app
    except Exception as exc:  # noqa: BLE001
        report(FAIL, f"App cannot be imported: {exc}")
        return
    try:
        app = create_app("testing")
        with app.app_context():
            from auth import crypto, mfa

            ct = crypto.encrypt_secret("PROBE")
            assert crypto.decrypt_secret(ct) == "PROBE"
            report(OK, f"Secret encryption works ({crypto.backend_name()})")
            qr = mfa.totp_qr_data_uri("otpauth://totp/x?secret=ABC")
            report(OK if qr else WARN, "QR rendering: " + ("SVG" if qr else "unavailable, manual key only"))
            c = app.test_client()
            assert c.get("/healthz").status_code == 200
            assert c.get("/login").status_code == 200
            report(OK, "App boots in testing mode, /healthz and /login respond")
    except Exception as exc:  # noqa: BLE001
        report(FAIL, f"App self-test failed: {exc}")


def check_env_file() -> None:
    env = ROOT / ".env"
    if env.exists():
        report(OK, ".env present")
        if "DUMMY" in env.read_text(encoding="utf-8", errors="ignore"):
            report(WARN, ".env still contains DUMMY placeholders (fine for dev/test, never for production)")
    else:
        report(WARN, ".env not found")
    try:
        from dotenv import load_dotenv

        load_dotenv(env)
    except ImportError:
        pass
    for key in ("SECRET_KEY", "MFA_ENCRYPTION_KEY"):
        if os.environ.get(key):
            report(OK, f"{key} is set" + (" (DUMMY)" if os.environ[key].upper().startswith("DUMMY") or os.environ[key].startswith("RFVNTVkt") else ""))
        else:
            report(FAIL, f"{key} is not set - `python app.py` will refuse to start. Copy .env.example to .env")


def lan_ips() -> list[str]:
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(i for i in ips if not i.startswith("127."))


def main() -> int:
    logging.disable(logging.WARNING)  # keep the report readable
    print(f"ServiceUber environment check - {ROOT}")
    print(f"Interpreter: {sys.executable}\n")
    check_python()
    check_dependencies()
    check_totp()
    check_sqlite()
    check_env_file()
    check_app()
    ips = lan_ips()
    if ips:
        print("\nFor phone/tablet testing start with HOST=0.0.0.0 and open: " + ", ".join(f"http://{ip}:5000" for ip in ips))
    print("\nRESULT:", "READY" if failures == 0 else f"{failures} problem(s) found")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
