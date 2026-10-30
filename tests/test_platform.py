"""Cross-platform / environment-stub checks: crypto fallback, QR fallback, fake inbox, health."""

import json
import os

import pytest

from app import create_app
from auth import crypto, mfa
from auth.delivery import OutboundMessage, get_backend
from extensions import db
from models import User


def test_secret_encryption_roundtrip_with_available_backend(app):
    ct = crypto.encrypt_secret("JBSWY3DPEHPK3PXP")
    assert ct != "JBSWY3DPEHPK3PXP"
    assert crypto.decrypt_secret(ct) == "JBSWY3DPEHPK3PXP"
    assert crypto.decrypt_secret("garbage") is None


def test_stdlib_fallback_cipher_roundtrip_and_tamper_detection(app):
    ct = crypto._stdlib_encrypt(b"JBSWY3DPEHPK3PXP")
    assert ct.startswith(crypto.STDLIB_PREFIX)
    assert crypto.decrypt_secret(ct) == "JBSWY3DPEHPK3PXP"  # prefix routing works even when Fernet is present
    tampered = ct[:-6] + ("AAAAAA" if not ct.endswith("AAAAAA") else "BBBBBB")
    assert crypto.decrypt_secret(tampered) is None
    assert crypto._stdlib_encrypt(b"x") != crypto._stdlib_encrypt(b"x")  # fresh nonce each time


def test_app_works_without_cryptography(monkeypatch, app):
    monkeypatch.setattr(crypto, "HAVE_CRYPTOGRAPHY", False)
    ct = crypto.encrypt_secret("SECRET")
    assert ct.startswith(crypto.STDLIB_PREFIX) and crypto.decrypt_secret(ct) == "SECRET"
    assert "stdlib" in crypto.backend_name()


def test_qr_is_svg_and_degrades_without_qrcode(monkeypatch, app):
    if mfa.HAVE_QRCODE:
        data_uri = mfa.totp_qr_data_uri("otpauth://totp/X:a?secret=ABC&issuer=X")
        assert data_uri.startswith("data:image/svg+xml;base64,")
    monkeypatch.setattr(mfa, "HAVE_QRCODE", False)
    assert mfa.totp_qr_data_uri("otpauth://totp/X:a?secret=ABC&issuer=X") is None


def test_totp_setup_page_without_qrcode_still_offers_manual_key(monkeypatch, app):
    monkeypatch.setattr(mfa, "HAVE_QRCODE", False)
    u = User(username="alice", email="alice@example.com")
    u.set_password("CorrectHorse-Battery9")
    db.session.add(u)
    db.session.commit()
    c = app.test_client()
    c.post("/login", data={"username": "alice", "password": "CorrectHorse-Battery9"})
    r = c.get("/settings/security/totp/setup")
    assert r.status_code == 200 and b"manual-key" in r.data and b"otpauth://" in r.data and b"<img" not in r.data


def test_healthz_and_dev_env(app):
    c = app.test_client()
    assert c.get("/healthz").get_json()["status"] == "ok"
    report = c.get("/dev/env.json").get_json()
    assert report["features"]["totp_backend"].startswith("stdlib")
    assert report["storage"]["db_ok"] is True
    assert report["secrets"]["secret_key_is_dummy"] is True
    assert c.get("/dev/env").status_code == 200


def test_dev_outbox_shows_and_clears_messages(app):
    get_backend("sms").send(OutboundMessage("sms", "+15550100234", "sms", "ServiceUber code: 123456", "2025-01-01T00:00:00"))
    c = app.test_client()
    assert c.get("/dev/outbox.json").get_json()[0]["body"].endswith("123456")
    assert b"123456" in c.get("/dev/outbox").data
    c.post("/dev/outbox/clear")
    assert c.get("/dev/outbox.json").get_json() == []


def test_console_backend_writes_outbox_inside_instance_folder(tmp_path):
    app = create_app("testing", overrides={"EMAIL_BACKEND": "console"})
    app.instance_path = str(tmp_path)
    with app.app_context():
        get_backend("email").send(OutboundMessage("email", "a@b.c", "s", "code 654321", "2025-01-01T00:00:00"))
        path = os.path.join(str(tmp_path), "auth_outbox.jsonl")
        assert os.path.exists(path)
        assert json.loads(open(path, encoding="utf-8").read().splitlines()[-1])["body"] == "code 654321"
        db.session.remove()


def test_dev_tools_absent_when_disabled():
    app = create_app("testing", overrides={"ENABLE_DEV_TOOLS": False})
    with app.app_context():
        c = app.test_client()
        assert c.get("/dev/outbox").status_code == 404
        assert c.get("/dev/env").status_code == 404
        assert c.get("/healthz").status_code == 200
        db.session.remove()


def test_production_config_rejects_dummy_secrets(monkeypatch):
    import config as cfg

    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError) as exc:
        cfg.ProductionConfig()
    assert "DUMMY" in str(exc.value)


def _login_user(client, email="alice.dummy@example.com"):
    u = User(username="alice", email=email)
    u.set_password("CorrectHorse-Battery9")
    db.session.add(u)
    db.session.commit()
    client.post("/login", data={"username": "alice", "password": "CorrectHorse-Battery9"})
    return u


def test_stub_backend_tells_user_where_to_find_codes_and_links(app):
    c = app.test_client()
    _login_user(c)
    # setup pages show the notice before sending, and the flash after sending
    assert b"Where is my e-mail?" in c.get("/settings/security/email/setup").data
    r = c.post("/settings/security/email/setup", data={"action": "send"}, follow_redirects=True)
    assert b"TEST MODE: no real e-mail is sent" in r.data and b"/dev/outbox" in r.data
    assert b"Where is my SMS?" in c.get("/settings/security/sms/setup").data
    c.post("/logout")
    # password reset
    assert b"Where is my e-mail?" in c.get("/password/forgot").data
    r = c.post("/password/forgot", data={"email": "alice.dummy@example.com"}, follow_redirects=True)
    assert b"password-reset link" in r.data and b"TEST MODE" in r.data


def test_no_stub_notice_with_real_providers(tmp_path):
    app = create_app("testing", overrides={"EMAIL_BACKEND": "smtp", "SMS_BACKEND": "twilio"})
    app.instance_path = str(tmp_path)
    with app.app_context():
        c = app.test_client()
        _login_user(c)
        assert b"Where is my e-mail?" not in c.get("/settings/security/email/setup").data
        assert b"Where is my SMS?" not in c.get("/settings/security/sms/setup").data
        db.session.remove()


def test_code_input_is_left_aligned():
    import pathlib

    css = pathlib.Path(__file__).resolve().parents[1] / "static" / "app.css"
    rule = [ln for ln in css.read_text().splitlines() if ln.startswith(".code-input")][0]
    assert "text-align: left" in rule
