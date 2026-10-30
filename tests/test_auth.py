"""End-to-end tests for authentication and two-factor flows."""

import re
import time
from datetime import timedelta

import pytest

from app import create_app
from auth import crypto, mfa, totp
from auth.delivery import get_backend
from auth.mfa import TRUSTED_DEVICE_COOKIE
from clock import utcnow
from extensions import db
from models import AuthEvent, OneTimeCode, RecoveryCode, TrustedDevice, User

PASSWORD = "CorrectHorse-Battery9"
CODE_RE = re.compile(r"\b(\d{6})\b")


@pytest.fixture
def user(app):
    u = User(username="alice", email="alice@example.com", role="both")
    u.set_password(PASSWORD)
    db.session.add(u)
    db.session.commit()
    return u


def login(client, username="alice", password=PASSWORD, **kw):
    return client.post("/login", data={"username": username, "password": password}, **kw)


def last_code(channel, to):
    msg = get_backend(channel).last_for(to)
    assert msg is not None, f"no {channel} sent to {to}"
    return CODE_RE.search(msg.body).group(1)


def current_totp(secret):
    return totp.totp(secret)


def next_totp(secret):
    """Code for the *next* 30s step: the setup step already consumed the current one (replay protection)."""
    return totp.totp(secret, time.time() + 30)


def enable_totp(client, user):
    """Drive the setup UI and return the secret."""
    client.get("/settings/security/totp/setup")
    with client.session_transaction() as sess:
        secret = sess["pending_totp_secret"]
    resp = client.post(
        "/settings/security/totp/setup",
        data={"code": current_totp(secret), "current_password": PASSWORD},
    )
    assert resp.status_code == 200 and b"recovery codes" in resp.data
    codes = re.findall(r"[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", resp.data.decode())
    assert len(codes) == 10
    return secret, codes


def events(user_id=None):
    q = AuthEvent.query
    if user_id:
        q = q.filter_by(user_id=user_id)
    return [e.event for e in q.order_by(AuthEvent.id).all()]


# ================================================================ basics

class TestRegistrationAndLogin:
    def test_register_then_login_without_mfa(self, client):
        r = client.post(
            "/register",
            data={"username": "bob", "email": "bob@example.com", "password": PASSWORD, "role": "buyer"},
            follow_redirects=True,
        )
        assert b"Registration successful" in r.data
        r = login(client, "bob", follow_redirects=True)
        assert b"Welcome back, bob" in r.data
        assert events(User.query.filter_by(username="bob").one().id) == ["register", "login_success"]

    def test_register_rejects_weak_password(self, client):
        r = client.post("/register", data={"username": "bob", "email": "bob@example.com", "password": "short"})
        assert r.status_code == 400 and b"at least 10 characters" in r.data

    def test_login_by_email(self, client, user):
        r = login(client, "alice@example.com", follow_redirects=True)
        assert b"Welcome back, alice" in r.data

    def test_wrong_password_generic_message(self, client, user):
        r = login(client, password="nope")
        assert r.status_code == 401 and b"Invalid username or password" in r.data
        r = login(client, "ghost", password="nope")
        assert r.status_code == 401 and b"Invalid username or password" in r.data

    def test_account_lockout_after_failed_attempts(self, client, user, app):
        for _ in range(app.config["LOGIN_MAX_FAILED_ATTEMPTS"]):
            login(client, password="nope")
        assert db.session.get(User, user.id).is_locked
        r = login(client)  # even the correct password is refused while locked
        assert r.status_code == 423 and b"temporarily locked" in r.data

    def test_logout_requires_post(self, client, user):
        login(client)
        assert client.get("/logout").status_code == 405
        r = client.post("/logout", follow_redirects=True)
        assert b"Logged out" in r.data
        assert client.get("/dashboard").status_code == 302

    def test_open_redirect_blocked(self, client, user):
        r = login(client, query_string={"next": "https://evil.example"})
        assert r.headers["Location"].endswith("/dashboard")
        r = client.post("/logout")
        r = login(client, query_string={"next": "/service/1"})
        assert r.headers["Location"].endswith("/service/1")


# =============================================================== TOTP (app)

class TestTOTP:
    def test_setup_requires_correct_code(self, client, user):
        login(client)
        client.get("/settings/security/totp/setup")
        r = client.post("/settings/security/totp/setup", data={"code": "000000", "current_password": PASSWORD}, follow_redirects=True)
        assert b"Check the time on your device" in r.data
        assert not db.session.get(User, user.id).totp_enabled

    def test_setup_requires_password(self, client, user):
        login(client)
        client.get("/settings/security/totp/setup")
        with client.session_transaction() as sess:
            secret = sess["pending_totp_secret"]
        r = client.post("/settings/security/totp/setup", data={"code": current_totp(secret), "current_password": "wrong"}, follow_redirects=True)
        assert b"Incorrect password" in r.data
        assert not db.session.get(User, user.id).totp_enabled

    def test_full_login_flow(self, client, user):
        login(client)
        secret, _ = enable_totp(client, user)
        u = db.session.get(User, user.id)
        assert u.totp_enabled and u.totp_secret_enc != secret  # encrypted at rest
        assert crypto.decrypt_secret(u.totp_secret_enc) == secret
        client.post("/logout")

        # Password alone is not enough
        r = login(client)
        assert r.headers["Location"].endswith("/2fa/verify")
        assert client.get("/dashboard").status_code == 302  # not logged in yet

        # Wrong code
        r = client.post("/2fa/verify", data={"method": "totp", "code": "123456"}, follow_redirects=True)
        assert b"Incorrect code" in r.data

        # Right code -> logged in
        r = client.post("/2fa/verify", data={"method": "totp", "code": next_totp(secret)}, follow_redirects=True)
        assert b"Welcome back, alice" in r.data
        assert client.get("/dashboard").status_code == 200
        assert "mfa_success" in events(user.id)

    def test_totp_replay_rejected(self, client, user):
        login(client)
        secret, _ = enable_totp(client, user)
        client.post("/logout")
        # The setup confirmation already consumed the current timestep.
        login(client)
        r = client.post("/2fa/verify", data={"method": "totp", "code": current_totp(secret)}, follow_redirects=True)
        assert b"Incorrect code" in r.data

    def test_too_many_wrong_codes_aborts_login(self, client, user):
        login(client)
        enable_totp(client, user)
        client.post("/logout")
        login(client)
        for _ in range(5):
            r = client.post("/2fa/verify", data={"method": "totp", "code": "000000"}, follow_redirects=True)
        assert b"Too many incorrect codes" in r.data
        with client.session_transaction() as sess:
            assert "mfa_pending" not in sess

    def test_pending_session_expires(self, client, user):
        login(client)
        enable_totp(client, user)
        client.post("/logout")
        login(client)
        with client.session_transaction() as sess:
            sess["mfa_pending"] = {**sess["mfa_pending"], "exp": 0}
        r = client.get("/2fa/verify", follow_redirects=True)
        assert b"session expired" in r.data

    def test_disable_requires_password_and_clears_secret(self, client, user):
        login(client)
        enable_totp(client, user)
        r = client.post("/settings/security/disable/totp", data={"current_password": "wrong"}, follow_redirects=True)
        assert b"Incorrect password" in r.data and db.session.get(User, user.id).totp_enabled
        r = client.post("/settings/security/disable/totp", data={"current_password": PASSWORD}, follow_redirects=True)
        u = db.session.get(User, user.id)
        assert not u.totp_enabled and u.totp_secret_enc is None and not u.mfa_enabled
        assert RecoveryCode.query.filter_by(user_id=u.id).count() == 0  # cleaned up with last factor
        client.post("/logout")
        assert login(client).headers["Location"].endswith("/dashboard")


# ============================================================ recovery codes

class TestRecoveryCodes:
    def test_recovery_code_login_single_use(self, client, user):
        login(client)
        _, codes = enable_totp(client, user)
        client.post("/logout")

        login(client)
        r = client.post("/2fa/verify", data={"method": "recovery", "code": codes[0].upper()}, follow_redirects=True)
        assert b"Welcome back" in r.data and b"9 left" in r.data
        client.post("/logout")

        login(client)
        r = client.post("/2fa/verify", data={"method": "recovery", "code": codes[0]}, follow_redirects=True)
        assert b"Incorrect code" in r.data
        r = client.post("/2fa/verify", data={"method": "recovery", "code": codes[1]}, follow_redirects=True)
        assert b"Welcome back" in r.data

    def test_regenerate_invalidates_old(self, client, user):
        login(client)
        _, old = enable_totp(client, user)
        r = client.post("/settings/security/recovery-codes", data={"current_password": PASSWORD})
        new = re.findall(r"[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", r.data.decode())
        assert len(new) == 10 and not set(new) & set(old)
        assert not mfa.verify_recovery_code(db.session.get(User, user.id), old[0])
        assert mfa.verify_recovery_code(db.session.get(User, user.id), new[0])


# ================================================================== e-mail

class TestEmailOTP:
    def enable(self, client, user):
        r = client.post("/settings/security/email/setup", data={"action": "send"}, follow_redirects=True)
        assert b"We sent a code" in r.data
        code = last_code("email", user.email)
        r = client.post("/settings/security/email/setup", data={"action": "verify", "code": code, "current_password": PASSWORD})
        assert b"recovery codes" in r.data
        return code

    def test_setup_and_login(self, client, user):
        login(client)
        self.enable(client, user)
        u = db.session.get(User, user.id)
        assert u.email_2fa_enabled and u.email_verified
        client.post("/logout")

        login(client)
        r = client.post("/2fa/verify", data={"method": "email", "action": "send"}, follow_redirects=True)
        assert b"code has been sent" in r.data
        code = last_code("email", user.email)
        assert OneTimeCode.query.filter_by(purpose="login").first().code_hash != code  # hashed at rest
        r = client.post("/2fa/verify", data={"method": "email", "code": "999999"}, follow_redirects=True)
        assert b"Incorrect code" in r.data
        r = client.post("/2fa/verify", data={"method": "email", "code": code}, follow_redirects=True)
        assert b"Welcome back" in r.data

    def test_code_is_single_use_and_expires(self, client, user, app):
        login(client)
        self.enable(client, user)
        client.post("/logout")
        login(client)
        client.post("/2fa/verify", data={"method": "email", "action": "send"})
        code = last_code("email", user.email)
        rec = OneTimeCode.query.filter_by(purpose="login").order_by(OneTimeCode.id.desc()).first()
        rec.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
        r = client.post("/2fa/verify", data={"method": "email", "code": code}, follow_redirects=True)
        assert b"Incorrect code" in r.data

    def test_code_burns_after_max_attempts(self, client, user, app):
        login(client)
        self.enable(client, user)
        client.post("/logout")
        login(client)
        client.post("/2fa/verify", data={"method": "email", "action": "send"})
        code = last_code("email", user.email)
        u = db.session.get(User, user.id)
        for _ in range(app.config["OTP_MAX_ATTEMPTS"]):
            assert mfa.verify_code(u, "email", "login", "000000") == (False, None)
        assert mfa.verify_code(u, "email", "login", code) == (False, None)  # burnt

    def test_send_rate_limit(self, client, user, app):
        login(client)
        for _ in range(app.config["OTP_MAX_SENDS_PER_HOUR"]):
            client.post("/settings/security/email/setup", data={"action": "send"})
        r = client.post("/settings/security/email/setup", data={"action": "send"}, follow_redirects=True)
        assert b"Too many codes requested" in r.data


# ===================================================================== SMS

class TestSMSOTP:
    def test_setup_and_login(self, client, user):
        login(client)
        r = client.post("/settings/security/sms/setup", data={"action": "send", "phone": "0712 345 678"}, follow_redirects=True)
        assert b"international format" in r.data
        r = client.post("/settings/security/sms/setup", data={"action": "send", "phone": "+1 (555) 010-0001"}, follow_redirects=True)
        assert b"We sent a code to +15550100001" in r.data
        code = last_code("sms", "+15550100001")
        r = client.post("/settings/security/sms/setup", data={"action": "verify", "code": code, "current_password": PASSWORD})
        assert b"recovery codes" in r.data
        u = db.session.get(User, user.id)
        assert u.sms_2fa_enabled and u.phone == "+15550100001" and u.phone_verified
        client.post("/logout")

        login(client)
        client.post("/2fa/verify", data={"method": "sms", "action": "send"})
        r = client.post("/2fa/verify", data={"method": "sms", "code": last_code("sms", "+15550100001")}, follow_redirects=True)
        assert b"Welcome back" in r.data

    def test_phone_cannot_be_reused(self, client, app):
        other = User(username="carol", email="carol@example.com", phone="+15550100001", phone_verified=True, sms_2fa_enabled=True)
        other.set_password(PASSWORD)
        me = User(username="alice", email="alice@example.com")
        me.set_password(PASSWORD)
        db.session.add_all([other, me])
        db.session.commit()
        login(client)
        r = client.post("/settings/security/sms/setup", data={"action": "send", "phone": "+15550100001"}, follow_redirects=True)
        assert b"already in use" in r.data


# ========================================================== multi-method

class TestMultipleMethodsAndDevices:
    def test_preferred_method_and_switching(self, client, user):
        login(client)
        secret, _ = enable_totp(client, user)
        client.post("/settings/security/email/setup", data={"action": "send"})
        client.post("/settings/security/email/setup", data={"action": "verify", "code": last_code("email", user.email), "current_password": PASSWORD})
        assert db.session.get(User, user.id).enabled_mfa_methods == ["totp", "email"]
        client.post("/settings/security/preferred", data={"method": "email"})
        assert db.session.get(User, user.id).default_mfa_method == "email"
        client.post("/logout")

        login(client)
        r = client.get("/2fa/verify")
        assert b"Send code" in r.data  # email is default
        r = client.get("/2fa/verify?method=totp")
        assert b"authenticator app" in r.data
        # Recovery codes only generated once (with the first factor)
        assert RecoveryCode.query.filter_by(user_id=user.id).count() == 10

    def test_trusted_device_skips_2fa(self, client, user):
        login(client)
        secret, _ = enable_totp(client, user)
        client.post("/logout")
        login(client)
        r = client.post("/2fa/verify", data={"method": "totp", "code": next_totp(secret), "remember_device": "on"})
        cookie = client.get_cookie(TRUSTED_DEVICE_COOKIE)
        assert cookie is not None and cookie.http_only
        assert TrustedDevice.query.filter_by(user_id=user.id).count() == 1
        client.post("/logout")

        r = login(client)
        assert r.headers["Location"].endswith("/dashboard")  # no 2FA prompt
        assert "mfa_skipped_trusted_device" in events(user.id)

        # Revoke -> prompted again
        client.post("/settings/security/devices/revoke")
        client.post("/logout")
        assert login(client).headers["Location"].endswith("/2fa/verify")

    def test_tampered_device_cookie_ignored(self, client, user):
        login(client)
        enable_totp(client, user)
        client.post("/logout")
        client.set_cookie(TRUSTED_DEVICE_COOKIE, "forged-token")
        assert login(client).headers["Location"].endswith("/2fa/verify")


# ================================================================ settings

class TestSettingsAccess:
    def test_settings_require_login(self, client):
        for path in ["/settings/security", "/settings/security/totp/setup", "/settings/security/email/setup"]:
            r = client.get(path)
            assert r.status_code == 302 and "/login" in r.headers["Location"]

    def test_security_page_renders(self, client, user):
        login(client)
        r = client.get("/settings/security")
        assert r.status_code == 200 and b"Two-factor authentication is off" in r.data
        assert r.headers["Cache-Control"] == "no-store"
        assert r.headers["X-Frame-Options"] == "DENY"

    def test_change_password(self, client, user):
        login(client)
        r = client.post("/settings/security/password", data={"current_password": PASSWORD, "new_password": "Another-Strong-Pass1", "confirm_password": "Another-Strong-Pass1"}, follow_redirects=True)
        assert b"Password updated" in r.data
        client.post("/logout")
        assert login(client, password=PASSWORD).status_code == 401
        assert login(client, password="Another-Strong-Pass1").status_code == 302


class TestCSRF:
    def test_post_without_token_rejected(self, user):
        app = create_app("testing")
        app.config["CSRF_ENABLED"] = True
        with app.app_context():
            c = app.test_client()
            r = c.post("/login", data={"username": "alice", "password": PASSWORD})
            assert r.status_code == 400
