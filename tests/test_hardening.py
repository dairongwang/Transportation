"""Rate limiting, CAPTCHA, password reset (+ second factor), session invalidation, key rotation."""

import re
import time

import pytest

from app import create_app
from auth import crypto, totp
from auth.delivery import get_backend
from auth.mfa import TRUSTED_DEVICE_COOKIE
from extensions import db
from models import AuthEvent, PasswordResetToken, TrustedDevice, User

PASSWORD = "CorrectHorse-Battery9"
NEW_PASSWORD = "Another-Strong-Pass1"
# DUMMY identities: example.com is reserved for documentation, 555-01xx numbers are fictional.
EMAIL = "alice.dummy@example.com"


def make_user(username="alice", email=EMAIL, **kw):
    u = User(username=username, email=email, **kw)
    u.set_password(PASSWORD)
    db.session.add(u)
    db.session.commit()
    return u


def login(client, username="alice", password=PASSWORD, **extra):
    return client.post("/login", data={"username": username, "password": password, **extra})


def reset_link_from_mail(to):
    msg = get_backend("email").last_for(to)
    assert msg is not None, "no reset e-mail"
    return re.search(r"https?://[^\s]+/password/reset/([A-Za-z0-9_\-]+)", msg.body).group(1)


def allow_totp_reuse(user_id):
    """Tests run inside one 30s step; clear the replay marker so the next code is accepted."""
    db.session.get(User, user_id).totp_last_counter = None
    db.session.commit()


def enable_totp(client):
    client.get("/settings/security/totp/setup")
    with client.session_transaction() as sess:
        secret = sess["pending_totp_secret"]
    r = client.post("/settings/security/totp/setup", data={"code": totp.totp(secret), "current_password": PASSWORD})
    assert b"recovery codes" in r.data
    return secret


# ============================================================= CSRF (built-in)

class TestBuiltinCSRF:
    @pytest.fixture
    def capp(self, tmp_path):
        app = create_app("testing", overrides={"CSRF_ENABLED": True})
        app.instance_path = str(tmp_path)
        with app.app_context():
            make_user()
            yield app
            db.session.remove()
            db.drop_all()

    def test_missing_or_wrong_token_rejected(self, capp):
        c = capp.test_client()
        assert c.post("/login", data={"username": "alice", "password": PASSWORD}).status_code == 400
        c.get("/login")
        assert c.post("/login", data={"username": "alice", "password": PASSWORD, "csrf_token": "nope"}).status_code == 400

    def test_valid_token_in_form_or_header_accepted(self, capp):
        c = capp.test_client()
        page = c.get("/login").data.decode()
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        r = c.post("/login", data={"username": "alice", "password": PASSWORD, "csrf_token": token})
        assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
        # the session (and with it the token) is rotated at login
        token = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/dashboard").data.decode()).group(1)
        r = c.post("/logout", headers={"X-CSRF-Token": token})
        assert r.status_code == 302

    def test_get_requests_unaffected(self, capp):
        assert capp.test_client().get("/").status_code == 200

    def test_exempt_view_skips_check(self, capp):
        assert capp.test_client().post("/dev/outbox/clear").status_code == 302  # dev-only inbox, @csrf.exempt


# ============================================================= rate limiting

class TestRateLimiting:
    def test_login_is_throttled_per_ip(self, tmp_path):
        pytest.importorskip("flask_limiter")
        from throttle import limiter

        app = create_app("testing", overrides={"RATELIMIT_ENABLED": True, "RATELIMIT_LOGIN": "3 per minute"})
        app.instance_path = str(tmp_path)
        limiter.reset()
        with app.app_context():
            make_user()
            c = app.test_client()
            codes = [login(c, password="wrong").status_code for _ in range(4)]
            assert codes == [401, 401, 401, 429]
            assert login(c).status_code == 429  # even the right password is throttled now
            r = c.get("/login")  # GET is not limited
            assert r.status_code == 200
            db.session.remove()
            db.drop_all()
        limiter.reset()

    def test_limiter_status_reported(self, client):
        report = client.get("/dev/env.json").get_json()
        assert report["features"]["rate_limiting"].startswith(("disabled", "enabled", "unavailable"))


# ==================================================================== CAPTCHA

class TestCaptcha:
    @pytest.fixture
    def capp(self, tmp_path):
        app = create_app("testing", overrides={"CAPTCHA_PROVIDER": "dummy", "CAPTCHA_AFTER_FAILURES": 2})
        app.instance_path = str(tmp_path)
        with app.app_context():
            make_user()
            yield app
            db.session.remove()
            db.drop_all()

    def answer(self, client):
        with client.session_transaction() as sess:
            return sess["_dummy_captcha"]

    def test_captcha_appears_after_failures_and_blocks_without_answer(self, capp):
        c = capp.test_client()
        assert b"captcha_answer" not in c.get("/login").data
        login(c, password="wrong")
        assert b"captcha_answer" not in c.get("/login").data
        login(c, password="wrong")
        assert b"captcha_answer" in c.get("/login").data  # threshold reached
        # Correct password but no CAPTCHA -> refused, and counted as another failure
        r = login(c)
        assert r.status_code == 400 and b"complete the CAPTCHA" in r.data
        assert AuthEvent.query.filter_by(event="captcha_failed").count() == 1
        assert c.get("/dashboard").status_code == 302

    def test_wrong_then_right_answer(self, capp):
        c = capp.test_client()
        login(c, password="wrong")
        login(c, password="wrong")
        c.get("/login")
        r = login(c, captcha_answer="999")
        assert r.status_code == 400
        c.get("/login")
        r = login(c, captcha_answer=self.answer(c))
        assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")

    def test_captcha_on_forgot_password_and_register(self, capp):
        c = capp.test_client()
        login(c, password="wrong")
        login(c, password="wrong")
        assert b"captcha_answer" in c.get("/password/forgot").data
        assert c.post("/password/forgot", data={"email": EMAIL}).status_code == 400
        assert b"captcha_answer" in c.get("/register").data

    def test_always_required_when_threshold_zero(self, tmp_path):
        app = create_app("testing", overrides={"CAPTCHA_PROVIDER": "dummy", "CAPTCHA_AFTER_FAILURES": 0})
        app.instance_path = str(tmp_path)
        with app.app_context():
            c = app.test_client()
            assert b"captcha_answer" in c.get("/login").data
            db.session.remove()


# ============================================================ password reset

class TestPasswordReset:
    def test_forgot_is_generic_and_sends_mail_only_for_known_users(self, client, app):
        make_user()
        r = client.post("/password/forgot", data={"email": "nobody.dummy@example.com"}, follow_redirects=True)
        assert b"If an account with that e-mail exists" in r.data
        assert get_backend("email").last_for("nobody.dummy@example.com") is None
        r = client.post("/password/forgot", data={"email": EMAIL}, follow_redirects=True)
        assert b"If an account with that e-mail exists" in r.data
        assert reset_link_from_mail(EMAIL)
        assert PasswordResetToken.query.count() == 1
        assert PasswordResetToken.query.first().token_hash != reset_link_from_mail(EMAIL)  # hashed at rest

    def test_reset_without_2fa_changes_password_and_kills_sessions(self, client, app):
        user = make_user()
        other = app.test_client()  # a second, already logged-in browser
        assert login(other).status_code == 302 and other.get("/dashboard").status_code == 200

        client.post("/password/forgot", data={"email": EMAIL})
        token = reset_link_from_mail(EMAIL)
        r = client.get(f"/password/reset/{token}")
        assert r.headers["Location"].endswith("/password/reset/new")
        r = client.post("/password/reset/new", data={"new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD}, follow_redirects=True)
        assert b"Your password has been reset" in r.data

        assert login(client, password=PASSWORD).status_code == 401
        assert login(client, password=NEW_PASSWORD).status_code == 302
        assert other.get("/dashboard").status_code == 302  # old session invalidated
        assert get_backend("email").last_for(EMAIL).subject.endswith("password was changed")
        assert "password_reset_completed" in [e.event for e in AuthEvent.query.filter_by(user_id=user.id)]

    def test_token_single_use_expired_and_tampered(self, client, app):
        make_user()
        client.post("/password/forgot", data={"email": EMAIL})
        token = reset_link_from_mail(EMAIL)
        assert client.get("/password/reset/" + token[:-2] + "zz").headers["Location"].endswith("/password/forgot")
        client.get(f"/password/reset/{token}")
        client.post("/password/reset/new", data={"new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
        r = client.get(f"/password/reset/{token}", follow_redirects=True)
        assert b"invalid or has expired" in r.data
        # expired
        client.post("/password/forgot", data={"email": EMAIL})
        token = reset_link_from_mail(EMAIL)
        rec = PasswordResetToken.query.filter_by(used_at=None).one()
        from datetime import timedelta

        from clock import utcnow

        rec.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
        assert b"invalid or has expired" in client.get(f"/password/reset/{token}", follow_redirects=True).data

    def test_per_user_request_cap(self, client, app):
        make_user()
        for _ in range(app.config["PASSWORD_RESET_MAX_PER_HOUR"] + 2):
            client.post("/password/forgot", data={"email": EMAIL})
        assert PasswordResetToken.query.count() == app.config["PASSWORD_RESET_MAX_PER_HOUR"]
        assert AuthEvent.query.filter_by(event="password_reset_throttled").count() == 2

    def test_reset_requires_second_factor_when_enabled(self, client, app):
        user = make_user()
        login(client)
        secret = enable_totp(client)
        # also a trusted device, to prove it gets revoked
        client.post("/logout")
        login(client)
        client.post("/2fa/verify", data={"method": "totp", "code": totp.totp(secret, time.time() + 30), "remember_device": "on"})
        assert TrustedDevice.query.count() == 1
        client.post("/logout")

        client.post("/password/forgot", data={"email": EMAIL})
        token = reset_link_from_mail(EMAIL)
        r = client.get(f"/password/reset/{token}")
        assert r.headers["Location"].endswith("/password/reset/verify")
        # Can't skip to the password form
        assert client.get("/password/reset/new").headers["Location"].endswith("/password/reset/verify")
        r = client.get("/password/reset/verify")
        assert b"Resetting the password" in r.data and b"remember_device" not in r.data
        r = client.post("/password/reset/verify", data={"method": "totp", "code": "000000"}, follow_redirects=True)
        assert b"Incorrect code" in r.data
        allow_totp_reuse(user.id)
        r = client.post("/password/reset/verify", data={"method": "totp", "code": totp.totp(secret)})
        assert r.headers["Location"].endswith("/password/reset/new")
        r = client.post("/password/reset/new", data={"new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD}, follow_redirects=True)
        assert b"has been reset" in r.data
        assert TrustedDevice.query.count() == 0  # revoked
        assert client.get_cookie(TRUSTED_DEVICE_COOKIE) is None
        assert db.session.get(User, user.id).check_password(NEW_PASSWORD)

    def test_email_factor_not_offered_for_reset_when_another_exists(self, client, app):
        make_user()
        login(client)
        enable_totp(client)
        client.post("/settings/security/email/setup", data={"action": "send"})
        code = re.search(r"\b(\d{6})\b", get_backend("email").last_for(EMAIL).body).group(1)
        client.post("/settings/security/email/setup", data={"action": "verify", "code": code, "current_password": PASSWORD})
        client.post("/logout")
        client.post("/password/forgot", data={"email": EMAIL})
        client.get("/password/reset/" + reset_link_from_mail(EMAIL))
        page = client.get("/password/reset/verify").data
        assert b"Authenticator app" in page and b"E-mail codes" not in page
        # and a request for an e-mail code is refused
        assert client.post("/password/reset/verify", data={"method": "email", "action": "send"}).status_code in (302, 400)
        assert not any(m.body.startswith("Your ServiceUber code to sign in") for m in get_backend("email").messages)

    def test_email_factor_allowed_when_it_is_the_only_one(self, client, app):
        make_user()
        login(client)
        client.post("/settings/security/email/setup", data={"action": "send"})
        code = re.search(r"\b(\d{6})\b", get_backend("email").last_for(EMAIL).body).group(1)
        client.post("/settings/security/email/setup", data={"action": "verify", "code": code, "current_password": PASSWORD})
        client.post("/logout")
        client.post("/password/forgot", data={"email": EMAIL})
        client.get("/password/reset/" + reset_link_from_mail(EMAIL))
        assert b"E-mail codes" in client.get("/password/reset/verify").data

    def test_too_many_wrong_codes_aborts_reset(self, client, app):
        make_user()
        login(client)
        enable_totp(client)
        client.post("/logout")
        client.post("/password/forgot", data={"email": EMAIL})
        client.get("/password/reset/" + reset_link_from_mail(EMAIL))
        for _ in range(5):
            r = client.post("/password/reset/verify", data={"method": "totp", "code": "000000"}, follow_redirects=True)
        assert b"Too many incorrect codes" in r.data
        assert client.get("/password/reset/new").headers["Location"].endswith("/password/forgot")


# ============================================== session invalidation on change

class TestSessionInvalidation:
    def test_change_password_signs_out_other_sessions_but_not_own(self, app):
        make_user()
        a, b = app.test_client(), app.test_client()
        login(a)
        login(b)
        a.post("/settings/security/password", data={"current_password": PASSWORD, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
        assert a.get("/dashboard").status_code == 200
        assert b.get("/dashboard").status_code == 302
        assert get_backend("email").last_for(EMAIL).subject.endswith("password was changed")


# ================================================================ key rotation

class TestKeyRotation:
    OLD = "RFVNTVktTUZBLUVOQ1JZUFRJT04tS0VZLTMyQllURVM="  # dummy key A
    NEW = "TkVXLURVTU1ZLU1GQS1LRVktRk9SLVJPVEFUSU9OLVQ="  # dummy key B (base64 of 32 bytes)

    def test_hashes_do_not_depend_on_secret_key(self, app):
        h1 = crypto.keyed_hash("x")
        app.config["SECRET_KEY"] = "DUMMY_ROTATED_SECRET_KEY"
        assert crypto.keyed_hash("x") == h1

    def test_previous_key_still_verifies_and_decrypts(self, app):
        app.config["MFA_ENCRYPTION_KEY"] = self.OLD
        ct = crypto.encrypt_secret("JBSWY3DPEHPK3PXP")
        h = crypto.keyed_hash("rc:1:abcd-efgh-ijkl")
        # rotate
        app.config["MFA_ENCRYPTION_KEY"] = self.NEW
        app.config["MFA_ENCRYPTION_KEY_PREVIOUS"] = [self.OLD]
        assert crypto.decrypt_secret(ct) == "JBSWY3DPEHPK3PXP"
        assert crypto.needs_reencryption(ct) is True
        assert crypto.keyed_hash_matches("rc:1:abcd-efgh-ijkl", h) is True
        assert crypto.keyed_hash("rc:1:abcd-efgh-ijkl") != h  # new values use the new key
        # without the previous key nothing old works
        app.config["MFA_ENCRYPTION_KEY_PREVIOUS"] = []
        assert crypto.decrypt_secret(ct) is None
        assert crypto.keyed_hash_matches("rc:1:abcd-efgh-ijkl", h) is False

    def test_full_user_flow_survives_rotation_and_rotate_script(self, client, app):
        user = make_user()
        login(client)
        secret = enable_totp(client)
        client.post("/logout")
        login(client)
        client.post("/2fa/verify", data={"method": "totp", "code": totp.totp(secret, time.time() + 30), "remember_device": "on"})
        client.post("/logout")

        app.config["MFA_ENCRYPTION_KEY"] = self.NEW
        app.config["MFA_ENCRYPTION_KEY_PREVIOUS"] = [self.OLD]

        # trusted device (keyed hash under the old key) still recognised and re-keyed on use
        r = login(client)
        assert r.headers["Location"].endswith("/dashboard")
        assert TrustedDevice.query.first().token_hash == crypto.keyed_hash_candidates(f"td:{client.get_cookie(TRUSTED_DEVICE_COOKIE).value}")[0]
        client.post("/logout")

        # re-encrypt TOTP secrets with the script's function
        from scripts.rotate_keys import rotate

        stats = rotate(app)
        assert stats["reencrypted"] == 1
        u = db.session.get(User, user.id)
        assert not crypto.needs_reencryption(u.totp_secret_enc)
        assert crypto.decrypt_secret(u.totp_secret_enc) == secret

        # previous key can now be dropped for TOTP; login with authenticator still works
        app.config["MFA_ENCRYPTION_KEY_PREVIOUS"] = []
        TrustedDevice.query.delete()
        db.session.commit()
        allow_totp_reuse(user.id)
        login(client)
        r = client.post("/2fa/verify", data={"method": "totp", "code": totp.totp(secret)})
        assert r.headers["Location"].endswith("/dashboard")
