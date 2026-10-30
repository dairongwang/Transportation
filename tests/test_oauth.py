"""
Social login (OAuth 2.0): the real client code in auth/oauth.py driven end-to-end through
the FAKE identity provider in auth/fake_oauth.py, for Google, Apple and Facebook.
"""

import html
import re
import time
import urllib.parse

import pytest

from app import create_app
from auth import jwt_min, oauth, totp
from auth.fake_oauth import _CODES, _TOKENS
from extensions import db
from models import AuthEvent, OAuthAccount, User

PASSWORD = "CorrectHorse-Battery9"
LOCAL_EMAIL = "alice.dummy@example.com"
PROVIDERS = ("google", "apple", "facebook")


@pytest.fixture(autouse=True)
def _clean_fake_provider():
    _CODES.clear()
    _TOKENS.clear()


def make_local_user(email=LOCAL_EMAIL, username="alice"):
    u = User(username=username, email=email)
    u.set_password(PASSWORD)
    db.session.add(u)
    db.session.commit()
    return u


def social_login(client, provider, email="tester.dummy@example.com", name="Test Dummy", verified=True,
                 decision="allow", link=False, first_time=True, tamper=None):
    """Drive the browser side of the flow. Returns the final response (callback result)."""
    start = client.get(f"/oauth/{provider}/start" + ("?link=1" if link else ""))
    assert start.status_code == 302, start.data
    auth_url = start.headers["Location"]
    assert f"/dev/oauth/{provider}/authorize?" in auth_url
    params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(auth_url).query))
    consent = client.get(auth_url)  # provider's consent page
    assert consent.status_code == 200 and b"FAKE" in consent.data and b"invalid" not in consent.data
    form = {**params, "email": email, "name": name, "decision": decision}
    if verified:
        form["email_verified"] = "on"
    if first_time:
        form["first_time"] = "on"
    r = client.post(auth_url.split("?")[0], data=form)
    if provider == "apple" and decision == "allow":
        # form_post: the page contains a form that POSTs code/state/user to our callback
        assert r.status_code == 200 and b'id="autosubmit"' in r.data
        page = r.data.decode()
        fields = dict(re.findall(r'name="(code|state)" value="([^"]+)"', page))
        user_field = re.search(r"name=\"user\" value='([^']+)'", page)
        if user_field:
            fields["user"] = html.unescape(user_field.group(1))
        if tamper:
            fields.update(tamper)
        r = client.post("/oauth/apple/callback", data=fields)
        assert r.status_code == 303
        return client.get(r.headers["Location"])
    assert r.status_code == 302
    callback = r.headers["Location"]
    if tamper:
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(callback).query))
        q.update(tamper)
        callback = f"/oauth/{provider}/callback?" + urllib.parse.urlencode(q)
    return client.get(callback)


def flashes(client, path="/login"):
    html = client.get(path).data.decode()
    return [re.sub(r"\s+", " ", a).strip() for a in re.findall(r'role="alert">\s*(.*?)\s*<button', html, re.S)]


# ============================================================ happy paths

@pytest.mark.parametrize("provider", PROVIDERS)
def test_new_user_is_created_and_logged_in(client, provider):
    r = social_login(client, provider, email=f"new.dummy@{provider}.example", name="Newbie Dummy")
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200
    user = User.query.filter_by(email=f"new.dummy@{provider}.example").one()
    assert user.username.startswith("new.dummy") and user.display_name == "Newbie Dummy"
    assert user.email_verified is True and user.password_is_usable is False
    acct = OAuthAccount.query.filter_by(user_id=user.id).one()
    assert acct.provider == provider and acct.provider_user_id.startswith(provider[:2] + "_")
    events = [e.event for e in AuthEvent.query.filter_by(user_id=user.id)]
    assert "oauth_signup" in events and "oauth_login" in events and "login_success" in events


@pytest.mark.parametrize("provider", PROVIDERS)
def test_returning_user_logs_in_without_creating_duplicates(client, provider):
    social_login(client, provider, email="again.dummy@example.com")
    client.post("/logout")
    r = social_login(client, provider, email="again.dummy@example.com", first_time=False)
    assert r.headers["Location"].endswith("/dashboard")
    assert User.query.count() == 1 and OAuthAccount.query.count() == 1


def test_social_account_cannot_use_password_login_until_reset(client):
    social_login(client, "google", email="nopass.dummy@example.com")
    client.post("/logout")
    r = client.post("/login", data={"username": "nopass.dummy", "password": "anything-at-all"})
    assert r.status_code == 401 and b"social login and has no password" in r.data


def test_2fa_still_required_after_social_login(client):
    social_login(client, "google", email="mfa.dummy@example.com")
    # social accounts have no password and enabling 2FA needs one: simulate the reset flow
    user = User.query.filter_by(email="mfa.dummy@example.com").one()
    user.set_password(PASSWORD)  # bumps the password stamp -> current session ends (by design)
    db.session.commit()
    assert client.get("/dashboard").status_code == 302
    social_login(client, "google", email="mfa.dummy@example.com", first_time=False)
    client.get("/settings/security/totp/setup")
    with client.session_transaction() as sess:
        secret = sess["pending_totp_secret"]
    client.post("/settings/security/totp/setup", data={"code": totp.totp(secret), "current_password": PASSWORD})
    assert db.session.get(User, user.id).totp_enabled
    client.post("/logout")

    r = social_login(client, "google", email="mfa.dummy@example.com", first_time=False)
    assert r.headers["Location"].endswith("/2fa/verify")  # not logged in yet
    assert client.get("/dashboard").status_code == 302
    r = client.post("/2fa/verify", data={"method": "totp", "code": totp.totp(secret, time.time() + 30)})
    assert r.headers["Location"].endswith("/dashboard")


# ============================================================= linking

def test_existing_email_is_not_auto_linked_but_linked_after_password_login(client):
    make_local_user()
    r = social_login(client, "facebook", email=LOCAL_EMAIL)
    assert r.headers["Location"].endswith("/login")
    assert client.get("/dashboard").status_code == 302  # NOT logged in
    assert OAuthAccount.query.count() == 0
    assert any("already exists" in f for f in flashes(client))
    r = client.post("/login", data={"username": "alice", "password": PASSWORD}, follow_redirects=True)
    assert b"Facebook account linked" in r.data
    assert OAuthAccount.query.filter_by(provider="facebook").one().user.email == LOCAL_EMAIL
    # and from now on the social button logs straight in
    client.post("/logout")
    r = social_login(client, "facebook", email=LOCAL_EMAIL)
    assert r.headers["Location"].endswith("/dashboard")


def test_pending_link_survives_2fa_and_ignores_email_mismatch(client):
    user = make_local_user()
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    client.get("/settings/security/totp/setup")
    with client.session_transaction() as sess:
        secret = sess["pending_totp_secret"]
    client.post("/settings/security/totp/setup", data={"code": totp.totp(secret), "current_password": PASSWORD})
    client.post("/logout")
    social_login(client, "google", email=LOCAL_EMAIL)  # -> pending link
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    r = client.post("/2fa/verify", data={"method": "totp", "code": totp.totp(secret, time.time() + 30)}, follow_redirects=True)
    assert b"Google account linked" in r.data
    assert OAuthAccount.query.filter_by(user_id=user.id, provider="google").count() == 1


def test_link_and_unlink_from_security_page(client):
    make_local_user()
    client.post("/login", data={"username": "alice", "password": PASSWORD})
    page = client.get("/settings/security").data
    assert b"No social accounts linked" in page and b"Link Google" in page
    r = social_login(client, "google", email="whatever.dummy@example.com", link=True)
    assert r.headers["Location"].endswith("/settings/security")
    page = client.get("/settings/security").data
    assert b"Google</strong>" in page and b"linked" in page and b"Link Google" not in page
    # unlink needs the password
    r = client.post("/settings/security/oauth/google/unlink", data={"current_password": "wrong"}, follow_redirects=True)
    assert b"Incorrect password" in r.data and OAuthAccount.query.count() == 1
    r = client.post("/settings/security/oauth/google/unlink", data={"current_password": PASSWORD}, follow_redirects=True)
    assert b"Google account unlinked" in r.data and OAuthAccount.query.count() == 0


def test_identity_linked_elsewhere_cannot_be_linked_again(client):
    social_login(client, "apple", email="shared.dummy@example.com")
    client.post("/logout")
    make_local_user(email="other.dummy@example.com", username="bob")
    client.post("/login", data={"username": "bob", "password": PASSWORD})
    r = social_login(client, "apple", email="shared.dummy@example.com", link=True, first_time=False)
    assert r.headers["Location"].endswith("/settings/security")
    assert any("already linked to a different account" in f for f in flashes(client, "/settings/security"))


def test_last_social_identity_cannot_be_unlinked_without_password(client):
    social_login(client, "google", email="only.dummy@example.com")
    r = client.post("/settings/security/oauth/google/unlink", data={}, follow_redirects=True)
    assert b"Set a password first" in r.data and OAuthAccount.query.count() == 1


# ============================================================ failure paths

def test_denied_consent(client):
    r = social_login(client, "google", decision="deny")
    assert r.headers["Location"].endswith("/login")
    assert any("cancelled" in f for f in flashes(client))
    assert User.query.count() == 0


def test_state_mismatch_rejected(client):
    social_login(client, "google", tamper={"state": "forged-state"})
    assert any("Invalid sign-in state" in f for f in flashes(client))
    assert User.query.count() == 0


def test_apple_state_mismatch_rejected_on_form_post(client):
    social_login(client, "apple", tamper={"state": "forged-state"})
    assert any("Invalid sign-in state" in f for f in flashes(client))
    assert User.query.count() == 0


def test_code_is_single_use_and_pkce_enforced(client, app):
    # Capture a valid code, then try to redeem it twice / with the wrong verifier
    start = client.get("/oauth/google/start").headers["Location"]
    params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(start).query))
    r = client.post(start.split("?")[0], data={**params, "email": "x.dummy@example.com", "decision": "allow", "email_verified": "on"})
    code = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["Location"]).query))["code"]
    token_url = "/dev/oauth/google/token"
    base = {"grant_type": "authorization_code", "code": code, "redirect_uri": params["redirect_uri"],
            "client_id": params["client_id"], "client_secret": app.config["OAUTH_GOOGLE_CLIENT_SECRET"]}
    assert client.post(token_url, data={**base, "code_verifier": "wrong-verifier"}).status_code == 400
    assert client.post(token_url, data={**base, "client_secret": "bad"}).status_code == 401
    # the wrong-verifier attempt consumed the code (single use) - a real flow would now fail
    with client.session_transaction() as sess:
        verifier = sess[oauth.SESSION_KEY]["verifier"]
    assert client.post(token_url, data={**base, "code_verifier": verifier}).get_json()["error"] == "invalid_grant"


def test_unknown_provider_and_unconfigured_provider_404(tmp_path):
    app = create_app("testing", overrides={"OAUTH_PROVIDERS": ["google"]})
    app.instance_path = str(tmp_path)
    with app.app_context():
        c = app.test_client()
        assert c.get("/oauth/github/start").status_code == 404
        assert c.get("/oauth/facebook/start").status_code == 404
        page = c.get("/login").data
        assert b"Continue with Google" in page and b"Continue with Facebook" not in page
        db.session.remove()


def test_provider_without_email_is_refused(client):
    r = social_login(client, "facebook", email="hidden.dummy@example.com", verified=False)  # fb only returns verified e-mails
    assert r.headers["Location"].endswith("/login")
    assert any("did not share an e-mail" in f for f in flashes(client))
    assert User.query.count() == 0


def test_flow_expires(client):
    client.get("/oauth/google/start")
    with client.session_transaction() as sess:
        sess[oauth.SESSION_KEY] = {**sess[oauth.SESSION_KEY], "exp": 0}
    client.get("/oauth/google/callback?code=x&state=y")
    assert any("expired" in f for f in flashes(client))


def test_fake_provider_absent_in_real_mode(tmp_path):
    app = create_app("testing", overrides={"OAUTH_MODE": "real"})
    app.instance_path = str(tmp_path)
    with app.app_context():
        c = app.test_client()
        assert c.get("/dev/oauth/google/authorize").status_code == 404
        # real mode points at the real Google endpoint
        assert c.get("/oauth/google/start").headers["Location"].startswith("https://accounts.google.com/")
        db.session.remove()


# ============================================================ jwt helpers

def test_jwt_hs256_roundtrip_and_claim_checks():
    tok = jwt_min.sign_hs256({"iss": "fake-apple", "aud": "me", "sub": "1", "nonce": "n", "exp": time.time() + 60}, "k")
    payload = jwt_min.verify_hs256(tok, "k")
    jwt_min.check_claims(payload, issuer="fake-apple", audience="me", nonce="n")
    with pytest.raises(jwt_min.JWTError):
        jwt_min.verify_hs256(tok, "other-key")
    with pytest.raises(jwt_min.JWTError):
        jwt_min.check_claims(payload, issuer="fake-apple", audience="me", nonce="wrong")
    with pytest.raises(jwt_min.JWTError):
        jwt_min.check_claims({**payload, "exp": time.time() - 600}, issuer="fake-apple", audience="me")
    # alg:none / alg confusion is rejected
    none_tok = tok.split(".")
    none_tok[0] = jwt_min.b64url_encode(b'{"alg":"none"}')
    with pytest.raises(jwt_min.JWTError):
        jwt_min.verify_hs256(".".join(none_tok), "k")


def test_apple_client_secret_es256_with_cryptography():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    tok = jwt_min.sign_es256({"iss": "TEAM", "sub": "svc"}, pem, "KID1")
    header, payload = jwt_min.peek(tok)
    assert header == {"alg": "ES256", "kid": "KID1"} and payload["iss"] == "TEAM"
    assert len(jwt_min.b64url_decode(tok.split(".")[2])) == 64  # raw r||s, JOSE format


def test_rs256_verification_against_jwks():
    pytest.importorskip("cryptography")
    import json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()
    jwks = {"keys": [{"kid": "k1", "kty": "RSA", "n": jwt_min.b64url_encode(pub.n.to_bytes(256, "big")), "e": jwt_min.b64url_encode(pub.e.to_bytes(3, "big"))}]}
    header = jwt_min.b64url_encode(json.dumps({"alg": "RS256", "kid": "k1"}).encode())
    payload = jwt_min.b64url_encode(json.dumps({"sub": "apple-user"}).encode())
    sig = key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    tok = f"{header}.{payload}.{jwt_min.b64url_encode(sig)}"
    assert jwt_min.verify_rs256_jwks(tok, jwks)["sub"] == "apple-user"
    with pytest.raises(jwt_min.JWTError):
        jwt_min.verify_rs256_jwks(tok[:-4] + "AAAA", jwks)
