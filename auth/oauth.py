"""
OAuth 2.0 / OpenID Connect client for "Continue with Google / Apple / Facebook".

Standard library only (urllib). Authorization-code flow with:
  * `state`  - CSRF protection for the callback (random, bound to the session)
  * PKCE     - S256 code challenge (protects the code even if intercepted)
  * `nonce`  - bound into Apple/Google id_tokens (replay protection)

Providers
---------
google    OIDC. Profile from the userinfo endpoint using the access token.
facebook  OAuth 2.0. Profile from Graph API /me?fields=id,name,email.
apple     OIDC with quirks: response_mode=form_post (POST callback), client_secret is a
          short-lived ES256 JWT signed with your .p8 key, the profile comes from the
          id_token (name only on the FIRST authorization via the `user` form field).

OAUTH_MODE=fake swaps every endpoint for the stub identity provider (auth/fake_oauth.py or
scripts/fake_oauth_server.py). The client code path is identical - only URLs differ.

Security notes
--------------
* Tokens are obtained server-to-server over TLS with client authentication, so the access
  token / id_token are trusted as coming from the provider. Apple id_tokens are additionally
  signature-checked against Apple's JWKS when `cryptography` is installed.
* E-mail addresses from providers are only treated as verified when the provider says so
  (`email_verified`); auth.oauth_routes decides what that permits.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from flask import current_app, request, session, url_for

from . import jwt_min

log = logging.getLogger("auth.oauth")

SESSION_KEY = "oauth_flow"  # {'provider','state','verifier','nonce','next','link'}
FLOW_TTL = 600
SUPPORTED = ("google", "apple", "facebook")
LABELS = {"google": "Google", "apple": "Apple", "facebook": "Facebook"}


class OAuthError(Exception):
    """User-presentable failure."""


@dataclass
class Profile:
    provider: str
    subject: str  # provider's stable user id
    email: str | None
    email_verified: bool
    name: str | None


# ------------------------------------------------------------- providers

def _real_endpoints(provider: str) -> dict:
    return {
        "google": {
            "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
            "token": "https://oauth2.googleapis.com/token",
            "userinfo": "https://openidconnect.googleapis.com/v1/userinfo",
            "scope": "openid email profile",
            "issuer": ["https://accounts.google.com", "accounts.google.com"],
        },
        "facebook": {
            "authorize": "https://www.facebook.com/v19.0/dialog/oauth",
            "token": "https://graph.facebook.com/v19.0/oauth/access_token",
            "userinfo": "https://graph.facebook.com/v19.0/me?fields=id,name,email",
            "scope": "email public_profile",
        },
        "apple": {
            "authorize": "https://appleid.apple.com/auth/authorize",
            "token": "https://appleid.apple.com/auth/token",
            "jwks": "https://appleid.apple.com/auth/keys",
            "scope": "name email",
            "issuer": "https://appleid.apple.com",
            "response_mode": "form_post",
        },
    }[provider]


def _fake_endpoints(provider: str) -> dict:
    base = current_app.config.get("OAUTH_FAKE_BASE_URL") or (request.url_root.rstrip("/") + "/dev/oauth")
    ep = {
        "authorize": f"{base}/{provider}/authorize",
        "token": f"{base}/{provider}/token",
        "userinfo": f"{base}/{provider}/userinfo",
        "jwks": f"{base}/{provider}/keys",
        "scope": _real_endpoints(provider)["scope"],
        "issuer": f"fake-{provider}",
        "fake": True,
    }
    if provider == "apple":
        ep["response_mode"] = "form_post"
    return ep


def endpoints(provider: str) -> dict:
    if provider not in SUPPORTED:
        raise OAuthError("Unknown sign-in provider.")
    if is_fake():
        return _fake_endpoints(provider)
    return _real_endpoints(provider)


def is_fake() -> bool:
    return current_app.config.get("OAUTH_MODE", "fake") == "fake"


def enabled_providers() -> list[str]:
    return [p for p in current_app.config.get("OAUTH_PROVIDERS", []) if p in SUPPORTED]


def client_id(provider: str) -> str:
    cfg = current_app.config
    return {"google": cfg["OAUTH_GOOGLE_CLIENT_ID"], "facebook": cfg["OAUTH_FACEBOOK_APP_ID"], "apple": cfg["OAUTH_APPLE_CLIENT_ID"]}[provider]


def client_secret(provider: str) -> str:
    cfg = current_app.config
    if provider == "google":
        return cfg["OAUTH_GOOGLE_CLIENT_SECRET"]
    if provider == "facebook":
        return cfg["OAUTH_FACEBOOK_APP_SECRET"]
    return apple_client_secret()


def apple_client_secret() -> str:
    """
    Apple requires a JWT (ES256, max 6 months) as the client secret. With the fake provider
    a DUMMY placeholder is accepted so the flow can be validated without an Apple key.
    """
    cfg = current_app.config
    if is_fake():
        return "DUMMY_APPLE_CLIENT_SECRET_JWT"
    pem = cfg["OAUTH_APPLE_PRIVATE_KEY"]
    if pem and os.path.exists(pem):
        pem = open(pem, encoding="utf-8").read()
    pem = (pem or "").replace("\\n", "\n")
    if "BEGIN" not in pem:
        raise OAuthError("Apple sign-in is not configured (OAUTH_APPLE_PRIVATE_KEY).")
    now = int(time.time())
    payload = {"iss": cfg["OAUTH_APPLE_TEAM_ID"], "iat": now, "exp": now + 3600, "aud": "https://appleid.apple.com", "sub": cfg["OAUTH_APPLE_CLIENT_ID"]}
    try:
        return jwt_min.sign_es256(payload, pem, cfg["OAUTH_APPLE_KEY_ID"])
    except jwt_min.JWTError as exc:
        raise OAuthError(f"Apple sign-in unavailable: {exc}") from exc


def redirect_uri(provider: str) -> str:
    base = current_app.config.get("APP_BASE_URL") or request.url_root.rstrip("/")
    return base + url_for("auth.oauth_callback", provider=provider)


# ------------------------------------------------------------------ start

def begin(provider: str, *, next_url: str | None = None, link: bool = False) -> str:
    """Store flow state in the session and return the provider's authorization URL."""
    ep = endpoints(provider)
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    nonce = secrets.token_urlsafe(16)
    challenge = jwt_min.b64url_encode(hashlib.sha256(verifier.encode()).digest())
    session[SESSION_KEY] = {
        "provider": provider,
        "state": state,
        "verifier": verifier,
        "nonce": nonce,
        "next": next_url,
        "link": link,
        "exp": time.time() + FLOW_TTL,
    }
    params = {
        "client_id": client_id(provider),
        "redirect_uri": redirect_uri(provider),
        "response_type": "code",
        "scope": ep["scope"],
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    if ep.get("response_mode"):
        params["response_mode"] = ep["response_mode"]
    if provider == "google":
        params["access_type"] = "online"
        params["prompt"] = "select_account"
    return ep["authorize"] + "?" + urllib.parse.urlencode(params)


# --------------------------------------------------------------- callback

def _in_app_fake(url: str) -> str | None:
    """Path of an in-app fake-provider URL (None for anything external)."""
    if not is_fake() or current_app.config.get("OAUTH_FAKE_BASE_URL"):
        return None
    parsed = urllib.parse.urlparse(url)
    if parsed.path.startswith("/dev/oauth/"):
        return parsed.path + (f"?{parsed.query}" if parsed.query else "")
    return None


def _http_json(url: str, data: dict | None = None, headers: dict | None = None) -> dict:
    path = _in_app_fake(url)
    if path is not None:
        # Server-to-server call to the stub hosted by this very app: dispatch internally
        # instead of over the network (works in tests and with single-threaded servers).
        with current_app.test_client() as tc:
            resp = tc.open(path, method="POST" if data is not None else "GET", data=data, headers=headers or {})
        if resp.status_code >= 400:
            log.error("OAuth fake provider HTTP %s from %s: %s", resp.status_code, path, resp.get_data(as_text=True)[:300])
            raise OAuthError("The sign-in provider rejected the request.")
        return resp.get_json()
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Accept": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        log.error("OAuth HTTP %s from %s: %s", exc.code, url, detail)
        raise OAuthError("The sign-in provider rejected the request.") from exc
    except (OSError, ValueError) as exc:
        log.error("OAuth request to %s failed: %s", url, exc)
        raise OAuthError("Could not reach the sign-in provider.") from exc


def finish(provider: str, args) -> tuple[Profile, dict]:
    """
    Validate the callback (`args` = request.values), exchange the code and return
    (profile, flow_state). Raises OAuthError on any problem. Consumes the flow state.
    """
    flow = session.pop(SESSION_KEY, None)
    if not flow or flow.get("provider") != provider or flow.get("exp", 0) < time.time():
        raise OAuthError("Sign-in session expired or invalid. Please try again.")
    if args.get("error"):
        raise OAuthError("Sign-in was cancelled." if args.get("error") == "access_denied" else f"Provider error: {args.get('error')}")
    state = args.get("state", "")
    if not state or not secrets.compare_digest(state, flow["state"]):
        raise OAuthError("Invalid sign-in state. Please try again.")
    code = args.get("code")
    if not code:
        raise OAuthError("No authorization code received.")

    ep = endpoints(provider)
    token = _http_json(
        ep["token"],
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri(provider),
            "client_id": client_id(provider),
            "client_secret": client_secret(provider),
            "code_verifier": flow["verifier"],
        },
    )
    if provider == "apple":
        profile = _apple_profile(token, ep, flow["nonce"], args.get("user"))
    elif provider == "google":
        profile = _google_profile(token, ep)
    else:
        profile = _facebook_profile(token, ep)
    return profile, flow


def _bearer(url: str, access_token: str) -> dict:
    return _http_json(url, headers={"Authorization": f"Bearer {access_token}"})


def _google_profile(token: dict, ep: dict) -> Profile:
    info = _bearer(ep["userinfo"], token.get("access_token", ""))
    if not info.get("sub"):
        raise OAuthError("Google did not return a user id.")
    return Profile("google", str(info["sub"]), info.get("email"), bool(info.get("email_verified")), info.get("name"))


def _facebook_profile(token: dict, ep: dict) -> Profile:
    info = _bearer(ep["userinfo"], token.get("access_token", ""))
    if not info.get("id"):
        raise OAuthError("Facebook did not return a user id.")
    # Facebook only returns e-mails it has verified.
    return Profile("facebook", str(info["id"]), info.get("email"), bool(info.get("email")), info.get("name"))


def _apple_profile(token: dict, ep: dict, nonce: str, user_json: str | None) -> Profile:
    id_token = token.get("id_token")
    if not id_token:
        raise OAuthError("Apple did not return an identity token.")
    if ep.get("fake"):
        payload = jwt_min.verify_hs256(id_token, current_app.config["FAKE_OAUTH_SIGNING_KEY"])
    elif jwt_min.HAVE_CRYPTOGRAPHY:
        payload = jwt_min.verify_rs256_jwks(id_token, _http_json(ep["jwks"]))
    else:
        # Token came straight from Apple's token endpoint over TLS with client auth; without
        # `cryptography` we cannot check the signature, so we only parse it. Install
        # cryptography for production (ProductionConfig requires it via Apple client secret).
        log.warning("cryptography not installed - Apple id_token signature NOT verified")
        _, payload = jwt_min.peek(id_token)
    try:
        jwt_min.check_claims(payload, issuer=ep["issuer"], audience=client_id("apple"), nonce=nonce)
    except jwt_min.JWTError as exc:
        raise OAuthError(f"Apple identity token rejected ({exc}).") from exc
    name = None
    if user_json:  # only on the first authorization
        try:
            n = json.loads(user_json).get("name") or {}
            name = " ".join(x for x in (n.get("firstName"), n.get("lastName")) if x) or None
        except (ValueError, AttributeError):
            name = None
    verified = payload.get("email_verified") in (True, "true")
    return Profile("apple", str(payload["sub"]), payload.get("email"), verified, name)
