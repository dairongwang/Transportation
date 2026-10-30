"""
FAKE identity provider (stub for Google / Apple / Facebook) hosted by the app itself at
/dev/oauth/<provider>/...  -  active only when OAUTH_MODE=fake and ENABLE_DEV_TOOLS=true.

It behaves like the real thing from the client's point of view:
  * /authorize  shows a consent page where the tester chooses the identity (e-mail, name,
                verified flag) and can Allow or Deny; Apple uses response_mode=form_post
  * /token      checks client_id + client_secret, grant_type, redirect_uri, single-use code
                and the PKCE code_verifier (S256); returns access_token (+ id_token for
                Google/Apple, HS256-signed with FAKE_OAUTH_SIGNING_KEY)
  * /userinfo   Google-shaped (sub/email/email_verified/name) or Facebook-shaped (id/name/email)
  * /keys       JWKS placeholder

No data leaves the machine, no real accounts are involved. scripts/fake_oauth_server.py is
the same stub as a standalone process for testing from another machine.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request

from extensions import csrf

fake_oauth_bp = Blueprint("fake_oauth", __name__, url_prefix="/dev/oauth")

PROVIDERS = ("google", "apple", "facebook")
_CODES: dict[str, dict] = {}  # code -> grant (single use, 5 min)
_TOKENS: dict[str, dict] = {}  # access_token -> profile
CODE_TTL = 300

# Pre-canned DUMMY identities offered on the consent page (editable there).
PRESETS = {
    "google": {"email": "tester.dummy@gmail.example", "name": "Gina Google (dummy)"},
    "apple": {"email": "tester.dummy@privaterelay.appleid.example", "name": "Ava Apple (dummy)"},
    "facebook": {"email": "tester.dummy@facebook.example", "name": "Frank Facebook (dummy)"},
}


def _expected_client(provider: str) -> tuple[str, str | None]:
    from .oauth import client_id

    cfg = current_app.config
    secret = {
        "google": cfg["OAUTH_GOOGLE_CLIENT_SECRET"],
        "facebook": cfg["OAUTH_FACEBOOK_APP_SECRET"],
        "apple": "DUMMY_APPLE_CLIENT_SECRET_JWT",
    }[provider]
    return client_id(provider), secret


def _subject(provider: str, email: str) -> str:
    """Stable per-(provider, e-mail) subject id, like a real provider's user id."""
    return provider[:2] + "_" + hashlib.sha256(f"{provider}:{email.lower()}".encode()).hexdigest()[:20]


@fake_oauth_bp.before_request
def _guard():
    if current_app.config.get("OAUTH_MODE") != "fake":
        abort(404)


@fake_oauth_bp.route("/<provider>/authorize", methods=["GET", "POST"])
def authorize(provider):
    if provider not in PROVIDERS:
        abort(404)
    q = request.values
    expected_id, _ = _expected_client(provider)
    problems = []
    if q.get("client_id") != expected_id:
        problems.append(f"client_id mismatch (got {q.get('client_id')!r})")
    if q.get("response_type") != "code":
        problems.append("response_type must be 'code'")
    if not q.get("redirect_uri", "").endswith(f"/oauth/{provider}/callback"):
        problems.append("redirect_uri is not this app's callback")
    if q.get("code_challenge_method", "S256") != "S256" or not q.get("code_challenge"):
        problems.append("PKCE S256 code_challenge required")
    if not q.get("state"):
        problems.append("state missing")

    if request.method == "POST" and not problems:
        if q.get("decision") != "allow":
            sep = "&" if "?" in q["redirect_uri"] else "?"
            return redirect(f"{q['redirect_uri']}{sep}error=access_denied&state={q['state']}")
        email = (q.get("email") or PRESETS[provider]["email"]).strip().lower()
        name = (q.get("name") or PRESETS[provider]["name"]).strip()
        verified = q.get("email_verified") == "on"
        code = secrets.token_urlsafe(24)
        _CODES[code] = {
            "provider": provider,
            "client_id": expected_id,
            "redirect_uri": q["redirect_uri"],
            "code_challenge": q["code_challenge"],
            "nonce": q.get("nonce"),
            "exp": time.time() + CODE_TTL,
            "profile": {"sub": _subject(provider, email), "email": email, "email_verified": verified, "name": name},
        }
        if q.get("response_mode") == "form_post":  # Apple
            user_json = '{"name":{"firstName":"%s","lastName":"%s"},"email":"%s"}' % (
                name.split(" ")[0], " ".join(name.split(" ")[1:]), email
            )
            return render_template("dev/oauth_form_post.html", provider=provider, action=q["redirect_uri"],
                                   code=code, state=q["state"], user_json=user_json if q.get("first_time") == "on" else None)
        sep = "&" if "?" in q["redirect_uri"] else "?"
        return redirect(f"{q['redirect_uri']}{sep}code={code}&state={q['state']}")

    return render_template("dev/oauth_consent.html", provider=provider, params=q, problems=problems,
                           preset=PRESETS[provider], apple=(provider == "apple"))


@fake_oauth_bp.route("/<provider>/token", methods=["POST"])
@csrf.exempt  # server-to-server call from the OAuth client
def token(provider):
    if provider not in PROVIDERS:
        abort(404)
    f = request.form
    expected_id, expected_secret = _expected_client(provider)

    def err(code, desc, status=400):
        return jsonify(error=code, error_description=desc), status

    if f.get("client_id") != expected_id or f.get("client_secret") != expected_secret:
        return err("invalid_client", "client authentication failed", 401)
    if f.get("grant_type") != "authorization_code":
        return err("unsupported_grant_type", "only authorization_code is supported")
    grant = _CODES.pop(f.get("code", ""), None)  # single use
    if grant is None or grant["exp"] < time.time() or grant["provider"] != provider:
        return err("invalid_grant", "unknown, expired or already used code")
    if f.get("redirect_uri") != grant["redirect_uri"]:
        return err("invalid_grant", "redirect_uri mismatch")
    verifier = f.get("code_verifier", "")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    if not secrets.compare_digest(challenge, grant["code_challenge"]):
        return err("invalid_grant", "PKCE verification failed")

    access = secrets.token_urlsafe(32)
    _TOKENS[access] = {**grant["profile"], "provider": provider}
    body = {"access_token": access, "token_type": "Bearer", "expires_in": 3600}
    if provider in ("google", "apple"):
        from . import jwt_min

        now = int(time.time())
        claims = {
            "iss": f"fake-{provider}",
            "aud": expected_id,
            "sub": grant["profile"]["sub"],
            "email": grant["profile"]["email"],
            "email_verified": grant["profile"]["email_verified"],
            "iat": now,
            "exp": now + 600,
            "nonce": grant["nonce"],
        }
        body["id_token"] = jwt_min.sign_hs256(claims, current_app.config["FAKE_OAUTH_SIGNING_KEY"])
    return jsonify(body)


@fake_oauth_bp.route("/<provider>/userinfo")
def userinfo(provider):
    auth = request.headers.get("Authorization", "")
    profile = _TOKENS.get(auth[7:]) if auth.startswith("Bearer ") else None
    if profile is None or profile["provider"] != provider:
        return jsonify(error="invalid_token"), 401
    if provider == "facebook":
        return jsonify(id=profile["sub"], name=profile["name"], email=profile["email"] if profile["email_verified"] else None)
    return jsonify(sub=profile["sub"], email=profile["email"], email_verified=profile["email_verified"], name=profile["name"])


@fake_oauth_bp.route("/<provider>/keys")
def keys(provider):
    return jsonify(keys=[], note="fake provider signs id_tokens with HS256 + FAKE_OAUTH_SIGNING_KEY")
