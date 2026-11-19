"""
FAKE identity provider (stub for Google / Apple / Facebook) - development only.

Mounted at /dev/oauth/<provider>/... when OAUTH_MODE=fake and ENABLE_DEV_TOOLS is on.
The OAuth client (auth/oauth.py) talks to these endpoints exactly like it would talk to
the real provider, so the production code path is what gets exercised:

    GET  /dev/oauth/<p>/authorize   consent page: pick the test identity, Allow / Deny
    POST /dev/oauth/<p>/authorize   issue a single-use authorization code and redirect back
                                    (Apple: response_mode=form_post -> cross-site POST page)
    POST /dev/oauth/<p>/token       exchange the code (client auth + redirect_uri + PKCE S256)
    GET  /dev/oauth/<p>/userinfo    profile for a Bearer access token (Google / Facebook)
    GET  /dev/oauth/<p>/keys        JWKS placeholder (the fake id_token is HS256-signed with
                                    FAKE_OAUTH_SIGNING_KEY, see auth/jwt_min.py)

The provider logic lives in `FakeIdentityProvider`, which has no Flask dependency, so
scripts/fake_oauth_server.py can host the very same stub on another machine.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode, urlsplit

from flask import Blueprint, abort, current_app, jsonify, redirect, render_template, request

from extensions import csrf

from . import jwt_min

fake_oauth_bp = Blueprint("fake_oauth", __name__, url_prefix="/dev/oauth")

PROVIDERS = ("google", "apple", "facebook")
CODE_TTL = 300  # seconds an authorization code stays exchangeable
TOKEN_TTL = 3600

# Suggested identities on the consent page (RFC 2606 documentation domains).
PRESETS = {
    "google": {"email": "dummy.google.user@example.com", "name": "Dummy Google User"},
    "apple": {"email": "dummy.apple.user@example.com", "name": "Dummy Apple User"},
    "facebook": {"email": "dummy.facebook.user@example.com", "name": "Dummy Facebook User"},
}


@dataclass
class Identity:
    email: str
    name: str
    email_verified: bool = True
    first_time: bool = True  # Apple only sends the name on the first authorization

    @property
    def subject(self) -> str:
        """Stable per-e-mail subject so the same test identity maps to the same account."""
        import hashlib

        return "fake-" + hashlib.sha256(self.email.lower().encode()).hexdigest()[:20]


@dataclass
class _Grant:
    provider: str
    identity: Identity
    client_id: str
    redirect_uri: str
    nonce: str | None
    code_challenge: str | None
    code_challenge_method: str | None
    expires_at: float = field(default_factory=lambda: time.time() + CODE_TTL)


class FakeIdentityProvider:
    """Framework-independent stub. One instance per process keeps codes / tokens in memory."""

    def __init__(self, *, signing_key: str, clients: dict[str, tuple[str, str]]):
        """
        clients: provider -> (client_id, client_secret). Apple's secret is a JWT in real life;
        the stub accepts the DUMMY placeholder auth/oauth.py sends in fake mode.
        """
        self.signing_key = signing_key
        self.clients = clients
        self._codes: dict[str, _Grant] = {}
        self._tokens: dict[str, _Grant] = {}

    # ------------------------------------------------------------ validation
    def check_authorize_request(self, provider: str, params) -> list[str]:
        problems = []
        client_id, _ = self.clients.get(provider, ("", ""))
        if params.get("client_id") != client_id:
            problems.append("client_id does not match the configured credentials")
        if params.get("response_type") != "code":
            problems.append("response_type must be 'code'")
        if not params.get("redirect_uri"):
            problems.append("redirect_uri is missing")
        if not params.get("state"):
            problems.append("state is missing (CSRF protection)")
        if params.get("code_challenge") and params.get("code_challenge_method") != "S256":
            problems.append("only PKCE S256 is supported")
        if provider == "apple" and params.get("response_mode") != "form_post":
            problems.append("Apple requires response_mode=form_post")
        return problems

    # ------------------------------------------------------------ authorize
    def issue_code(self, provider: str, params, identity: Identity) -> str:
        code = secrets.token_urlsafe(24)
        self._codes[code] = _Grant(
            provider=provider, identity=identity, client_id=params.get("client_id", ""),
            redirect_uri=params.get("redirect_uri", ""), nonce=params.get("nonce"),
            code_challenge=params.get("code_challenge"), code_challenge_method=params.get("code_challenge_method"),
        )
        return code

    # ------------------------------------------------------------ token
    def exchange(self, provider: str, form, issuer: str) -> tuple[int, dict]:
        """RFC 6749 token endpoint. Returns (http_status, json_body)."""
        client_id, client_secret = self.clients.get(provider, ("", ""))
        if form.get("grant_type") != "authorization_code":
            return 400, {"error": "unsupported_grant_type"}
        if form.get("client_id") != client_id or not secrets.compare_digest(str(form.get("client_secret", "")), client_secret):
            return 401, {"error": "invalid_client"}
        grant = self._codes.pop(str(form.get("code", "")), None)  # single use
        if grant is None or grant.provider != provider or grant.expires_at < time.time():
            return 400, {"error": "invalid_grant", "error_description": "unknown, expired or already used code"}
        if grant.client_id != client_id or form.get("redirect_uri") != grant.redirect_uri:
            return 400, {"error": "invalid_grant", "error_description": "redirect_uri mismatch"}
        if grant.code_challenge:
            verifier = str(form.get("code_verifier", ""))
            import hashlib

            expected = jwt_min.b64url_encode(hashlib.sha256(verifier.encode()).digest())
            if not verifier or not secrets.compare_digest(expected, grant.code_challenge):
                return 400, {"error": "invalid_grant", "error_description": "PKCE verification failed"}
        access_token = secrets.token_urlsafe(32)
        self._tokens[access_token] = grant
        body = {"access_token": access_token, "token_type": "Bearer", "expires_in": TOKEN_TTL, "scope": "openid email profile"}
        if provider in ("google", "apple"):
            body["id_token"] = self._id_token(grant, issuer)
        return 200, body

    def _id_token(self, grant: _Grant, issuer: str) -> str:
        now = int(time.time())
        ident = grant.identity
        payload = {
            "iss": issuer, "aud": grant.client_id, "sub": ident.subject, "iat": now, "exp": now + TOKEN_TTL,
            "email": ident.email, "email_verified": ident.email_verified,
        }
        if grant.nonce:
            payload["nonce"] = grant.nonce
        if grant.provider == "google":
            payload["name"] = ident.name
        return jwt_min.sign_hs256(payload, self.signing_key)

    # ------------------------------------------------------------ userinfo
    def userinfo(self, provider: str, authorization: str | None) -> tuple[int, dict]:
        token = (authorization or "").removeprefix("Bearer ").strip()
        grant = self._tokens.get(token)
        if grant is None or grant.provider != provider:
            return 401, {"error": "invalid_token"}
        ident = grant.identity
        if provider == "facebook":
            body = {"id": ident.subject, "name": ident.name}
            if ident.email_verified:  # Facebook only returns verified e-mails
                body["email"] = ident.email
            return 200, body
        return 200, {"sub": ident.subject, "email": ident.email, "email_verified": ident.email_verified, "name": ident.name}

    # ------------------------------------------------------------ helpers
    @staticmethod
    def apple_user_json(identity: Identity) -> str | None:
        """Apple posts {"name": {...}, "email": ...} only on the first authorization."""
        if not identity.first_time:
            return None
        first, _, last = identity.name.partition(" ")
        return json.dumps({"name": {"firstName": first, "lastName": last}, "email": identity.email})

    @staticmethod
    def add_query(url: str, params: dict) -> str:
        return url + ("&" if "?" in url else "?") + urlencode(params)


# ======================================================================= Flask glue

def _provider() -> FakeIdentityProvider:
    ext = current_app.extensions.get("fake_oauth")
    if ext is None:
        cfg = current_app.config
        ext = FakeIdentityProvider(
            signing_key=cfg["FAKE_OAUTH_SIGNING_KEY"],
            clients={
                "google": (cfg["OAUTH_GOOGLE_CLIENT_ID"], cfg["OAUTH_GOOGLE_CLIENT_SECRET"]),
                "facebook": (cfg["OAUTH_FACEBOOK_APP_ID"], cfg["OAUTH_FACEBOOK_APP_SECRET"]),
                "apple": (cfg["OAUTH_APPLE_CLIENT_ID"], "DUMMY_APPLE_CLIENT_SECRET_JWT"),
            },
        )
        current_app.extensions["fake_oauth"] = ext
    return ext


def _check_provider(provider: str) -> None:
    if provider not in PROVIDERS:
        abort(404)


def _redirect_uri_allowed(uri: str) -> bool:
    """The stub only redirects back to this app (or a relative path) - never to an arbitrary host."""
    parts = urlsplit(uri)
    if not parts.scheme and not parts.netloc:
        return uri.startswith("/") and not uri.startswith("//")
    app_base = current_app.config.get("APP_BASE_URL") or request.url_root.rstrip("/")
    base = urlsplit(app_base)
    return parts.scheme == base.scheme and parts.netloc == base.netloc


@fake_oauth_bp.route("/<provider>/authorize", methods=["GET", "POST"])
def authorize(provider: str):
    _check_provider(provider)
    idp = _provider()
    params = request.values
    problems = idp.check_authorize_request(provider, params)
    if params.get("redirect_uri") and not _redirect_uri_allowed(params["redirect_uri"]):
        problems.append("redirect_uri must point at this app")
    preset = {"email": params.get("email") or PRESETS[provider]["email"], "name": params.get("name") or PRESETS[provider]["name"]}

    if request.method == "GET" or problems:
        return render_template("dev/oauth_consent.html", provider=provider, params=params, problems=problems,
                               preset=preset, apple=provider == "apple"), (400 if problems else 200)

    redirect_uri, state = params["redirect_uri"], params["state"]
    if request.form.get("decision") != "allow":
        result = {"error": "access_denied", "state": state}
        if provider == "apple":
            return render_template("dev/oauth_form_post.html", action=redirect_uri, code="", state=state, user_json=None, error="access_denied")
        return redirect(idp.add_query(redirect_uri, result))

    email = request.form.get("email", "").strip().lower()
    if "@" not in email:
        problems.append("Enter the e-mail address the provider should assert")
        return render_template("dev/oauth_consent.html", provider=provider, params=params, problems=problems,
                               preset=preset, apple=provider == "apple"), 400
    identity = Identity(
        email=email, name=request.form.get("name", "").strip()[:120] or PRESETS[provider]["name"],
        email_verified=bool(request.form.get("email_verified")), first_time=bool(request.form.get("first_time")),
    )
    code = idp.issue_code(provider, params, identity)
    current_app.logger.info("fake %s: consent granted for %s, code issued", provider, email)
    if provider == "apple":
        return render_template("dev/oauth_form_post.html", action=redirect_uri, code=code, state=state,
                               user_json=idp.apple_user_json(identity))
    return redirect(idp.add_query(redirect_uri, {"code": code, "state": state}))


@fake_oauth_bp.route("/<provider>/token", methods=["POST"])
@csrf.exempt  # server-to-server call from the OAuth client: no browser session, no CSRF token
def token(provider: str):
    _check_provider(provider)
    status, body = _provider().exchange(provider, request.form, issuer=f"fake-{provider}")
    return jsonify(body), status


@fake_oauth_bp.route("/<provider>/userinfo")
def userinfo(provider: str):
    _check_provider(provider)
    status, body = _provider().userinfo(provider, request.headers.get("Authorization"))
    return jsonify(body), status


@fake_oauth_bp.route("/<provider>/keys")
def keys(provider: str):
    _check_provider(provider)
    # The fake id_token is HS256 (shared FAKE_OAUTH_SIGNING_KEY); there is no public key to publish.
    return jsonify(keys=[], note="fake provider: id_tokens are HS256-signed with FAKE_OAUTH_SIGNING_KEY")
