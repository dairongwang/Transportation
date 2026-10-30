#!/usr/bin/env python3
"""
Standalone FAKE OAuth 2.0 / OIDC identity provider (stub for Google, Apple and Facebook).
Standard library only - runs on any OS, no accounts, no internet.

Same behaviour as the in-app stub (auth/fake_oauth.py) but as a separate process, so you
can validate the app's OAuth client against a "remote" provider, e.g. from another machine:

    python scripts/fake_oauth_server.py                 # http://127.0.0.1:8090
    python scripts/fake_oauth_server.py 0.0.0.0 8090    # reachable on the LAN

Then run the app with:
    OAUTH_MODE=fake  OAUTH_FAKE_BASE_URL=http://127.0.0.1:8090

Endpoints per provider (google | apple | facebook):
    GET/POST /<provider>/authorize   consent page -> code (Apple: form_post)
    POST     /<provider>/token       client auth + PKCE check -> access_token (+ id_token)
    GET      /<provider>/userinfo    profile for a Bearer token
    GET      /<provider>/keys        JWKS placeholder

Credentials it expects are the DUMMY ones from .env.example (override with env vars of the
same names: OAUTH_GOOGLE_CLIENT_ID, ... , FAKE_OAUTH_SIGNING_KEY).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENTS = {
    "google": (os.environ.get("OAUTH_GOOGLE_CLIENT_ID", "DUMMY_GOOGLE_CLIENT_ID.apps.googleusercontent.com"),
               os.environ.get("OAUTH_GOOGLE_CLIENT_SECRET", "DUMMY_GOOGLE_CLIENT_SECRET")),
    "facebook": (os.environ.get("OAUTH_FACEBOOK_APP_ID", "DUMMY_FACEBOOK_APP_ID"),
                 os.environ.get("OAUTH_FACEBOOK_APP_SECRET", "DUMMY_FACEBOOK_APP_SECRET")),
    "apple": (os.environ.get("OAUTH_APPLE_CLIENT_ID", "DUMMY_APPLE_SERVICE_ID"), "DUMMY_APPLE_CLIENT_SECRET_JWT"),
}
SIGNING_KEY = os.environ.get("FAKE_OAUTH_SIGNING_KEY", "DUMMY_FAKE_OAUTH_SIGNING_KEY")
PRESETS = {
    "google": ("tester.dummy@gmail.example", "Gina Google (dummy)"),
    "apple": ("tester.dummy@privaterelay.appleid.example", "Ava Apple (dummy)"),
    "facebook": ("tester.dummy@facebook.example", "Frank Facebook (dummy)"),
}
CODES: dict[str, dict] = {}
TOKENS: dict[str, dict] = {}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_hs256(payload: dict) -> str:
    head = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "fake-1"}).encode())
    body = b64url(json.dumps(payload).encode())
    sig = hmac.new(SIGNING_KEY.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64url(sig)}"


CONSENT = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<body style="font-family:sans-serif;max-width:480px;margin:2em auto">
<h2 style="background:#ffc107;padding:.5em">FAKE {label} sign-in <small>(stub identity provider)</small></h2>
<p>This stands in for {label}'s consent screen. Pick the identity to return to the app.</p>
{problems}
<form method=post>
{hidden}
<label>E-mail <input name=email value="{email}" style="width:100%"></label><br><br>
<label>Display name <input name=name value="{name}" style="width:100%"></label><br><br>
<label><input type=checkbox name=email_verified checked> E-mail verified by provider</label><br>
{apple}
<br><button name=decision value=allow>Allow</button> <button name=decision value=deny>Deny</button>
</form></body>"""

FORM_POST = """<!doctype html><body onload="document.forms[0].submit()" style="font-family:sans-serif;text-align:center">
<p>Apple form_post: submitting to the app...</p>
<form method=post action="{action}"><input type=hidden name=code value="{code}"><input type=hidden name=state value="{state}">
{user}<button>Continue</button></form></body>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[fake-oauth] {self.command} {self.path.split('?')[0]} -> {args[1] if len(args) > 1 else ''}", flush=True)

    # ------------------------------------------------------------ helpers
    def _send(self, status: int, body: bytes, ctype="text/html; charset=utf-8", extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict):
        self._send(status, json.dumps(payload).encode(), "application/json")

    def _route(self):
        parts = urllib.parse.urlparse(self.path)
        segs = parts.path.strip("/").split("/")
        if len(segs) != 2 or segs[0] not in CLIENTS:
            return None, None, {}
        return segs[0], segs[1], dict(urllib.parse.parse_qsl(parts.query))

    def _form(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return dict(urllib.parse.parse_qsl(self.rfile.read(length).decode()))

    # ----------------------------------------------------------------- GET
    def do_GET(self):
        provider, action, q = self._route()
        if provider is None:
            return self._send(404, b"not found")
        if action == "authorize":
            return self._consent(provider, q)
        if action == "userinfo":
            auth = self.headers.get("Authorization", "")
            prof = TOKENS.get(auth[7:]) if auth.startswith("Bearer ") else None
            if prof is None or prof["provider"] != provider:
                return self._json(401, {"error": "invalid_token"})
            if provider == "facebook":
                return self._json(200, {"id": prof["sub"], "name": prof["name"], "email": prof["email"] if prof["email_verified"] else None})
            return self._json(200, {k: prof[k] for k in ("sub", "email", "email_verified", "name")})
        if action == "keys":
            return self._json(200, {"keys": [], "note": "fake provider signs id_tokens with HS256"})
        self._send(404, b"not found")

    # ---------------------------------------------------------------- POST
    def do_POST(self):
        provider, action, q = self._route()
        if provider is None:
            return self._send(404, b"not found")
        form = self._form()
        if action == "authorize":
            return self._consent(provider, {**q, **form}, submitted=True)
        if action == "token":
            return self._token(provider, form)
        self._send(404, b"not found")

    # ------------------------------------------------------------ consent
    def _consent(self, provider: str, q: dict, submitted: bool = False):
        cid, _ = CLIENTS[provider]
        problems = []
        if q.get("client_id") != cid:
            problems.append(f"client_id mismatch (got {q.get('client_id')!r}, expected {cid!r})")
        if q.get("response_type") != "code":
            problems.append("response_type must be 'code'")
        if not q.get("redirect_uri", "").endswith(f"/oauth/{provider}/callback"):
            problems.append("redirect_uri is not the app's callback")
        if not q.get("code_challenge") or q.get("code_challenge_method", "S256") != "S256":
            problems.append("PKCE S256 code_challenge required")
        if not q.get("state"):
            problems.append("state missing")
        if submitted and not problems:
            sep = "&" if "?" in q["redirect_uri"] else "?"
            if q.get("decision") != "allow":
                return self._send(302, b"", extra={"Location": f"{q['redirect_uri']}{sep}error=access_denied&state={q['state']}"})
            email = (q.get("email") or PRESETS[provider][0]).strip().lower()
            name = (q.get("name") or PRESETS[provider][1]).strip()
            code = secrets.token_urlsafe(24)
            CODES[code] = {
                "provider": provider, "redirect_uri": q["redirect_uri"], "code_challenge": q["code_challenge"],
                "nonce": q.get("nonce"), "exp": time.time() + 300,
                "profile": {"sub": provider[:2] + "_" + hashlib.sha256(f"{provider}:{email}".encode()).hexdigest()[:20],
                            "email": email, "email_verified": q.get("email_verified") == "on", "name": name},
            }
            if q.get("response_mode") == "form_post":
                first, last = (name.split(" ") + [""])[:2]
                user = ""
                if q.get("first_time") == "on":
                    uj = json.dumps({"name": {"firstName": first, "lastName": last}, "email": email})
                    user = f'<input type=hidden name=user value="{html.escape(uj)}">'
                return self._send(200, FORM_POST.format(action=html.escape(q["redirect_uri"]), code=code, state=html.escape(q["state"]), user=user).encode())
            return self._send(302, b"", extra={"Location": f"{q['redirect_uri']}{sep}code={code}&state={q['state']}"})
        hidden = "".join(f'<input type=hidden name="{k}" value="{html.escape(v)}">' for k, v in q.items()
                         if k in ("client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "nonce", "response_mode"))
        page = CONSENT.format(
            label=provider.capitalize(),
            problems=("<p style='color:red'>Invalid request: " + "; ".join(problems) + "</p>") if problems else "",
            hidden=hidden, email=PRESETS[provider][0], name=PRESETS[provider][1],
            apple='<label><input type=checkbox name=first_time checked> First authorization (Apple sends the name once)</label>' if provider == "apple" else "",
        )
        self._send(200, page.encode())

    # -------------------------------------------------------------- token
    def _token(self, provider: str, f: dict):
        cid, csecret = CLIENTS[provider]
        if f.get("client_id") != cid or f.get("client_secret") != csecret:
            return self._json(401, {"error": "invalid_client"})
        if f.get("grant_type") != "authorization_code":
            return self._json(400, {"error": "unsupported_grant_type"})
        grant = CODES.pop(f.get("code", ""), None)
        if grant is None or grant["exp"] < time.time() or grant["provider"] != provider:
            return self._json(400, {"error": "invalid_grant", "error_description": "unknown, expired or used code"})
        if f.get("redirect_uri") != grant["redirect_uri"]:
            return self._json(400, {"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
        challenge = b64url(hashlib.sha256(f.get("code_verifier", "").encode()).digest())
        if not hmac.compare_digest(challenge, grant["code_challenge"]):
            return self._json(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})
        access = secrets.token_urlsafe(32)
        TOKENS[access] = {**grant["profile"], "provider": provider}
        body = {"access_token": access, "token_type": "Bearer", "expires_in": 3600}
        if provider in ("google", "apple"):
            now = int(time.time())
            body["id_token"] = sign_hs256({"iss": f"fake-{provider}", "aud": cid, "sub": grant["profile"]["sub"],
                                           "email": grant["profile"]["email"], "email_verified": grant["profile"]["email_verified"],
                                           "iat": now, "exp": now + 600, "nonce": grant["nonce"]})
        self._json(200, body)


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8090
    with ThreadingHTTPServer((host, port), Handler) as server:
        print(f"Fake OAuth identity provider listening on http://{host}:{port}  (Ctrl+C to stop)")
        print(f"Run the app with: OAUTH_MODE=fake OAUTH_FAKE_BASE_URL=http://{host}:{port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
