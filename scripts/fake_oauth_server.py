#!/usr/bin/env python3
"""
Standalone FAKE identity provider (Google / Apple / Facebook stub) on its own port.

The app normally hosts the stub itself at /dev/oauth/... . Run this when the provider
should live on ANOTHER machine / port (e.g. to test the real HTTP client path or to share
one stub between several app instances):

    python scripts/fake_oauth_server.py                 # http://127.0.0.1:8090
    python scripts/fake_oauth_server.py --port 8090 --host 0.0.0.0

then point the app at it in .env:

    OAUTH_FAKE_BASE_URL=http://127.0.0.1:8090/dev/oauth

Same logic as auth/fake_oauth.py (FakeIdentityProvider): client auth, redirect_uri binding,
single-use codes, PKCE S256, HS256 id_tokens signed with FAKE_OAUTH_SIGNING_KEY. The
credentials are read from .env so they match the app's.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from flask import Flask, jsonify, redirect, render_template_string, request  # noqa: E402

import config as cfg  # noqa: E402
from auth.fake_oauth import PRESETS, PROVIDERS, FakeIdentityProvider, Identity  # noqa: E402

CONSENT = """<!doctype html><title>FAKE {{ provider|capitalize }} sign-in</title>
<body style="font-family:sans-serif;max-width:34em;margin:3em auto">
<h2>FAKE {{ provider|capitalize }} sign-in <small style="color:#a60">(standalone stub)</small></h2>
{% if problems %}<div style="color:#b00"><b>Invalid authorization request:</b><ul>{% for p in problems %}<li>{{ p }}</li>{% endfor %}</ul></div>
{% else %}<form method="post">
{% for k, v in params.items() %}<input type="hidden" name="{{ k }}" value="{{ v }}">{% endfor %}
<p><label>E-mail the provider asserts<br><input name="email" value="{{ preset.email }}" size="40"></label></p>
<p><label>Display name<br><input name="name" value="{{ preset.name }}" size="40"></label></p>
<p><label><input type="checkbox" name="email_verified" checked> e-mail verified by the provider</label></p>
{% if provider == 'apple' %}<p><label><input type="checkbox" name="first_time" checked> first authorization (Apple sends the name once)</label></p>{% endif %}
<button name="decision" value="allow">Allow</button> <button name="decision" value="deny">Deny</button></form>{% endif %}
<details><summary>request</summary><pre>{% for k, v in params.items() %}{{ k }} = {{ v }}
{% endfor %}</pre></details></body>"""

FORM_POST = """<!doctype html><title>Apple form_post</title><body onload="document.forms[0].submit()">
<form method="post" action="{{ action }}">{% if error %}<input type="hidden" name="error" value="{{ error }}">{% else %}
<input type="hidden" name="code" value="{{ code }}">{% endif %}<input type="hidden" name="state" value="{{ state }}">
{% if user_json %}<input type="hidden" name="user" value='{{ user_json }}'>{% endif %}<button>Continue</button></form></body>"""


def build_app() -> Flask:
    import os

    app = Flask(__name__)
    idp = FakeIdentityProvider(
        signing_key=os.environ.get("FAKE_OAUTH_SIGNING_KEY") or cfg.DUMMY_FAKE_OAUTH_SIGNING_KEY,
        clients={
            "google": (os.environ.get("OAUTH_GOOGLE_CLIENT_ID") or cfg.DUMMY_OAUTH["GOOGLE_CLIENT_ID"],
                       os.environ.get("OAUTH_GOOGLE_CLIENT_SECRET") or cfg.DUMMY_OAUTH["GOOGLE_CLIENT_SECRET"]),
            "facebook": (os.environ.get("OAUTH_FACEBOOK_APP_ID") or cfg.DUMMY_OAUTH["FACEBOOK_APP_ID"],
                         os.environ.get("OAUTH_FACEBOOK_APP_SECRET") or cfg.DUMMY_OAUTH["FACEBOOK_APP_SECRET"]),
            "apple": (os.environ.get("OAUTH_APPLE_CLIENT_ID") or cfg.DUMMY_OAUTH["APPLE_CLIENT_ID"], "DUMMY_APPLE_CLIENT_SECRET_JWT"),
        },
    )

    @app.route("/")
    def index():
        return jsonify(fake_identity_provider=True, providers=list(PROVIDERS),
                       endpoints={p: f"/dev/oauth/{p}/{{authorize,token,userinfo,keys}}" for p in PROVIDERS})

    @app.route("/dev/oauth/<provider>/authorize", methods=["GET", "POST"])
    def authorize(provider):
        if provider not in PROVIDERS:
            return "unknown provider", 404
        params = request.values
        problems = idp.check_authorize_request(provider, params)
        preset = {"email": params.get("email") or PRESETS[provider]["email"], "name": params.get("name") or PRESETS[provider]["name"]}
        if request.method == "GET" or problems:
            return render_template_string(CONSENT, provider=provider, params=params, problems=problems, preset=preset), (400 if problems else 200)
        redirect_uri, state = params["redirect_uri"], params["state"]
        if request.form.get("decision") != "allow":
            if provider == "apple":
                return render_template_string(FORM_POST, action=redirect_uri, code="", state=state, user_json=None, error="access_denied")
            return redirect(idp.add_query(redirect_uri, {"error": "access_denied", "state": state}))
        identity = Identity(email=request.form.get("email", "").strip().lower(), name=request.form.get("name", "").strip() or PRESETS[provider]["name"],
                            email_verified=bool(request.form.get("email_verified")), first_time=bool(request.form.get("first_time")))
        code = idp.issue_code(provider, params, identity)
        app.logger.info("fake %s: consent granted for %s", provider, identity.email)
        if provider == "apple":
            return render_template_string(FORM_POST, action=redirect_uri, code=code, state=state, user_json=idp.apple_user_json(identity), error=None)
        return redirect(idp.add_query(redirect_uri, {"code": code, "state": state}))

    @app.route("/dev/oauth/<provider>/token", methods=["POST"])
    def token(provider):
        if provider not in PROVIDERS:
            return jsonify(error="unknown_provider"), 404
        status, body = idp.exchange(provider, request.form, issuer=f"fake-{provider}")
        return jsonify(body), status

    @app.route("/dev/oauth/<provider>/userinfo")
    def userinfo(provider):
        if provider not in PROVIDERS:
            return jsonify(error="unknown_provider"), 404
        status, body = idp.userinfo(provider, request.headers.get("Authorization"))
        return jsonify(body), status

    @app.route("/dev/oauth/<provider>/keys")
    def keys(provider):
        return jsonify(keys=[], note="fake provider: id_tokens are HS256-signed with FAKE_OAUTH_SIGNING_KEY")

    return app


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    args = ap.parse_args()
    print(f"Fake identity provider on http://{args.host}:{args.port}/dev/oauth/<provider>/...")
    print(f"  .env:  OAUTH_FAKE_BASE_URL=http://{args.host}:{args.port}/dev/oauth")
    build_app().run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
