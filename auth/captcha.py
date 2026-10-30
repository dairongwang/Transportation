"""
Pluggable CAPTCHA.

Providers (CAPTCHA_PROVIDER):
  none       never ask
  dummy      offline arithmetic challenge ("What is 3 + 4?") - a STUB for development and
             tests on any platform. Trivially solvable by a script: production refuses it.
  turnstile  Cloudflare Turnstile   (CAPTCHA_SITE_KEY / CAPTCHA_SECRET_KEY)
  hcaptcha   hCaptcha
  recaptcha  Google reCAPTCHA v2/v3

When is it shown?  `required(ip, user_id)` -> True once CAPTCHA_AFTER_FAILURES failed auth
events were recorded for the IP or the account inside CAPTCHA_WINDOW_MINUTES (or always,
when CAPTCHA_AFTER_FAILURES=0). Verification is server-side via stdlib urllib - no SDK.
"""

from __future__ import annotations

import json
import logging
import secrets
import urllib.parse
import urllib.request

from flask import current_app, request, session

from throttle import recent_failures

log = logging.getLogger("auth.captcha")

_VERIFY_URLS = {
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    "hcaptcha": "https://api.hcaptcha.com/siteverify",
    "recaptcha": "https://www.google.com/recaptcha/api/siteverify",
}
_SCRIPT_URLS = {
    "turnstile": "https://challenges.cloudflare.com/turnstile/v0/api.js",
    "hcaptcha": "https://js.hcaptcha.com/1/api.js",
    "recaptcha": "https://www.google.com/recaptcha/api.js",
}
_WIDGET_CLASS = {"turnstile": "cf-turnstile", "hcaptcha": "h-captcha", "recaptcha": "g-recaptcha"}
_RESPONSE_FIELD = {"turnstile": "cf-turnstile-response", "hcaptcha": "h-captcha-response", "recaptcha": "g-recaptcha-response"}

DUMMY_SESSION_KEY = "_dummy_captcha"


def provider() -> str:
    return current_app.config.get("CAPTCHA_PROVIDER", "none")


def required(ip: str | None, user_id: int | None = None) -> bool:
    if provider() == "none":
        return False
    threshold = current_app.config["CAPTCHA_AFTER_FAILURES"]
    if threshold <= 0:
        return True
    return recent_failures(ip=ip, user_id=user_id) >= threshold


def challenge() -> dict:
    """Context for templates/auth/_captcha.html."""
    p = provider()
    if p == "dummy":
        a, b = secrets.randbelow(9) + 1, secrets.randbelow(9) + 1
        session[DUMMY_SESSION_KEY] = str(a + b)
        return {"provider": p, "question": f"What is {a} + {b}?"}
    if p in _WIDGET_CLASS:
        return {
            "provider": p,
            "site_key": current_app.config["CAPTCHA_SITE_KEY"],
            "script_url": _SCRIPT_URLS[p],
            "widget_class": _WIDGET_CLASS[p],
        }
    return {"provider": "none"}


def verify(form) -> bool:
    """Validate the submitted challenge. Returns True when the CAPTCHA passed."""
    p = provider()
    if p == "none":
        return True
    if p == "dummy":
        expected = session.pop(DUMMY_SESSION_KEY, None)
        answer = (form.get("captcha_answer") or "").strip()
        return bool(expected) and secrets.compare_digest(expected, answer)
    token = form.get(_RESPONSE_FIELD.get(p, ""), "")
    if not token:
        return False
    data = urllib.parse.urlencode(
        {"secret": current_app.config["CAPTCHA_SECRET_KEY"], "response": token, "remoteip": request.remote_addr or ""}
    ).encode()
    try:
        with urllib.request.urlopen(_VERIFY_URLS[p], data=data, timeout=10) as resp:  # noqa: S310
            return bool(json.load(resp).get("success"))
    except (OSError, ValueError) as exc:
        log.error("CAPTCHA verification failed: %s", exc)
        return False


def csp_sources() -> list[str]:
    """Extra script-src / frame-src origins needed by the active provider."""
    return {
        "turnstile": ["https://challenges.cloudflare.com"],
        "hcaptcha": ["https://js.hcaptcha.com", "https://*.hcaptcha.com"],
        "recaptcha": ["https://www.google.com", "https://www.gstatic.com"],
    }.get(provider(), [])
