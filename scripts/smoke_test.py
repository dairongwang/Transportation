#!/usr/bin/env python3
"""
End-to-end smoke test against a RUNNING server — standard library only.

Exercises registration, login, all three 2FA methods, recovery codes and trusted
devices exactly as a browser would (cookies, CSRF tokens, redirects). Codes are read
from the app's fake inbox (/dev/outbox.json), so the server must run with
ENABLE_DEV_TOOLS=true and the console/memory (or fake smtp/twilio) backends.

    python scripts/smoke_test.py                       # against http://127.0.0.1:5000
    python scripts/smoke_test.py http://192.168.1.20:5000   # e.g. from another machine

Exit code 0 = all steps passed.
"""

from __future__ import annotations

import http.cookiejar
import json
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _totp_loader import load_totp  # noqa: E402

totp = load_totp()

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000").rstrip("/")
PASSWORD = "SmokeTest-Passw0rd!"
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
passed = failed = 0


_last_totp_step = 0


def fresh_totp(key: str, after_setup: bool = False) -> str:
    """
    Next authenticator code the server will accept: never reuse a time step (replay
    protection) and stay inside the +/-1 step drift window - sleeping to the next 30s
    boundary when necessary, like a person waiting for the code to roll over.
    """
    global _last_totp_step
    if after_setup:  # the server records the *current* step at setup time
        _last_totp_step = totp.counter_for()
    while True:
        now_step = totp.counter_for()
        candidate = max(_last_totp_step + 1, now_step)
        if candidate <= now_step + 1:
            _last_totp_step = candidate
            return totp.hotp(key, candidate)
        wait = 30 - int(time.time()) % 30 + 0.5
        print(f"      (waiting {wait:.0f}s for the next authenticator code)", flush=True)
        time.sleep(wait)


class Page:
    def __init__(self, url: str, status: int, body: str):
        self.url, self.status, self.body = url, status, body

    @property
    def csrf(self) -> str:
        m = re.search(r'name="csrf_token" value="([^"]+)"', self.body)
        return m.group(1) if m else ""

    @property
    def alerts(self) -> list[str]:
        return [re.sub(r"\s+", " ", a).strip() for a in re.findall(r'role="alert">\s*(.*?)\s*<button', self.body, re.S)]


def get(path: str) -> Page:
    try:
        with opener.open(BASE + path, timeout=15) as r:
            return Page(r.geturl(), r.status, r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return Page(e.geturl(), e.code, e.read().decode("utf-8", "replace"))


def solve_dummy_captcha(page: Page | None) -> str | None:
    """The dev 'dummy' CAPTCHA asks 'What is a + b?' - answer it like a human tester would."""
    if page is None:
        return None
    m = re.search(r"What is (\d+) \+ (\d+)\?", page.body)
    return str(int(m.group(1)) + int(m.group(2))) if m else None


def post(path: str, data: dict, csrf_from: Page | None = None) -> Page:
    data = dict(data)
    if csrf_from is not None and csrf_from.csrf:
        data["csrf_token"] = csrf_from.csrf
    answer = solve_dummy_captcha(csrf_from)
    if answer is not None and "captcha_answer" not in data:
        data["captcha_answer"] = answer
    req = urllib.request.Request(BASE + path, data=urllib.parse.urlencode(data).encode())
    try:
        with opener.open(req, timeout=15) as r:
            return Page(r.geturl(), r.status, r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return Page(e.geturl(), e.code, e.read().decode("utf-8", "replace"))


def latest_message(channel: str, to: str, pattern: str) -> str:
    for _ in range(10):
        with opener.open(BASE + "/dev/outbox.json", timeout=15) as r:
            for m in json.load(r):
                if m["channel"] == channel and m["to"] == to:
                    found = re.search(pattern, m["body"])
                    if found:
                        return found.group(1)
        time.sleep(0.5)
    raise AssertionError(f"no {channel} message for {to} matching {pattern!r} in /dev/outbox.json")


def latest_code(channel: str, to: str) -> str:
    return latest_message(channel, to, r"\b(\d{6})\b")


def step(name: str, ok: bool, detail="") -> None:
    global passed, failed
    passed += ok
    failed += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""), flush=True)


def logout(page: Page) -> None:
    post("/logout", {}, csrf_from=page)


def main() -> int:
    print(f"Smoke test against {BASE}\n")
    try:
        health = json.loads(get("/healthz").body)
        step("server reachable", health.get("status") == "ok", health.get("platform", ""))
    except Exception as exc:  # noqa: BLE001
        step("server reachable", False, str(exc))
        return 1
    env = get("/dev/env.json")
    if env.status != 200:
        step("dev tools enabled (ENABLE_DEV_TOOLS=true)", False, "needed to read codes")
        return 1
    feats = json.loads(env.body)["features"]
    step("dev tools enabled", True, f"{feats['secret_encryption']}; rate limiting {feats['rate_limiting']}; captcha={feats['captcha_provider']}")

    uid = secrets.token_hex(3)
    username, email, phone = f"smoke_{uid}", f"smoke_{uid}@example.com", f"+1555010{secrets.randbelow(10**4):04d}"

    # ---- register + plain login
    p = get("/register")
    p = post("/register", {"username": username, "email": email, "password": PASSWORD, "role": "both"}, csrf_from=p)
    step("register", any("Registration successful" in a for a in p.alerts), p.alerts[:1])
    p = post("/login", {"username": username, "password": PASSWORD}, csrf_from=get("/login"))
    step("login without 2FA lands on dashboard", p.url.endswith("/dashboard"))

    # ---- authenticator app
    p = get("/settings/security/totp/setup")
    key = re.search(r'class="manual-key[^>]*>([^<]+)<', p.body).group(1).replace(" ", "")
    step("TOTP setup page shows manual key" + (" + QR" if "data:image/svg+xml" in p.body else " (no QR)"), bool(key))
    p = post("/settings/security/totp/setup", {"code": totp.totp(key), "current_password": PASSWORD}, csrf_from=p)
    recovery = re.findall(r"[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", p.body)
    step("TOTP enabled, 10 recovery codes shown", len(recovery) == 10)
    fresh_totp(key, after_setup=True)

    # ---- e-mail + sms
    p = get("/settings/security/email/setup")
    p = post("/settings/security/email/setup", {"action": "send"}, csrf_from=p)
    p = post("/settings/security/email/setup", {"action": "verify", "code": latest_code("email", email), "current_password": PASSWORD}, csrf_from=p)
    step("e-mail 2FA enabled", any("enabled" in a for a in p.alerts), p.alerts[:1])
    p = get("/settings/security/sms/setup")
    p = post("/settings/security/sms/setup", {"action": "send", "phone": phone}, csrf_from=p)
    p = post("/settings/security/sms/setup", {"action": "verify", "code": latest_code("sms", phone), "current_password": PASSWORD}, csrf_from=p)
    step("SMS 2FA enabled", any("enabled" in a for a in p.alerts), p.alerts[:1])
    p = get("/settings/security")
    step("security page shows all three methods on", p.body.count('badge bg-success">On') == 3)
    logout(p)

    # ---- login requires second factor; wrong code rejected; TOTP accepted
    p = post("/login", {"username": username, "password": PASSWORD}, csrf_from=get("/login"))
    step("password alone redirects to /2fa/verify", p.url.endswith("/2fa/verify"))
    step("dashboard blocked before second factor", get("/dashboard").url.endswith("/login") or "login" in get("/dashboard").url)
    p = get("/2fa/verify?method=totp")
    p = post("/2fa/verify", {"method": "totp", "code": "000000"}, csrf_from=p)
    step("wrong TOTP code rejected", any("Incorrect code" in a for a in p.alerts))
    p = post("/2fa/verify", {"method": "totp", "code": fresh_totp(key)}, csrf_from=p)
    step("correct TOTP code logs in", p.url.endswith("/dashboard"))
    logout(p)

    # ---- e-mail code login
    p = post("/login", {"username": username, "password": PASSWORD}, csrf_from=get("/login"))
    p = get("/2fa/verify?method=email")
    p = post("/2fa/verify", {"method": "email", "action": "send"}, csrf_from=p)
    p = post("/2fa/verify", {"method": "email", "code": latest_code("email", email)}, csrf_from=p)
    step("e-mail code logs in", p.url.endswith("/dashboard"))
    logout(p)

    # ---- SMS code login with "remember this device"
    p = post("/login", {"username": username, "password": PASSWORD}, csrf_from=get("/login"))
    p = get("/2fa/verify?method=sms")
    p = post("/2fa/verify", {"method": "sms", "action": "send"}, csrf_from=p)
    p = post("/2fa/verify", {"method": "sms", "code": latest_code("sms", phone), "remember_device": "on"}, csrf_from=p)
    step("SMS code logs in", p.url.endswith("/dashboard"))
    step("trusted-device cookie set", any(c.name == "su_trusted_device" for c in jar))
    logout(p)
    p = post("/login", {"username": username, "password": PASSWORD}, csrf_from=get("/login"))
    step("trusted device skips second factor", p.url.endswith("/dashboard"))
    p = post("/settings/security/devices/revoke", {}, csrf_from=get("/settings/security"))
    logout(p)

    # ---- recovery code
    p = post("/login", {"username": username, "password": PASSWORD}, csrf_from=get("/login"))
    step("after revoking devices, 2FA required again", p.url.endswith("/2fa/verify"))
    p = get("/2fa/verify?method=recovery")
    p = post("/2fa/verify", {"method": "recovery", "code": recovery[0]}, csrf_from=p)
    step("recovery code logs in", p.url.endswith("/dashboard"))
    logout(p)
    p = post("/login", {"username": username, "password": PASSWORD}, csrf_from=get("/login"))
    p = post("/2fa/verify", {"method": "recovery", "code": recovery[0]}, csrf_from=get("/2fa/verify?method=recovery"))
    step("used recovery code rejected", any("Incorrect code" in a for a in p.alerts))

    # ---- password reset (e-mail link + second factor)
    p = get("/password/forgot")
    p = post("/password/forgot", {"email": email}, csrf_from=p)
    step("forgot-password gives generic answer", any("If an account" in a for a in p.alerts))
    reset_token = latest_message("email", email, r"/password/reset/([A-Za-z0-9_\-]+)")
    p = get(f"/password/reset/{reset_token}")
    step("reset link with 2FA enabled asks for second factor", "/password/reset/verify" in p.url, p.url)
    p = get("/password/reset/verify?method=totp")
    step("e-mail factor not offered for reset (stronger factor exists)", "E-mail codes" not in p.body)
    p = post("/password/reset/verify", {"method": "totp", "code": fresh_totp(key)}, csrf_from=p)
    step("second factor accepted for reset", "/password/reset/new" in p.url, p.url)
    new_password = PASSWORD + "-new"
    p = post("/password/reset/new", {"new_password": new_password, "confirm_password": new_password}, csrf_from=p)
    step("password reset completed", any("has been reset" in a for a in p.alerts), p.alerts[:1])
    step("old password rejected", post("/login", {"username": username, "password": PASSWORD}, csrf_from=get("/login")).status == 401)
    # By now this IP has >= 3 failures (wrong TOTP, used recovery code, old password)
    login_page = get("/login")
    if feats["captcha_provider"] == "dummy":
        step("CAPTCHA challenge shown after repeated failures", "captcha_answer" in login_page.body)
        r = post("/login", {"username": username, "password": new_password, "captcha_answer": "wrong"}, csrf_from=login_page)
        step("wrong CAPTCHA answer rejected", r.status == 400)
        login_page = get("/login")
    p = post("/login", {"username": username, "password": new_password}, csrf_from=login_page)
    step("new password accepted (2FA still required)", p.url.endswith("/2fa/verify"))
    step("reset link is single-use", get(f"/password/reset/{reset_token}").url.endswith("/password/forgot"))

    # ---- social login (OAuth 2.0) through the fake identity provider
    if feats.get("oauth_mode") == "fake":
        def social(provider, email, first_time=True, expect_form_post=False):
            start = get(f"/oauth/{provider}/start")  # urllib follows to the consent page
            step(f"{provider}: app redirects to the (fake) provider with PKCE + state",
                 "/authorize" in start.url and "code_challenge=" in start.url and "state=" in start.url, start.url[:60])
            params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(start.url).query))
            form = {**params, "email": email, "name": "Smoke Dummy", "email_verified": "on", "decision": "allow"}
            if first_time:
                form["first_time"] = "on"
            p = post(urllib.parse.urlparse(start.url).path, form, csrf_from=start)
            if expect_form_post:
                fields = dict(re.findall(r'name="(code|state)" value="([^"]+)"', p.body))
                step("apple: provider returns a form_post page", "code" in fields and "state" in fields)
                return post("/oauth/apple/callback", fields)  # 303 -> GET callback (urllib follows)
            return p
        oauth_email = f"social_{uid}@example.com"
        p = social("google", oauth_email)
        step("google: new user created and logged in", p.url.endswith("/dashboard"), p.alerts[:1])
        logout(p)
        p = social("apple", f"apple_{uid}@privaterelay.appleid.example", expect_form_post=True)
        step("apple: id_token accepted, user logged in", p.url.endswith("/dashboard"), p.alerts[:1])
        logout(p)
        # e-mail collision with the password account created earlier: must NOT auto-link
        p = social("facebook", email, first_time=False)
        step("facebook: existing e-mail is not auto-linked (login required)", p.url.endswith("/login") and any("already exists" in a for a in p.alerts))
        step("still logged out after collision", get("/dashboard").url.endswith("/login") or "login" in get("/dashboard").url)
        p = get("/settings/security")

    # ---- CSRF + security headers + rate limiting
    r = post("/logout", {})
    step("POST without CSRF token rejected", r.status == 400)
    if feats["rate_limiting"].startswith("enabled"):
        statuses = [post("/password/forgot", {"email": email}, csrf_from=get("/password/forgot")).status for _ in range(8)]
        step("IP rate limit returns 429 on a flood", 429 in statuses, f"statuses={statuses}")
    with opener.open(BASE + "/login", timeout=15) as resp:
        h = resp.headers
    step("security headers present", h.get("X-Frame-Options") == "DENY" and "Content-Security-Policy" in h)

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"\nERROR: {exc}")
        sys.exit(1)
