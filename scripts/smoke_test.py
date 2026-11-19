#!/usr/bin/env python3
"""
Live end-to-end smoke test against a RUNNING ServiceUber (dev tools on, the default .env).

    python app.py                              # terminal 1 (or ./run.sh)
    python scripts/smoke_test.py               # terminal 2  -> exit 0 when everything works
    python scripts/smoke_test.py --base http://192.168.1.20:5000

Standard library only (urllib), so it runs from any machine that can reach the server.
It never depends on the demo accounts' state: every run registers a FRESH DUMMY account
(dummy_smoke_<random>, an example.com e-mail, a public dummy password, a fictional identity
with a fake driving licence number). No card numbers and no phone numbers are used.

Steps (every HTTP status is checked):
   1. /healthz and the public pages
   2. register -> log in (answers the offline dummy CAPTCHA if one is asked)
   3. background check with the fake provider (driver package) -> passed
   4. request a ride (auto-dispatch, cash) -> a demo driver bot is asked
   5. CHAT: the room is open as soon as the order is placed; send a message; the bot replies;
      share a location; a live push arrives on /events/account (Server-Sent Events)
   6. the bot accepts / picks up / completes (dev simulator) -> the chat closes, sending is refused
   7. log out
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PASSWORD = "dummySmokePass123"  # DUMMY PASSWORD (public placeholder)


class SmokeFailure(Exception):
    pass


class Client:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf: str | None = None

    def request(self, method: str, path: str, *, form: dict | None = None, js: dict | None = None,
                expect: int | tuple[int, ...] = 200) -> tuple[int, str, str]:
        headers = {"Accept": "application/json" if js is not None or path.startswith("/api/") else "text/html"}
        data = None
        if js is not None:
            data = json.dumps(js).encode()
            headers["Content-Type"] = "application/json"
        elif form is not None:
            form = dict(form)
            if self.csrf:
                form.setdefault("csrf_token", self.csrf)
            data = urllib.parse.urlencode(form).encode()
        if method == "POST" and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(req, timeout=20) as resp:
                code, body, url = resp.getcode(), resp.read().decode("utf-8", "replace"), resp.geturl()
        except urllib.error.HTTPError as exc:
            code, body, url = exc.code, exc.read().decode("utf-8", "replace"), exc.geturl()
        m = re.search(r'name="csrf_token" value="([^"]+)"', body)
        if m:
            self.csrf = m.group(1)
        ok = (expect,) if isinstance(expect, int) else expect
        if code not in ok:
            flashes = re.findall(r'role="alert">\s*([^<]+)', body)
            raise SmokeFailure(f"{method} {path} -> HTTP {code} (expected {ok}) {flashes[:2] or body[:200]}")
        return code, body, url

    def get(self, path: str, **kw):
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw):
        return self.request("POST", path, **kw)

    def json(self, method: str, path: str, payload: dict | None = None, expect=200) -> dict:
        _, body, _ = self.request(method, path, js=payload if method == "POST" else None, expect=expect)
        return json.loads(body)


def captcha_answer(html: str) -> dict:
    m = re.search(r"What is (\d+) \+ (\d+)\?", html)
    return {"captcha_answer": str(int(m.group(1)) + int(m.group(2)))} if m else {}


def run(base: str, verbose: bool = True) -> None:
    step = 0

    def ok(msg: str) -> None:
        nonlocal step
        step += 1
        if verbose:
            print(f" ✓ {step:2d}. {msg}")

    c = Client(base)
    # ---------------------------------------------------------------- 1. server up
    health = c.json("GET", "/healthz")
    if health.get("status") != "ok":
        raise SmokeFailure(f"/healthz: {health}")
    for path in ("/", "/login", "/register", "/search?q=ride"):
        c.get(path)
    ok(f"server healthy ({health.get('platform')}), public pages render")

    # ---------------------------------------------------------------- 2. register + log in
    tag = secrets.token_hex(3)
    user = f"dummy_smoke_{tag}"
    _, page, _ = c.get("/register")
    _, page, url = c.post("/register", form={"username": user, "email": f"dummy.smoke.{tag}@example.com",
                                             "password": PASSWORD, "role": "both", **captcha_answer(page)})
    if not url.rstrip("/").endswith("/login"):
        raise SmokeFailure(f"registration did not redirect to /login: {url}")
    _, page, _ = c.get("/login")
    _, page, url = c.post("/login", form={"username": user, "password": PASSWORD, **captcha_answer(page)})
    if "/background-check" not in url and "/dashboard" not in url:
        raise SmokeFailure(f"login landed on {url}")
    ok(f"registered and logged in as {user}")

    # ---------------------------------------------------------------- 3. background check
    c.get("/background-check")
    _, _, url = c.post("/background-check", form={
        # legal names are letters only: hex tag -> letters a..p
        "legal_first_name": "Dummy", "legal_last_name": "Smoke " + "".join(chr(97 + int(ch, 16)) for ch in tag).title(),
        "date_of_birth": "1990-01-01",
        "licence_number": f"DUMMY-{tag.upper()}", "licence_region": "Demo State", "consent": "on"})
    state = c.json("GET", "/api/background-check")
    if not state.get("passed"):
        raise SmokeFailure(f"background check did not pass: {state}")
    ok("background check passed (fake provider, driver package)")

    # ---------------------------------------------------------------- 4. ride + order
    # put the demo fleet online with fresh positions (they go stale after DRIVER_LOCATION_STALE_SECONDS)
    c.post("/dev/rides/simulate", form={"action": "shuffle"})
    ride = c.json("POST", "/api/rides", {"pickup": "Downtown", "dropoff": "Airport", "auto_dispatch": True,
                                         "payment_method_id": None}, expect=201)
    if ride["status"] != "offered":
        raise SmokeFailure(f"ride #{ride['id']} was not dispatched: {ride['status']}")
    rid = ride["id"]
    asked = next(o["driver"]["username"] for o in ride["offers"] if o["status"] == "pending")
    ok(f"ride #{rid} requested, order placed with {asked}")

    # ---------------------------------------------------------------- 5. chat
    chat = c.json("GET", f"/api/rides/{rid}/chat")
    if not (chat["chat"] and chat["chat"]["open"]):
        raise SmokeFailure(f"no open chat right after the order: {chat}")
    c.get(f"/rides/{rid}")  # page with the chat panel (also refreshes the CSRF token)

    pushed: list[dict] = []
    listening = threading.Event()

    def listen() -> None:  # what the browser's EventSource does
        req = urllib.request.Request(c.base + "/events/account", headers={"Accept": "text/event-stream"})
        try:
            with c.opener.open(req, timeout=15) as resp:
                event = None
                for raw in resp:
                    line = raw.decode().rstrip("\n")
                    if line.startswith("event:"):
                        event = line[6:].strip()
                        if event == "hello":
                            listening.set()
                    elif line.startswith("data:") and event == "chat":
                        pushed.append(json.loads(line[5:]))
                        if len(pushed) >= 2:
                            return
        except OSError:
            pass

    t = threading.Thread(target=listen, daemon=True)
    t.start()
    if not listening.wait(10):
        raise SmokeFailure("could not subscribe to /events/account")
    sent = c.json("POST", f"/api/rides/{rid}/chat", {"body": "Hi! Where exactly are you?"}, expect=201)
    t.join(10)
    if not any(p["message"]["id"] == sent["message"]["id"] and p["message"]["mine"] for p in pushed):
        raise SmokeFailure(f"own message was not pushed live: {pushed}")
    messages = c.json("GET", f"/api/rides/{rid}/chat")["messages"]
    reply = messages[-1]
    if reply["sender_role"] != "driver":
        raise SmokeFailure(f"the demo driver did not reply: {messages[-2:]}")
    loc = c.json("POST", f"/api/rides/{rid}/chat", {"lat": 40.0081, "lng": -74.9921, "body": "I'm here"}, expect=201)
    if not loc["message"]["location"]:
        raise SmokeFailure(f"location message without a location: {loc}")
    ok(f"chat open on order; message pushed live over SSE; {reply['sender']} replied: “{reply['body'][:50]}”")

    # ---------------------------------------------------------------- 6. ride happens -> chat closes
    for _ in range(12):  # bots accept with their acceptance rate; auto-dispatch moves on if they decline
        status = c.json("GET", f"/api/rides/{rid}")["status"]
        if status != "offered":
            break
        c.post("/dev/rides/simulate", form={"action": "respond", "ride_id": rid})
    if status == "no_drivers":
        raise SmokeFailure("every demo driver declined - run again")
    if status != "accepted":
        raise SmokeFailure(f"ride not accepted: {status}")
    c.post("/dev/rides/simulate", form={"action": "advance", "ride_id": rid})
    c.post("/dev/rides/simulate", form={"action": "advance", "ride_id": rid})
    status = c.json("GET", f"/api/rides/{rid}")["status"]
    if status != "completed":
        raise SmokeFailure(f"ride not completed: {status}")
    chat = c.json("GET", f"/api/rides/{rid}/chat")
    if chat["chat"]["open"]:
        raise SmokeFailure("chat still open after the ride completed")
    c.json("POST", f"/api/rides/{rid}/chat", {"body": "still there?"}, expect=409)
    c.post(f"/rides/{rid}/rate", form={"stars": "5"})
    ok(f"ride accepted -> started -> completed; chat closed ({chat['chat']['close_reason']}); rated 5★")

    # ---------------------------------------------------------------- 7. log out
    c.post("/logout", form={})
    _, _, url = c.get("/dashboard")
    if "/login" not in url:
        raise SmokeFailure(f"still logged in after logout: {url}")
    ok("logged out")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://127.0.0.1:5000", help="URL of the running app")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()
    started = time.time()
    try:
        run(args.base, verbose=not args.quiet)
    except SmokeFailure as exc:
        print(f"\n ✗ SMOKE TEST FAILED: {exc}")
        return 1
    except urllib.error.URLError as exc:
        print(f"\n ✗ cannot reach {args.base}: {exc.reason}. Start the app first (python app.py).")
        return 1
    print(f"\nSmoke test passed in {time.time() - started:.1f}s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
