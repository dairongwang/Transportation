# ServiceUber — ride hailing + service marketplace (demo)

A Flask demo of an Uber-like app: riders request rides, nearby drivers are ranked and asked,
and — **as soon as the rider places the order — rider and driver get a private, real-time
chat room** to agree on exactly where to meet. Around that: a small services marketplace,
two-factor authentication, social login, card-on-file payments with pre-authorisation,
mandatory background checks, and a separate admin dashboard for managers.

> **Everything external is fake and offline.** Every secret, token, key, username and password
> is a `DUMMY` placeholder. Payments, SMS, e-mail, OAuth (Google / Apple / Facebook), maps and
> background checks are stubs that never leave your machine. No real card numbers or phone
> numbers are needed anywhere — the only card number you will ever type is the public test
> card `4242 4242 4242 4242`. `APP_ENV=production` refuses to start with any `DUMMY` value.

---

## Quick start

Requirements: **Python 3.10+** (tested on 3.12). No database server, no Node, no internet after
`pip install`.

```bash
./run.sh              # Linux / macOS   -> http://127.0.0.1:5000
run.bat               # Windows cmd
.\run.ps1             # Windows PowerShell
```

The launchers create `.venv`, install `requirements.txt`, copy `.env.example` to `.env` (DUMMY
values that work as-is), run the environment doctor and start the app. Options:

| Linux / macOS | Windows cmd | PowerShell | What |
|---|---|---|---|
| `./run.sh --check` | `run.bat --check` | `.\run.ps1 -Check` | environment doctor only |
| `./run.sh --test` | `run.bat --test` | `.\run.ps1 -Test` | test suite only |
| `./run.sh --lan` | `run.bat --lan` | `.\run.ps1 -Lan` | also reachable from phones / tablets on your Wi-Fi |
| `./run.sh --lan-https` | `run.bat --lan-https` | `.\run.ps1 -LanHttps` | same over HTTPS (self-signed) so phones can share GPS |

Manual equivalent:

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # Windows: copy .env.example .env
python scripts/check_env.py                            # optional: environment doctor
python app.py                                          # http://127.0.0.1:5000
```

On first start the SQLite database (`instance/uber_services.db`) is created/upgraded and DUMMY
demo data is seeded.

### Demo accounts (DUMMY, seeded in development)

| Username | Password | What it can do |
|---|---|---|
| `dummy_buyer` | `dummyBuyerPass123` | **rider** (role `buyer`) — has a DUMMY test Visa (`•••• 4242`) on file |
| `dummy_seller` | `dummySellerPass123` | role `seller` — receives bookings for the 3 demo services |
| `dummy_driver_1` … `dummy_driver_8` | `dummyDriverPass123` | **drivers** (role `seller`, "driver bots") online around the demo city |

**Roles** (chosen at registration) decide which tabs and dashboard sections you see; the pages
also refuse the role if opened directly:

| | `buyer` | `seller` | `both` |
|---|---|---|---|
| **Ride** tab, *My Recent Rides* — request rides | ✓ | – | ✓ |
| **Drive** tab, *Incoming Booking Requests (as Seller)* — drive, receive bookings | – | ✓ | ✓ |
| **Post Service** tab, *My Posted Services* — post services | – | – | ✓ |

All demo accounts have a passed (DUMMY) background check. Accounts you register yourself go
through the fake background-check provider first (see [Test data](#test-data)).

---

## Rider ↔ driver chat

**When:** the chat room opens the moment the rider presses **Order** (or, with auto-dispatch,
the moment a driver is asked). The driver sees it while still deciding whether to accept, so
the two can sort out the pickup right away: *"I'm by the newsstand at exit B"*, *"Grey Prius,
3 minutes"*. It stays open while the driver is on the way and during the ride.

**Where:** on the ride page (`/rides/<id>`, panel *💬 Chat with …*). Drivers also find a
*💬 Chat* link next to each incoming request and on their current ride. If a message arrives
while you are on another page (dashboard, drive page, …) you get a notice with an
*Open chat* link, and unread badges count up.

**What you can send:**
* text messages (up to 500 characters; Enter sends, Shift+Enter = new line)
* one-tap **quick replies** — riders: *"I'm at the pickup point."*, *"Where exactly are you?"*, …;
  drivers: *"I'm on my way."*, *"I've arrived at the pickup point."*, …
* **📍 Share my location** — your current GPS position, shown with the nearest landmark and a
  `geo:` link that opens the maps app on phones (browsers only allow GPS on `https://` or
  `localhost`: use `--lan-https` for phones)

Automatic notes in the timeline: *order placed* (with the vehicle and plate), *driver accepted*,
*ride started*, *chat closed*.

**When it closes:** the driver declines or does not answer in time, the driver hands the ride
back, the rider cancels, no driver is available, or the ride is completed. A closed chat stays
readable for both but takes no new messages.

**Privacy:**
* only the rider and that one driver can read or write the room;
* if dispatch moves on to another driver, that driver gets a **new, empty room** — drivers
  never see what the rider wrote to a previous driver (and vice versa);
* messages are pushed only to the two participants' own event streams — never on the ride's
  channel, which other drivers that were offered the ride may be watching;
* nobody needs to share a phone number.

**Real time, no polling:** messages are delivered over Server-Sent Events on the stream every
logged-in page already has open (`GET /events/account`), published only after the database
commit. Sending uses `fetch`; without JavaScript the chat still works through plain form posts.
Drafts survive the page refresh that happens when the ride status changes, and a page that was
offline fetches what it missed on reconnect.

### Try it

**Solo (with the driver bots):** log in as `dummy_buyer` → **🚕 Ride** → pickup `Downtown`,
drop-off `Airport`, tick *auto-dispatch* → **Request**. The chat opens with the bot being asked.
Type *"Which car are you?"* — the bot answers (bots reply only when nobody is logged in as
them). Press **Let the driver answer**: the bot accepts and says hello.

**Two people (two browsers or a private window):**
1. Window A: log in as `dummy_buyer`, request a ride **without** auto-dispatch, **Select**
   `dummy_driver_2` in the ranked list, press **Order**.
2. Window B: log in as `dummy_driver_2` → dashboard. The request shows up live with a
   *💬 Chat* link. Write in window A — window B shows a notice within a fraction of a second.
3. Chat back and forth, accept, start and complete the ride from window B; the chat closes in
   both windows.

### Chat API (JSON, session cookie; POSTs need the `X-CSRF-Token` header)

| Method | Path | Body / query | Result |
|---|---|---|---|
| `GET` | `/api/rides/<id>/chat` | `?after=<message id>` | your room on this ride + messages (`chat: null` before the order) |
| `POST` | `/api/rides/<id>/chat` | `{"body": "..."}` or `{"lat": .., "lng": .., "body": "caption"}` | `201` + the message · `400` invalid · `404` not open yet · `409` closed · `429` too fast |
| `POST` | `/api/rides/<id>/chat/read` | `{"last_id": <id>}` (omit = all) | moves your read marker |
| `POST` | `/rides/<id>/chat` | form `body` (or `lat`/`lng`) | same as above for plain HTML forms |
| `GET` | `/events/account` | — | SSE stream; chat messages arrive as `event: chat` |

A pushed `chat` event looks like
`{"event": "chat", "ride_id": 3, "chat_id": 1, "open": true, "role": "driver", "message": {"id": 7, "kind": "text", "body": "...", "sender": "dummy_buyer", "sender_role": "rider", "mine": false, "created_at": "...Z", "location": null}}`.

Settings (`.env`): `RIDE_CHAT_MAX_LENGTH` (500), `RIDE_CHAT_HISTORY_LIMIT` (200),
`RIDE_CHAT_RATE_LIMIT` (`20 per minute` per user), `RIDE_CHAT_BOT_REPLIES` (dev tools only).

Code: `rides/chat.py` (rules, lifecycle, push), `rides/chat_routes.py` (routes),
`rides/matching.py` (opens/closes rooms on every ride state change), `templates/rides/_chat.html`,
`static/chat.js`, models `RideChat` + `ChatMessage` in `models.py`, tests in `tests/test_ride_chat.py`.

---

## Features at a glance

* **Ride hailing** (`rides/`): offline geocoder/router for a demo city; the nearest 40 online
  drivers (`RIDE_CANDIDATE_POOL`) within `RIDE_SEARCH_RADIUS_KM` are ranked by distance, rating,
  price and acceptance rate; the rider
  selects a driver and presses **Order** (or uses auto-dispatch, which cascades on decline /
  timeout); live updates over SSE; drivers share GPS or pick a landmark.
* **Payments** (`payments/`): cards are tokenised in the browser by a fake vault — the server
  never sees a card number; Stripe / PayPal connect flows are simulated; ordering places a
  pre-authorisation of the quote + 50 % that is captured for the real fare on completion.
* **Background checks** (`background/`): required before anyone can ride, drive, book or post;
  fake provider with signed webhooks; disputes go to managers in the admin dashboard.
* **Auth** (`auth/`): password + optional 2FA (authenticator app, e-mail or SMS codes, recovery
  codes, trusted devices), account lockout, IP rate limiting, CAPTCHA after failures, password
  reset, social login via a fake OAuth provider.
* **Marketplace**: post, search and book services.
* **Admin dashboard** (`admin_dashboard/`): a separate app (port 5001) for managers — see
  [admin_dashboard/README.md](admin_dashboard/README.md). Start ServiceUber first, then
  `cd admin_dashboard && ./run.sh` (demo operator `dummy_manager` / `dummyManagerPass123`).

---

## Test data

Everything below is public test data for the fake providers — nothing here is real.

**Card:** use the public fake test card `4242 4242 4242 4242` with any future expiry and any
3-digit CVC — it is the only card number you need. (The fake vault also knows a few other public
test numbers that simulate declines; they are listed in `payments/cards.py` if you want to test
failure paths.)

**Background checks** (fake provider — decided by the legal **last name**):

| Last name contains | Result |
|---|---|
| anything else | `clear` — passed |
| `consider` | needs a manager's review (admin dashboard) |
| `pending` | stays pending — finish it at **🧪 Provider (dev)** |
| `unverified` | identity not verified — resubmit |

A driving-licence number (any DUMMY value, e.g. `DUMMY-DL-1234`) adds the driver package;
riders need 18+, drivers 21+.

**Codes** sent by e-mail / SMS (2FA, verification, password reset) are not really sent: they are
printed in the terminal and shown in the fake inbox at **📬 Inbox (dev)** (`/dev/outbox`).
SMS 2FA asks for a phone number — use a fictional one such as `+1 555 010 0199`
(555-01xx numbers are reserved for fiction).

---

## Configuration

All settings live in `.env` (template: [`.env.example`](.env.example), fully commented). The
defaults are safe for local development. The most relevant:

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY`, `MFA_ENCRYPTION_KEY` | `DUMMY_…` | **required**; session signing / encryption at rest |
| `DATABASE_URL` | `sqlite:///uber_services.db` | any SQLAlchemy URL (SQLite file lives in `instance/`) |
| `HOST`, `PORT`, `HTTPS` | `127.0.0.1`, `5000`, off | `HOST=0.0.0.0` for the LAN, `HTTPS=1` self-signed |
| `ENABLE_DEV_TOOLS`, `SEED_DEMO_DATA` | `true` | fake inbox, simulators, demo accounts (forced off in production) |
| `PAYMENTS_MODE`, `OAUTH_MODE`, `BACKGROUND_CHECK_PROVIDER` | `fake` | offline stubs |
| `EMAIL_BACKEND`, `SMS_BACKEND` | `console` | `console` / `memory` / `smtp` / `twilio` |
| `CAPTCHA_PROVIDER` | `dummy` | `none`, `dummy`, `turnstile`, `hcaptcha`, `recaptcha` |
| `RIDE_OFFER_TTL_SECONDS` | `120` | how long a driver has to answer |
| `RIDE_CHAT_*` | see above | chat limits |
| `ADMIN_API_TOKEN` | `DUMMY_ADMIN_API_TOKEN` | must equal `MAIN_APP_API_TOKEN` in `admin_dashboard/.env` |

**Generate real keys** (for anything beyond local testing):

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"                                          # SECRET_KEY
python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())" # MFA_ENCRYPTION_KEY
```

Rotate `MFA_ENCRYPTION_KEY` with `MFA_ENCRYPTION_KEY_PREVIOUS` + `python scripts/rotate_keys.py`.

**Production** (`APP_ENV=production`) refuses to start while any secret is `DUMMY`, a fake
provider is active, dev tools are on or `APP_BASE_URL` is not `https://`. Real payment /
background-check / maps integrations are not part of this demo.

### Running under load (several worker processes)

Measured in [loadtest/REPORT.md](loadtest/REPORT.md) (2000-user login burst + 300 simultaneous
ride requests). What to do, and why:

* **One single-threaded API worker per core, leaving a core free.** The request path is
  CPU-bound Python: threads in the same process only contend for the GIL. On 4 vCPU:
  `-w 3 -k sync`. (gunicorn turns `sync` into `gthread` if you pass `--threads` > 1.)
* **`EVENT_BUS=unix` as soon as there is more than one process.** Live updates (ride status,
  chat, background checks) are fanned out between the processes of the host (`rides/bus.py`).
  Without it, a rider and a driver served by different workers miss each other's updates.
* **Serve the live-update streams (`/events/...`) from a separate server.** An open stream holds
  a worker or thread for its whole lifetime; a `sync` API worker would be blocked by it. Both
  servers share the events through the bus:

  ```bash
  export APP_ENV=production EVENT_BUS=unix BEHIND_PROXY=1     # + your real secrets
  gunicorn -w 3 -k sync -b 127.0.0.1:8000 wsgi:app                     # API + pages
  gunicorn -w 1 -k gthread --threads 200 -b 127.0.0.1:8001 wsgi:app    # /events/* (SSE)
  # reverse proxy (HTTPS): /events/ -> :8001 with buffering off, everything else -> :8000
  ```
* **SQLite** (the default) is tuned for this (`dbtuning.py`): WAL, a 15 s busy timeout, and a
  writer queue that hands the single write lock over within about a millisecond. Every ride
  request still writes under one database-wide lock, so beyond a few dozen ride requests per
  second **use PostgreSQL** (`DATABASE_URL`). Several hosts also need Redis, for rate limits
  (`RATELIMIT_STORAGE_URI`) and in place of the single-host event bus.
* Windows: `waitress-serve --listen=0.0.0.0:8000 wsgi:app` with one process (no `EVENT_BUS`).

Related settings: `RIDE_DRIVER_INDEX_TTL_SECONDS` (the matcher's in-memory driver index),
`RIDE_CANDIDATE_POOL` (score only the nearest N drivers; default 40, 0 = all), `SQLITE_WAL`,
`SQLITE_BUSY_TIMEOUT_MS`, `SQLITE_WRITE_LOCK` (and `SQLITE_WRITE_LOCK_STATS=1` for lock timings).

---

## Phones and tablets

`./run.sh --lan-https` (or `HOST=0.0.0.0 HTTPS=1 python app.py`) serves the app on your LAN with
a self-signed certificate; the log prints the URLs and `/dev/env` shows QR codes to open them.
Accept the certificate warning on the phone. HTTPS is what lets the browser share GPS — for the
driver's position and for **📍 Share my location** in the chat.

---

## Tests

```bash
python -m pytest                  # or ./run.sh --test   (in-memory SQLite, no network, ~1 min)
python scripts/smoke_test.py      # live end-to-end check against a RUNNING app (python app.py)
```

* `tests/test_ride_chat.py` — the chat: opens on order, live push to participants only, a fresh
  room per driver, validation, escaping, every closing path, unread markers, bots, rate limit,
  background-check gate, schema upgrade of an existing database.
* `tests/test_app_smoke.py` — pages, auth, marketplace, ride dispatch / payment regression,
  production guard, and that `.env.example` documents every setting with DUMMY secrets only.
* On Windows, 6 tests are **skipped**: the SQLite writer queue needs `fcntl`, and the cross-process
  event bus needs Unix datagram sockets, neither of which exists there. The app falls back
  automatically, to SQLite's own locking and to in-process events; the other tests cover that.
  They are skipped by capability, so the skip list is the same whatever the OS.
* `tests/test_load_optimisations.py` — every fast path gives exactly the answer of the code it
  replaced (background-check rules in every state, driver index against a brute-force scan,
  offer expiry). Also: the SQLite writer queue never leaks its lock under 20 concurrent writers,
  and the event bus delivers across processes.
* `scripts/smoke_test.py` — registers a fresh DUMMY account, passes the background check, orders
  a ride, chats with the driver bot (checks the live SSE push), completes the ride, verifies the
  chat closed.

Environment doctor: `python scripts/check_env.py` (or `/dev/env` in the browser).

**Load tests** (`loadtest/`, extra requirements in `loadtest/requirements.txt`):
`python loadtest/seed.py` (1000 riders + 1000 drivers in a separate database), then
`python loadtest/run.py --workers 3 --worker-class sync --env EVENT_BUS=unix`. It runs a login
burst of 2000 users in 60 s, then 3 × 300 simultaneous ride requests, and reports latency
percentiles, throughput, server CPU and memory, and hypervisor CPU steal. Latest result on
4 vCPU: ride request **P95 ≈ 3 s** (target < 7 s) at **71 % peak server CPU** (target < 80 %),
0 errors. The load tools (`run.py`) need Linux / macOS, because they start gunicorn.
`python loadtest/bench_request.py` measures the CPU cost of one ride request. Results and
analysis: [loadtest/REPORT.md](loadtest/REPORT.md).

Local fake servers for testing the *real* delivery code paths: `scripts/fake_smtp_server.py`
(port 2525, `EMAIL_BACKEND=smtp`), `scripts/fake_twilio_server.py` (port 8089,
`SMS_BACKEND=twilio`, `TWILIO_API_BASE=http://127.0.0.1:8089`), `scripts/fake_oauth_server.py`
(port 8090, `OAUTH_FAKE_BASE_URL=http://127.0.0.1:8090`), `scripts/fake_authenticator.py`
(prints TOTP codes for a secret).

---

## Dev tools (only with `ENABLE_DEV_TOOLS=true`)

| URL | What |
|---|---|
| `/dev/outbox` | fake inbox: e-mail / SMS codes |
| `/dev/env` | platform, dependency and configuration report (+ LAN QR codes) |
| `/dev/background-provider` | finish pending background checks (stand-in for the provider) |
| `POST /dev/rides/simulate` | driver bots: `action=respond` (answer offers), `advance` (start / complete), `shuffle` (re-position fleet) |
| `/dev/rides/fleet` | JSON snapshot of the bot fleet |
| `/healthz` | liveness probe (always on) |

---

## Project layout

```
app.py              app factory, marketplace routes, demo seeding     wsgi.py   production entry point
dbtuning.py         SQLite under concurrency: WAL, busy timeout, writer queue
config.py           settings from .env (DUMMY placeholders)           models.py SQLAlchemy models
extensions.py       db, login manager, CSRF                            migrations.py  idempotent schema upgrade
throttle.py         IP / per-user rate limiting                        devtools.py    /dev/* + /healthz
auth/               login, 2FA, OAuth, password reset, CAPTCHA
rides/              geo stub, matching + dispatch, SSE events, offer sweeper, bots,
                    chat.py + chat_routes.py (rider <-> driver chat),
                    driver_index.py (in-memory driver search), bus.py (events across worker processes)
loadtest/           seed + load generator + per-request benchmark, REPORT.md with the results
payments/           fake vault + gateway, payment methods, holds, ledger
background/         background checks, disputes, Admin API for the dashboard
templates/, static/ Jinja templates, vendored Bootstrap, page scripts (CSP: no inline JS)
scripts/            environment doctor, smoke test, fake SMTP / Twilio / OAuth servers, key rotation
tests/              pytest suite
admin_dashboard/    the separate managers' app (own README, .env, database)
```

See `SECURITY_REVIEW.md` for the security review and change log.

---

## Troubleshooting

* **`SECRET_KEY, MFA_ENCRYPTION_KEY must be set in .env`** — copy `.env.example` to `.env`
  (the launchers do this).
* **`ModuleNotFoundError` when running pytest** — pytest runs with a different interpreter than
  the one you installed into: `python -m pytest` from the activated `.venv`, or `./run.sh --test`.
* **`./run.sh: Permission denied`** — `chmod +x run.sh` or run `bash run.sh`.
* **"No drivers are available"** — the demo bots go stale after
  `DRIVER_LOCATION_STALE_SECONDS`; restart the app or `POST /dev/rides/simulate action=shuffle`
  (the *Environment check* page links the simulator).
* **Chat says "live" never / messages only appear after reload** — a proxy is buffering
  Server-Sent Events; disable buffering for `/events/` (`X-Accel-Buffering: no` is already sent).
* **"📍 Share my location" is missing** — the page is not a secure context; use `localhost` or
  start with `--lan-https`.
* **Demo accounts locked / rejected / without their test card** — `python scripts/reset_demo_accounts.py`
  makes them usable again (other accounts are untouched).
* **Start over with completely fresh data** — stop the app and delete `instance/uber_services.db`;
  it is recreated and re-seeded on the next start.
