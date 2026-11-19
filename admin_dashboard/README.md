# ServiceUber Admin Dashboard

A **separate application** for managers (Trust & Safety). Three tabs:
**🛡 Background checks** (everything about background checks), **👥 Users** (every ServiceUber
account) and **Audit log**.

* **Background-check review:** approve or reject reports the provider flagged (`consider`), and
  revoke clear reports (e.g. continuous monitoring found something).
* **Disputes:** a rejected user can dispute. The dispute triggers **another background check**
  (the *re-check*), then lands here. The manager reads the user's explanation next to the
  original report and the re-check, and **approves** (the user is let in) or **rejects** (the
  decision stands; the user is told the reason).
* **Users:** every ServiceUber account, filterable by role, status, user name and age range, with
  a detail page per user.
* **Its own operators and audit log:**
  * `manager` can decide; `viewer` can only read.
  * Every sign-in and decision is logged here. The ServiceUber app also records who decided.

It shares **no code and no database** with ServiceUber. Everything goes through ServiceUber's
**Admin API** (`/admin-api/v1`), authenticated with a bearer token. You can develop, test,
deploy, scale and operate it on its own: its own requirements, `.env`, SQLite DB, session cookie,
port, launchers, tests and WSGI entry point.

```
 browser (manager) ──► admin dashboard :5001 ──HTTPS + Bearer token──► ServiceUber :5000 /admin-api/v1
                        own DB: operators, audit                        users, background checks, disputes
```

> **DUMMY values only.** Every secret, token, username and password below is fake and contains
> `dummy`. Production refuses them.

## Quick start

Requirements: Python 3.10+. Start **ServiceUber first** (`python app.py` in the project root, or its
`run.*` launcher). Then, in this folder:

```bash
./run.sh              # Linux / macOS  -> http://127.0.0.1:5001
run.bat               # Windows cmd
.\run.ps1             # Windows PowerShell
./run.sh --test       # tests only (run.bat --test / .\run.ps1 -Test)
```

The launchers create `admin_dashboard/.venv`, install `requirements.txt`, copy `.env.example` to
`.env` and start `python app.py`. Manual equivalent:

```bash
cd admin_dashboard
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # Windows: copy .env.example .env
python app.py                                          # http://127.0.0.1:5001
python -m pytest                                       # 86 tests, no ServiceUber needed
```

### Demo operators (DUMMY, seeded in development when there are no users yet)

| Username | Password | Role |
|---|---|---|
| `dummy_manager` | `dummyManagerPass123` | manager: approves / rejects reports and disputes |
| `dummy_viewer` | `dummyViewerPass123` | viewer: read-only |

## Using it

`/` opens the **🛡 Background checks** tab. The dashboard shows an error page with a hint if
ServiceUber is not reachable or the token is wrong.

### 🛡 Background checks tab (`/background-checks`)

Everything about background checks, in three sub-tabs. The sub-tab badges show the work waiting
and update live.

* **Overview** (`/background-checks`): queue sizes — reports to review, disputes to decide,
  re-checks running, reports pending at the provider — and all reports by status.
* **Reports** (`/background-checks/reports`):
  * Filters: *Needs review* (default), pending, clear, rejected, …; search by username, e-mail,
    last name or reference.
  * A report page shows the screens, the masked licence (`••••1234`) and the user's history.
    Managers get **Approve / Reject** with a note. A rejection needs a note, and the user sees it.
  * Dates of birth and full licence numbers are never sent to the dashboard.
* **Disputes** (`/background-checks/disputes`):
  * *To decide* (default), *Re-check running*, approved, rejected.
  * The dispute page shows the user's explanation, the **original (rejected) report** and the
    **re-check** side by side.
  * You can decide once the re-check is back. **Approve** lets the user in. **Reject** makes the
    rejection final, unless ServiceUber allows more disputes (`BACKGROUND_CHECK_MAX_DISPUTES`).

The old URLs `/reviews[/<id>]` and `/disputes[/<id>]` redirect to these pages.

### 👥 Users tab (`/users`)

Every ServiceUber account (managers and viewers can both see it). Filters, which can be combined
and are kept in the URL, so a filtered list can be bookmarked or shared:

| Filter | Values |
|---|---|
| **User name** | part of the username, the display name or the e-mail (case-insensitive) |
| **Role** | buyer (rider), seller (driver / service provider), both |
| **Status** | the account's background-check standing: *Active (check passed)*, *No check yet*, *Check pending*, *Unverified*, *Needs review*, *Rejected*, *Disputed*, *Check expired*. Only active users may use ServiceUber. |
| **Age from / to** | whole years, inclusive (0-150) |
| **Sort** | newest / oldest first, username, age ↑ / ↓ |

* Columns: username and display name, e-mail (and whether it is verified), role, age, status (and
  *locked* after too many failed sign-ins), driving (vehicle, online, whether the driver check is
  valid), sign-in methods and 2FA, joined, last login.
* **Age** is computed by ServiceUber from the date of birth in the user's **accepted** background
  check. A dispute re-check counts once the manager approved it. The dashboard receives the age
  in years only, never the date of birth. Users without a background check have no age and are
  left out when an age range is set.
* A user's page (`/users/<id>`) shows the profile, driving (rating, acceptance rate), activity
  (rides as rider / driver, number of payment methods — no payment details), and all their
  background-check reports and disputes, linked to the Background checks tab.
* Live: new sign-ups and status changes appear without a refresh, and the filters stay as they are.

#### 💳 Financial transactions (on the user's page, `/users/<id>#transactions`)

The user's **financial transaction report**: one list, newest first, of everything money-related.

| Type | What it is |
|---|---|
| **Buy** | the user paid: ride payments by card / wallet, completed rides paid in cash, service bookings they made |
| **Sell** | the user earned: completed rides they drove, bookings of services they sell |
| **Refund** | money returned to the user (issued by a manager, see below) |
| **Hold** | pre-authorisation placed when a ride is ordered — money reserved, not charged (captured or released later) |
| **Verification** | the small hold placed and voided to validate a new payment method |

* **Filters** (combinable, kept in the URL, also applied to the CSV):
  * **date range**: from / to, inclusive, UTC;
  * **payment method**: each of the user's cards / wallets (removed ones too), *Cash*,
    *Card / wallet of the other party* (sales paid electronically by the buyer), or
    *Service booking payment*;
  * **type**: buy / sell / refund / hold / verification.
* **Totals** for the filtered list:
  * transactions count;
  * money out (paid), money in (earned + refunds) and net;
  * open holds.

  Only settled money counts: successful payments and refunds, completed cash rides, paid or cash
  rides driven, completed bookings.
* Each row shows the other party, payment method, status, signed amount and the provider
  reference. No token ids, card numbers or the other party's payment details ever appear.
* **⬇ CSV** downloads the filtered report. Text that could run as a spreadsheet formula is
  neutralised. Each export is recorded in the audit log.
* **Refunds** (managers only):
  * The **Refund** button appears on successful payments with money left to refund. Enter an
    amount (full or partial, at most what is left) and a reason; the user sees the reason.
  * The money goes back to the method it was charged to, and the user is e-mailed.
  * The refund appears as a *Refund* row linked to the payment, and on the user's own Account page.
  * It is recorded in both audit logs.
  * The driver's earning is not reduced: the platform bears the refund.
* Live: a payment, refund, completed ride or booking for this user updates the report without a
  refresh (a notice says so), and your filters stay as they are.

### Audit log (`/audit`)

Sign-ins, lockouts, decisions (ok / error / denied) with IP.

### Live updates (no refresh needed)

Every page updates by itself. A new report appears in the queue, a re-check result turns a dispute
into *To decide*, and a decision by **another manager** updates your page. A notice tells you what
happened (your own decisions are not announced back to you). The badge in the navbar shows
**● live** while connected, **○ offline** while reconnecting.

```
ServiceUber ── GET /admin-api/v1/events (SSE, bearer token) ──► relay thread (this server, one per process)
                                                                      │ local broker
browser ◄────────────── GET /events (SSE, operator session) ──────────┘  static/live.js re-renders [data-live] regions
```

* The token stays on the server. Browsers only talk to the dashboard.
* The relay starts with the first open page, reconnects with backoff when ServiceUber restarts,
  and tells browsers to **resync** after a reconnect, so nothing missed is lost.
* Regions are re-rendered in place from a fresh copy of the page. The **decision form** is only
  replaced when the item's state changes, so a note you are typing survives unrelated updates.
  If another manager decides first, the form is replaced by their decision and you are told your
  note could not be submitted.
* `ADMIN_LIVE_UPDATES=false` switches it off (pages still work; refresh by hand).

### The dispute flow end to end

1. On ServiceUber, a user's report is flagged; a manager **rejects** it here with a reason.
2. The user sees the reason on `/background-check` (and gets an e-mail) and **raises a dispute**.
   They give an explanation and can correct their details.
3. ServiceUber runs a **new background check**. It is *held for review*: even a clear result does
   not let the user in by itself.
   * If the provider takes time, the dispute shows *Re-check running*. In development, finish it on
     ServiceUber's fake provider console: `http://127.0.0.1:5000/dev/background-provider`.
4. The dispute appears under **Disputes → To decide**. The manager approves or rejects.
5. ServiceUber applies the decision immediately and e-mails the user.

## Managing operators

```bash
python manage.py list-users
python manage.py create-user alice --role manager --name "Alice Example"   # asks for the password (12+ chars)
python manage.py set-password alice        # also signs out alice's open sessions
python manage.py set-role alice viewer
python manage.py disable-user alice        # enable-user to undo
```

## Configuration (`.env`)

| Variable | Default | Meaning |
|---|---|---|
| `ADMIN_ENV` | `development` | `production` refuses DUMMY values, plain-http API URL and demo seeding |
| `ADMIN_HOST`, `ADMIN_PORT` | `127.0.0.1`, `5001` | dev server |
| `ADMIN_SECRET_KEY` | DUMMY | signs the `uber_admin_session` cookie |
| `ADMIN_DATABASE_URL` | `sqlite:///uber_admin.db` | the dashboard's own DB (in `admin_dashboard/instance/`) |
| `MAIN_APP_API_URL` | `http://127.0.0.1:5000/admin-api/v1` | ServiceUber's Admin API (`https://` in production) |
| `MAIN_APP_API_TOKEN` | `DUMMY_ADMIN_API_TOKEN` | must equal `ADMIN_API_TOKEN` in ServiceUber's `.env` |
| `MAIN_APP_API_TIMEOUT` | `10` | seconds |
| `ADMIN_SESSION_COOKIE_SECURE`, `ADMIN_SESSION_LIFETIME_SECONDS` | `false`, `28800` | session cookie (secure is forced in production) |
| `ADMIN_LOGIN_MAX_FAILED`, `ADMIN_LOCKOUT_SECONDS` | `5`, `900` | brute-force lockout |
| `ADMIN_PASSWORD_MIN_LENGTH` | `12` | for `manage.py` |
| `ADMIN_SEED_DEMO_USERS` | `true` | seed the DUMMY operators (off in production) |
| `ADMIN_LIVE_UPDATES` | `true` | relay ServiceUber's event stream to the browsers (pages update without a refresh) |

## Deploying on its own

```bash
gunicorn -k gthread -w 2 --threads 16 -b 0.0.0.0:8001 wsgi:app   # Linux / macOS
waitress-serve --threads=16 --listen=0.0.0.0:8001 wsgi:app       # Windows
```

Live updates hold one long-lived connection per open page. Use a **threaded** server as above; with
nginx, set `proxy_buffering off` for `/events`. Several workers or instances are fine: each runs
its own relay and receives every event.

Checklist:
* Put it behind HTTPS, ideally reachable only from the office network or a VPN.
* Set `ADMIN_ENV=production` with a real `ADMIN_SECRET_KEY`, and `MAIN_APP_API_URL=https://…`.
* Create a strong random token. Set it as ServiceUber's `ADMIN_API_TOKEN` and as this app's
  `MAIN_APP_API_TOKEN`.
* Create operators with `manage.py` (no demo users in production).
* Use PostgreSQL via `ADMIN_DATABASE_URL` if you run several instances.
* Liveness: `GET /healthz`. Dependency check: `GET /healthz?deep=1` also calls ServiceUber's Admin API.

Recommended next steps: SSO / MFA for operators, an IP allow-list on ServiceUber's `/admin-api`,
and token rotation (accept two tokens during a change-over).

## Layout

```
app.py, wsgi.py, manage.py      dev server, WSGI entry point, operator CLI
uber_admin/__init__.py          create_app(): config, DB, CSRF, security headers, error pages, demo seed
uber_admin/config.py            settings from admin_dashboard/.env (DUMMY defaults, production guard)
uber_admin/client.py            Admin API client (stdlib urllib): the only link to ServiceUber
uber_admin/auth.py              sign-in, lockout, session stamp, manager/viewer roles, audit helper
uber_admin/views.py             Background checks tab (overview, reports, disputes), Users tab, audit, events (SSE), healthz
uber_admin/live.py              live updates: relay of ServiceUber's event stream + browser stream
uber_admin/static/live.js       re-renders the live regions of the page, notices, ● live badge
uber_admin/models.py            AdminUser, AuditEntry (the dashboard's own tables)
uber_admin/templates, static    Bootstrap (vendored), no inline JS/CSS (strict CSP)
tests/                          86 tests with a fake Admin API + the real client / relay against stub servers
```
