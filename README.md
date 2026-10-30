# ServiceUber — Uber-like Service Marketplace (Python / Flask)

A simple web app for buying and selling services (rides, deliveries, cleaning, tutoring, …)
with **two-factor authentication** (authenticator app, e-mail codes, SMS codes), recovery
codes, trusted devices, **social login with Google / Apple / Facebook (OAuth 2.0)**, **password
reset that still requires the second factor**, layered brute-force protection (IP rate limits →
CAPTCHA → account lockout) and an audit log.

> **All secrets, tokens, API keys, demo passwords and demo identities in this repository are
> DUMMY placeholders** (`DUMMY_*`, `*.dummy@example.com`, `+1 555-01xx`). `.env.example` ships
> them so the app runs out of the box for development and testing; **`SECRET_KEY` and
> `MFA_ENCRYPTION_KEY` must be present in `.env`** (the app refuses to start otherwise) and
> `APP_ENV=production` refuses any `DUMMY_*` value.

Runs on **Linux, macOS (Intel & Apple Silicon) and Windows** with Python 3.10+ and is used from
**any browser — desktop, smartphone or tablet**. The dependency set is pure Python (no Pillow,
no compilers); see [Troubleshooting](#troubleshooting) for the history behind that.

---

## Contents
1. [Quick start](#1-quick-start)
2. [Configuration & dummy secrets](#2-configuration--dummy-secrets)
3. [Testing 2FA in each environment](#3-testing-2fa-in-each-environment)
4. [Fakes & stubs](#4-fakes--stubs)
5. [Validating an installation](#5-validating-an-installation)
6. [Production deployment](#6-production-deployment)
7. [Troubleshooting](#7-troubleshooting)
8. [Project layout](#8-project-layout)

---

## 1. Quick start

Requirement: **Python 3.10 or newer** (`python3 --version` / `py -3 --version`).
Everything else is installed into a local virtual environment by the launcher.

| Platform | Start | Reachable from phones/tablets on the same Wi-Fi |
|---|---|---|
| Linux / macOS | `./run.sh` | `./run.sh --lan` |
| Windows (cmd) | `run.bat` | `run.bat --lan` |
| Windows (PowerShell) | `.\run.ps1` | `.\run.ps1 -Lan` |

The launcher creates `.venv`, installs `requirements.txt`, copies `.env.example` → `.env`
(dummy secrets — **required**, see §2), runs the environment doctor and starts the server at
**http://127.0.0.1:5000**.

Demo accounts (dev only): `demo_seller / dummySellerPass123`, `demo_buyer / dummyBuyerPass123`.

<details>
<summary>Manual steps (what the launchers do)</summary>

**Linux / macOS**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python scripts/check_env.py       # optional doctor
python app.py                     # LAN access:  HOST=0.0.0.0 python app.py
```

**Windows — cmd.exe**
```bat
py -3 -m venv .venv && .venv\Scripts\activate.bat
pip install -r requirements.txt
copy .env.example .env
python scripts\check_env.py
python app.py
REM LAN access:  set HOST=0.0.0.0 && python app.py
```

**Windows — PowerShell**
```powershell
py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1     # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
Copy-Item .env.example .env
python scripts\check_env.py
python app.py                     # LAN access:  $env:HOST="0.0.0.0"; python app.py
```
</details>

---

## 2. Configuration & dummy secrets

All configuration is read from `.env` (or real environment variables). `.env.example` is the
template and documents every knob. **Two keys are mandatory** — there is no in-code fallback:

| Variable | What it protects | Effect of rotating it |
|---|---|---|
| `SECRET_KEY` | Session cookie + CSRF tokens — *nothing else* | Everyone is logged out. Nothing is invalidated. |
| `MFA_ENCRYPTION_KEY` | Authenticator secrets (encrypted) and the HMACs of one-time codes, recovery codes, remembered devices, reset tokens | Supported without loss: see *Rotating keys* below |

```bash
python -c "import secrets; print(secrets.token_hex(32))"                                   # SECRET_KEY
python -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"   # MFA_ENCRYPTION_KEY
```

Other dummies (all `DUMMY_*`, safe to leave in dev/test): `PAYMENT_GATEWAY_KEY`, `MAPS_API_KEY`,
`JWT_SECRET`, `SMTP_USERNAME/PASSWORD`, `TWILIO_ACCOUNT_SID/AUTH_TOKEN`, `CAPTCHA_SITE_KEY/SECRET_KEY`.
Demo identities are `demo.seller@example.com` / `demo.buyer@example.com` (RFC 2606 reserved domain)
and phone numbers in the fictional `+1 555-01xx` block.

**Rotating keys**
```
# .env
MFA_ENCRYPTION_KEY=<new key>
MFA_ENCRYPTION_KEY_PREVIOUS=<old key>        # comma-separate several if needed
```
```bash
python scripts/rotate_keys.py --dry-run      # what would change
python scripts/rotate_keys.py                # re-encrypts all authenticator secrets under the new key
```
Recovery codes and remembered-device tokens are one-way hashes; they keep verifying against
`MFA_ENCRYPTION_KEY_PREVIOUS` and are re-keyed on use (devices) or replaced when regenerated
(codes). Keep the previous key listed for `TRUSTED_DEVICE_DAYS` (30), then remove it.
Rotating `SECRET_KEY` needs no script.

**Brute-force protection (three layers, all configurable in `.env`)**

| Layer | Setting | Default |
|---|---|---|
| IP rate limits (Flask-Limiter) | `RATELIMIT_*`, `RATELIMIT_STORAGE_URI` | `memory://` — use `redis://…` with several workers |
| CAPTCHA after repeated failures per IP **or** account | `CAPTCHA_PROVIDER`, `CAPTCHA_AFTER_FAILURES` | `dummy` (offline stub), 3 failures / 15 min |
| Per-account lockout (last line; kept short so it can't be abused to lock victims out) | `LOGIN_MAX_FAILED_ATTEMPTS`, `LOGIN_LOCKOUT_SECONDS` | 5 → 15 min |

Real CAPTCHA providers: `turnstile` (Cloudflare), `hcaptcha`, `recaptcha` + the site/secret keys.
Behind a reverse proxy set `BEHIND_PROXY=1` so limits apply to the real client IP.

---

## 3. Testing 2FA in each environment

Log in → **Security** (navbar) → set up one or more methods. With the stub backends nothing is
really sent: **the web page tells you where to look** (a yellow *"TEST MODE: no real e-mail is
sent. Find it in…"* notice on every page that sends a code or reset link, and again in the
confirmation message). The three places are the **server console/log** (lines starting with
`[EMAIL -> …]` / `[SMS -> …]`), the file `instance/auth_outbox.jsonl`, and the fake inbox page
**http://&lt;host&gt;:5000/dev/outbox** (navbar *📬 Inbox (dev)*) — readable from any device.

### Desktop (Linux / macOS / Windows) — no phone needed
| Method | How to test |
|---|---|
| Authenticator app | On the setup page expand *Enter the key manually*, then run `python scripts/fake_authenticator.py <key>` (`--watch` keeps printing codes). Or use a desktop authenticator (1Password, Bitwarden, Authy desktop, KeePassXC) and scan the QR. |
| E-mail code | Click *Send code* → read it at `/dev/outbox`. |
| SMS code | Enter a fictional E.164 number (e.g. `+15550100001`) → read the code at `/dev/outbox`. |
| Recovery codes | Shown once when the first method is enabled; use one on the sign-in page via the *Recovery code* tab. |
| Password reset | Login → *Forgot password?* → the link appears in `/dev/outbox` → if 2FA is on you must pass it (e-mail codes are not offered when a stronger factor exists) → new password; every other session and remembered device is signed out. |
| CAPTCHA | Fail login 3× → the dummy challenge ("What is 3 + 4?") appears on login / register / forgot-password. |
| Rate limit | Submit any auth form more than the per-minute limit → HTTP 429 page. |

### Smartphone / tablet (iOS, iPadOS, Android) as the *client*
1. Start the server with LAN access: `./run.sh --lan` / `run.bat --lan` / `.\run.ps1 -Lan`.
   The console prints the address(es), e.g. `http://192.168.1.20:5000` (also on `/dev/env`).
2. Allow the port through the firewall the first time:
   * **Windows**: accept the Defender prompt, or `netsh advfirewall firewall add rule name="ServiceUber" dir=in action=allow protocol=TCP localport=5000`
   * **macOS**: accept the "allow incoming connections" prompt
   * **Linux**: `sudo ufw allow 5000/tcp` (if ufw is active)
3. Open the address in the phone's browser. The UI is responsive (Bootstrap 5); code fields use
   `inputmode="numeric"` and `autocomplete="one-time-code"`, so iOS/Android offer SMS/e-mail
   autofill when a real provider is configured.
4. Authenticator setup **on the phone itself**: the QR can't be scanned from the same screen, so tap
   **Open in authenticator app on this device** (an `otpauth://` link that Google Authenticator,
   Authy, Microsoft Authenticator, 1Password… pick up) or paste the manual key.
5. Authenticator setup **scanning from a phone** while the browser is on a laptop: just scan the QR.
6. Read e-mail/SMS codes on the phone at `http://<lan-ip>:5000/dev/outbox`.

Tip: `python scripts/smoke_test.py http://192.168.1.20:5000` from another machine validates the
whole flow across the network.

### Real providers
```
EMAIL_BACKEND=smtp   SMTP_HOST=smtp.example.com SMTP_PORT=587 SMTP_USE_TLS=true SMTP_USE_AUTH=true SMTP_USERNAME=… SMTP_PASSWORD=…
SMS_BACKEND=twilio   TWILIO_ACCOUNT_SID=… TWILIO_AUTH_TOKEN=… TWILIO_FROM_NUMBER=+1…
```

---

### Social login (OAuth 2.0: Google, Apple, Facebook)

Buttons *Continue with Google / Apple / Facebook* are on the login and register pages; *Link …*
buttons are under **Security → Connected accounts**.

**Default: `OAUTH_MODE=fake`** — the app hosts a **stub identity provider** at
`/dev/oauth/<provider>/…`. Clicking a button opens a yellow *FAKE … sign-in* consent page where
you type the e-mail/name the provider should "return", tick *verified*, and press **Allow** (or
**Deny** to test cancellation). Nothing is sent anywhere; no Google/Apple/Facebook account is
needed, and it works on phones/tablets over the LAN too. The stub enforces what the real
providers enforce — client id/secret, `redirect_uri`, single-use code, PKCE `S256`, and for
Google/Apple a signed `id_token` with `nonce` — so the **real client code** (`auth/oauth.py`) is
what gets validated.

What to try:
| Scenario | Expected |
|---|---|
| New identity | account created (no password), logged in, nudged to add 2FA |
| Same identity again | logs straight in, no duplicate |
| Identity whose e-mail matches an existing password account | **not** auto-linked — you're sent to log in with password (+2FA); the link completes afterwards |
| Account with 2FA enabled | social login still asks for the second factor |
| Security → Link / Unlink | unlink needs the password; the last social identity can't be unlinked until a password exists (*Forgot password?* sets one) |
| Apple | `form_post` callback (cross-site POST) and `id_token` are exercised; the *first authorization* checkbox simulates Apple sending the name only once |

Standalone stub (e.g. provider on another machine): `python scripts/fake_oauth_server.py 0.0.0.0 8090`
and run the app with `OAUTH_FAKE_BASE_URL=http://<ip>:8090`.

**Real providers:** set `OAUTH_MODE=real`, register the redirect URIs shown on
`/oauth/providers` (`<APP_BASE_URL>/oauth/<provider>/callback`) with each provider, and fill in
the `OAUTH_*` credentials in `.env`. Apple additionally needs the `cryptography` package (its
client secret is an ES256 JWT signed with your `.p8` key). Google and Facebook need only the
standard library.

## 4. Fakes & stubs

Everything under `scripts/` uses **only the Python standard library**, so it runs on any OS even
if `pip install` is incomplete.

| Stub | Replaces | Usage |
|---|---|---|
| `console` backend + `/dev/outbox` | E-mail & SMS providers | Default. Codes go to the log, `instance/auth_outbox.jsonl` and the fake inbox page. |
| `scripts/fake_authenticator.py` | Google Authenticator / Authy | `python scripts/fake_authenticator.py JBSW Y3DP … [--watch]` or pass the `otpauth://` URI |
| `scripts/fake_smtp_server.py` | Real SMTP server — exercises the **real** `smtp` backend | Terminal 1: `python scripts/fake_smtp_server.py` · Terminal 2: `EMAIL_BACKEND=smtp SMTP_HOST=127.0.0.1 SMTP_PORT=2525 SMTP_USE_TLS=false python app.py` |
| `scripts/fake_twilio_server.py` | Twilio REST API — exercises the **real** `twilio` backend incl. Basic auth | Terminal 1: `python scripts/fake_twilio_server.py` · Terminal 2: `SMS_BACKEND=twilio TWILIO_API_BASE=http://127.0.0.1:8089 python app.py` |
| `memory` backend | Providers, inside pytest | Selected automatically by `TestingConfig` |
| `CAPTCHA_PROVIDER=dummy` | Turnstile / hCaptcha / reCAPTCHA | Offline arithmetic challenge; `scripts/smoke_test.py` solves it like a tester would. Production refuses it. |
| `scripts/rotate_keys.py --dry-run` | — | Rehearse an `MFA_ENCRYPTION_KEY` rotation against your database |
| `OAUTH_MODE=fake` (in-app `/dev/oauth/…`) | Google / Apple / Facebook identity providers | Default. Consent page to pick the identity; enforces PKCE, state, client auth, signed `id_token`. |
| `scripts/fake_oauth_server.py` | Same, as a standalone process | `python scripts/fake_oauth_server.py` then `OAUTH_FAKE_BASE_URL=http://127.0.0.1:8090` |
| `/dev/env` · `/dev/env.json` | — | Platform, dependency, backend and storage report for the running install |
| `/healthz` | — | Liveness probe (always on) |

Messages captured by the fake SMTP/Twilio servers also appear on `/dev/outbox`.
On Windows set variables with `set NAME=value` (cmd) or `$env:NAME="value"` (PowerShell) — or put them in `.env`.

---

## 5. Validating an installation

```bash
python scripts/check_env.py         # 1. doctor: Python, deps, TOTP vectors, SQLite, encryption, app boot
python -m pytest                    # 2. 92 unit/integration tests (in-memory DB, no network, no .env needed)
python app.py                       # 3. start the server (needs .env) …
python scripts/smoke_test.py        # … and drive it end-to-end like a browser (41 steps incl. reset, CAPTCHA, 429, OAuth)
```
Launcher shortcuts: `./run.sh --check`, `./run.sh --test` (same flags for `run.bat` / `run.ps1 -Check -Test`).

What gets verified per environment:
* **TOTP** — stdlib implementation checked against RFC 6238 / RFC 4226 vectors (and pyotp if installed).
* **Secret encryption** — Fernet via `cryptography`; if that package is unavailable the stdlib
  fallback is used and reported (dev/test only).
* **QR rendering** — SVG via `qrcode`; if missing, the manual key / `otpauth://` link still work.
* **Storage** — SQLite file under `instance/`, outbox file path, write permissions.

A GitHub Actions matrix (ubuntu / macos / windows × Python 3.10–3.13) is provided in
`.github/workflows/ci.yml`.

---

## 6. Production deployment

```
APP_ENV=production  SECRET_KEY=<real>  MFA_ENCRYPTION_KEY=<real>  APP_BASE_URL=https://your.host
EMAIL_BACKEND=smtp  SMS_BACKEND=twilio  (+ credentials)
CAPTCHA_PROVIDER=turnstile|hcaptcha|recaptcha (+ keys)   RATELIMIT_STORAGE_URI=redis://...   BEHIND_PROXY=1
OAUTH_MODE=real + OAUTH_* credentials (or trim OAUTH_PROVIDERS to the ones you configured)
```
* Linux/macOS: `pip install gunicorn && gunicorn -w 2 -b 0.0.0.0:8000 wsgi:app`
* Windows: `pip install waitress && waitress-serve --listen=0.0.0.0:8000 wsgi:app`
* Always behind TLS (nginx / Caddy / IIS / a cloud load balancer). Dev tools and demo data are forced off.
* Read `SECURITY_REVIEW.md` before going live — it lists what is and isn't covered.

---

## 7. Troubleshooting

**`ModuleNotFoundError: No module named 'flask_wtf'` / `'flask_...'` when running `python -m pytest`**
The Python that runs pytest is not the one you installed the requirements into (typically the
global `python` instead of `.venv`). `tests/conftest.py` now stops with the exact interpreter path
and the command to fix it. Either activate the venv first (`.venv\Scripts\activate` /
`source .venv/bin/activate`), run `.venv\Scripts\python -m pytest`, or use `run.bat --test` /
`.\run.ps1 -Test` / `./run.sh --test`, which install into the right interpreter before testing.
(Flask-WTF itself is no longer a dependency — CSRF protection is built in.)

**`RuntimeError: SECRET_KEY, MFA_ENCRYPTION_KEY must be set in .env`**
Intentional: the app never falls back to a hidden default key. `copy .env.example .env` (Windows) /
`cp .env.example .env` — the template contains DUMMY values for development.

**`Failed building wheel for pillow` / `Pillow 10.4.0 does not support Python 3.14` (Windows)**
Old versions pinned Pillow to render the QR as PNG. Pillow is a compiled package and had no wheel
for the new Python, so pip aborted the *whole* install. Pillow is **no longer a dependency** — QR codes
are SVG. Delete `.venv` and reinstall: `pip install -r requirements.txt`.

**`ModuleNotFoundError: No module named 'pyotp'` when running pytest**
Consequence of the failed install above (pip stopped before reaching the remaining packages).
`pyotp` is no longer required either — TOTP is implemented in `auth/totp.py`. Reinstall and run
`python scripts/check_env.py`; it tells you exactly what is missing.

**`cryptography` fails to install** — rare (it ships abi3 wheels for all platforms), but the app still
runs: secrets are protected with a stdlib fallback and `/dev/env` reports `stdlib HMAC-CTR fallback`.
Install a newer `cryptography` when a wheel is available; ciphertexts are prefixed so both coexist.

**Authenticator code "didn't match"** — TOTP depends on the clock. Make sure the server *and* the
phone/computer running the authenticator are time-synced (Windows: *Settings → Time → Sync now*).
The app accepts ±30 s of drift.

**Phone can't reach the server** — start with `--lan`, check the firewall rule for port 5000, make sure
both devices are on the same network (guest Wi-Fi often isolates clients), and use the IP printed at
startup / shown on `/dev/env`.

**PowerShell: "running scripts is disabled"** — `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use `run.bat`.

**`py` not found on Windows** — install Python from python.org (tick *Add to PATH* and the *py launcher*), or replace `py -3` with `python`.

**Port already in use** — `PORT=5001 python app.py` (`set PORT=5001` / `$env:PORT=5001` on Windows).

**Windows Subsystem for Linux** — follow the Linux steps inside WSL; to reach it from a phone bind with `--lan` and forward the port from Windows (`netsh interface portproxy add v4tov4 listenport=5000 connectaddress=<wsl-ip> connectport=5000`).

**CAPTCHA keeps appearing / HTTP 429 while testing** — you tripped the brute-force layers (3 failures
in 15 min → CAPTCHA; more than the per-minute limit → 429). Wait a minute, answer the dummy challenge,
or relax `CAPTCHA_AFTER_FAILURES` / `RATELIMIT_*` in `.env` for load testing.

**Existing `instance/uber_services.db` from the original app** — it is upgraded in place on first start (`migrations.py` adds the new columns/tables); no data is lost.

---

## 8. Project layout

```
app.py               app factory + marketplace routes           run.sh / run.bat / run.ps1   platform launchers
wsgi.py              production entry point (gunicorn/waitress) .env.example                  all settings documented
config.py            env-driven config, required keys, dummies  requirements.txt              pure-Python deps
extensions.py        db / login manager / built-in CSRF         throttle.py                   IP rate limits (Flask-Limiter)
models.py            User (+2FA), Service, Booking, OTP,        requirements-optional.txt     pyotp, gunicorn, waitress
                     RecoveryCode, TrustedDevice, AuthEvent     pytest.ini                    test config (pythonpath=.)
migrations.py        in-place SQLite schema upgrade             SECURITY_REVIEW.md            assessment & roadmap
clock.py             UTC "now" helper
devtools.py          /healthz, /dev/outbox, /dev/env
auth/
  routes.py          register, login, 2FA, reset, settings      scripts/
  captcha.py         none / dummy / turnstile / hcaptcha / re…    rotate_keys.py             MFA key rotation
  oauth.py           OAuth 2.0 / OIDC client (stdlib)             fake_oauth_server.py       standalone stub IdP
  oauth_routes.py    start / callback / link / unlink
  fake_oauth.py      in-app stub identity provider (/dev/oauth)
  jwt_min.py         HS256 / RS256-JWKS / ES256 for Apple
  mfa.py             TOTP/e-mail/SMS, recovery, devices, reset    check_env.py               environment doctor
  totp.py            RFC 6238 TOTP, stdlib only                   smoke_test.py              end-to-end test vs running server
  crypto.py          Fernet + stdlib fallback, keyed hashes       fake_authenticator.py      TOTP code generator
  delivery.py        console / memory / smtp / twilio             fake_smtp_server.py        SMTP sink
  audit.py           auth event log                               fake_twilio_server.py      Twilio API stub
templates/auth/      login, register, 2FA, security pages       tests/
templates/dev/       fake inbox, environment report               test_auth.py               29 auth/2FA tests
static/app.css                                                    test_totp.py               RFC vectors (+pyotp cross-check)
                                                                  test_platform.py           fallbacks, stubs, prod guard
                                                                  test_hardening.py          CSRF, rate limit, CAPTCHA, reset, rotation
                                                                  test_oauth.py              social login via the stub, all 3 providers
```

MIT-style demo — feel free to extend.
