# ServiceUber — Authentication & Authorization Review

**Scope:** `app.py`, templates, `requirements.txt`, `instance/uber_services.db` as uploaded (single-file Flask app, ~250 lines).
**Method:** manual code review of every route, model and template; runtime inspection of the SQLite schema; behavioural testing of login/session handling.

Severity scale: **Critical** (account/system takeover) · **High** (direct account compromise) · **Medium** (weakens defences / business-logic abuse) · **Low** (hygiene).

---

## 1. Executive summary

The original app had a *functional* but *minimal* auth layer: Flask-Login sessions, scrypt-hashed passwords (Werkzeug default), and a `@login_required` guard on private routes. Everything else that normally surrounds authentication was missing — no second factor, no CSRF protection, no brute-force limits, a hard-coded session signing key, and a `role` field that was stored but never enforced.

**Status after this work:** the items marked ✅ below are implemented and covered by the test suite (`tests/test_auth.py`, 29 tests). Items marked ⬜ are recommendations for the next iterations, ordered by priority in §5.

| # | Finding | Severity | Status |
|---|---|---|---|
| A1 | Hard-coded `SECRET_KEY` placeholder → forgeable session cookies | Critical | ✅ env-driven; prod refuses to start without it |
| A2 | No two-factor authentication | High | ✅ TOTP app + e-mail + SMS, recovery codes, trusted devices |
| A3 | No CSRF protection on any POST form | High | ✅ synchroniser-token CSRF guard (`extensions.CSRFProtect`) on all forms |
| A4 | No brute-force protection on login | High | ✅ three layers: IP rate limits (Flask-Limiter) → CAPTCHA after repeated failures → per-account lockout |
| A5 | `debug=True`, bound to `0.0.0.0` (Werkzeug debugger = RCE) | Critical if deployed | ✅ debug from config; default host 127.0.0.1 |
| A6 | No password policy (1-char passwords accepted) | Medium | ✅ min length, not containing username/e-mail |
| A7 | No session hardening (fixation, cookie flags, protection level) | Medium | ✅ session rotated on login, HttpOnly/SameSite/Secure, `strong` protection |
| A8 | Logout via GET (CSRF-able, prefetch-able) | Low | ✅ POST + CSRF |
| A9 | No e-mail ownership verification | Medium | ◐ verified when enabling e-mail 2FA; ⬜ not enforced at registration |
| A10 | Timing difference reveals whether a username exists | Low | ✅ dummy hash on unknown user |
| A11 | Demo credentials rendered on login page | Medium | ✅ only shown when `DEBUG` |
| A12 | No password reset / change flow | Medium | ✅ change-password (re-auth) + reset-by-e-mail that still requires the second factor; sessions/devices invalidated |
| A13 | No audit trail of auth events | Medium | ✅ `auth_event` table + log lines |
| A14 | No security response headers | Low | ✅ CSP, X-Frame-Options, nosniff, Referrer-Policy, HSTS (when secure) |
| Z1 | `role` (buyer/seller/both) never enforced | Medium | ✅ buyer-only can't post, seller-only can't book |
| Z2 | Any party to a booking can set *any* status (buyer can "accept"/"complete" own booking) | Medium | ✅ per-role transition table, terminal states locked |
| Z3 | No admin role / no RBAC abstraction | Medium | ⬜ |
| Z4 | Authorization is ad-hoc inline `if` checks | Low | ⬜ introduce policy helpers |
| I1 | `db.create_all()` only; no migrations | Low | ◐ idempotent `migrations.py`; ⬜ Alembic |
| I2 | SQLite, single process, no HTTPS termination | Low (demo) | ⬜ |
| I3 | CDN assets without Subresource Integrity | Low | ⬜ |

---

## 2. Authentication — detailed findings (original code)

### Key management (post-review hardening)
* `SECRET_KEY` and `MFA_ENCRYPTION_KEY` are **required** from `.env`; no in-code fallback (the previous round's dummy fallback was removed). Dev templates still ship DUMMY values; production refuses them.
* `SECRET_KEY` now signs **only** sessions and CSRF tokens. All keyed hashes (one-time codes, recovery codes, trusted-device tokens, reset tokens) and the TOTP secret encryption are keyed from `MFA_ENCRYPTION_KEY`, so rotating the session key logs users out and nothing else.
* `MFA_ENCRYPTION_KEY` rotation is supported: `MFA_ENCRYPTION_KEY_PREVIOUS` keeps old generations valid for decryption/verification, `scripts/rotate_keys.py` re-encrypts authenticator secrets, device tokens are re-keyed on use, recovery codes are replaced when regenerated. Drop the previous key after `TRUSTED_DEVICE_DAYS`.

### A1 · Hard-coded session secret — Critical
```python
DUMMY_SECRET_KEY = "YOUR_FLASK_SECRET_KEY_HERE"
app.config['SECRET_KEY'] = DUMMY_SECRET_KEY
```
Flask sessions are client-side cookies signed with this key. With a known key anyone can mint a cookie containing `_user_id=1` and become any user — no password needed. The README even publishes the value. Because the key is also what Flask-Login's "strong" protection and the CSRF tokens depend on, every other control is void until this is fixed.

**Fix:** `config.py` reads `SECRET_KEY` from the environment. Development/test fall back to clearly named `DUMMY_*` placeholders (so the app runs out of the box on any platform), and `ProductionConfig.__init__` **refuses to start** while `SECRET_KEY` or `MFA_ENCRYPTION_KEY` is a dummy value or while a stub delivery backend is selected. `/dev/env` shows whether dummies are in use.

### A2 · Single-factor only — High
A leaked/phished/reused password was sufficient. See §4 for what was built.

### A3 · No CSRF protection — High
`/book/<id>`, `/booking/<id>/update`, `/post_service` and `/logout` (GET!) had no anti-CSRF token. A malicious page could book services or cancel incoming bookings on behalf of a logged-in user. `SameSite` was not set, so older browsers would send the cookie cross-site.

**Fix:** a dependency-free synchroniser-token guard (`extensions.CSRFProtect`: random token in the signed session, required in the `csrf_token` field or `X-CSRF-Token` header on every unsafe method, `@csrf.exempt` for the dev-only inbox); every form carries `csrf_token`; tests confirm a token-less or wrong-token POST returns 400.

### A4 · No brute-force protection — High
Unlimited attempts on `/login`. With the demo usernames public, online guessing was trivial.

**Fix (layered, `throttle.py` + `auth/captcha.py` + `models.User`):**
1. **IP rate limits** on every auth POST (`/login`, `/2fa/verify`, `/register`, `/password/*`, code-send endpoints) via Flask-Limiter; storage `memory://` for one process or Redis for many workers; `BEHIND_PROXY` enables ProxyFix so the real client IP is used. HTTP 429 with a friendly page.
2. **CAPTCHA** once `CAPTCHA_AFTER_FAILURES` (3) failed events are seen from the IP *or* for the account within 15 min — evaluated *before* the password, so bots can't probe credentials past it. Providers: `dummy` (offline stub for dev/test; production refuses it), Turnstile, hCaptcha, reCAPTCHA (server-side verification, no SDK).
3. **Per-account lockout** (5 → 15 min) as the last line. Because layers 1–2 stop automated guessing first, the lockout rarely triggers for a victim, which addresses the lock-out-the-victim DoS concern; the login page also points locked users to the reset flow.
OTP codes additionally: max 5 wrong guesses then the code is burnt; max 6 sends/hour with a 60 s resend cooldown; 5 wrong second-factor attempts abort the pending flow.

### A5 · Debug mode on an all-interfaces bind — Critical when reachable
`app.run(debug=True, host='0.0.0.0')` exposes the Werkzeug interactive debugger, which gives remote code execution to anyone who can reach the port (the PIN is brute-forceable/leakable).

**Fix:** `DEBUG` comes from `APP_ENV`; default host `127.0.0.1`. A real WSGI server is still required (§5).

### A6 · No password policy — Medium
`request.form['password']` went straight to the hasher. Werkzeug's scrypt default is good, but nothing stopped `"a"`.

**Fix:** `PASSWORD_MIN_LENGTH` (10), max 128, must not contain the username or e-mail local part. Breach-list checking is recommended (§5).

### A7 · Session handling — Medium
* No session regeneration on login → session fixation.
* `SESSION_COOKIE_SECURE` unset; `SameSite` unset.
* Flask-Login `session_protection` at default `basic`.
* Sessions had no explicit lifetime.

**Fix:** `session.clear()` before `login_user()`; explicit cookie flags; `strong` protection (note: this logs users out when their IP/UA changes — acceptable for a web app, revisit if a mobile client appears); 12 h lifetime.

### A12 · Password reset — built, second-factor-gated
`/password/forgot` → generic response (no enumeration; throttled per IP and 3/hour per account) → e-mail with a single-use, 1-hour token (hashed at rest, `password_reset_token` table) → **if 2FA is enabled the user must pass it first** (`/password/reset/verify`, same challenge UI as login). E-mail codes are *not* offered for the reset when another factor exists — the link already proved mailbox control, so they'd add nothing; they remain available only when e-mail is the sole factor (otherwise the user would be locked out). On completion: password stamp changes (every other session dies via the Flask-Login identity), trusted devices revoked, all reset tokens burnt, notification e-mail sent, audit events recorded. Five wrong codes abort the reset and count toward the lockout.

### A9 · E-mail never verified — Medium
Anyone could register with someone else's address. That matters once e-mail becomes a recovery/2FA channel.

**Fix (partial):** enabling e-mail 2FA requires proving ownership (`email_verified` flag). Registration itself still doesn't verify — recommended in §5.

### A10 · Username enumeration via timing — Low
When the username didn't exist the code skipped the hash check, responding measurably faster. The wording was already generic.

**Fix:** a throwaway hash is computed on the unknown-user path.

### A11 · Demo credentials in the UI — Medium
`login.html` printed the seller/buyer passwords to every visitor.

**Fix:** rendered only when `config.DEBUG`.

### A13 · No audit logging — Medium
No record of logins, failures, or lockouts → no way to investigate an incident.

**Fix:** `auth_event` table (`login_success`, `login_failed`, `mfa_enabled`, `recovery_code_used`, …) with IP and user-agent, mirrored to the application log.

---

## 3. Authorization — detailed findings (original code)

### Z1 · Role stored but never enforced — Medium
`User.role` ∈ {buyer, seller, both} was collected at registration and then ignored: a "buyer" could post services and a "seller" could book. The role is essentially user-chosen so it is a weak control anyway, but the UI implied it meant something.

**Fix:** `post_service` rejects `role == 'buyer'`; `book_service` rejects `role == 'seller'`.

### Z2 · Booking state machine not enforced — Medium
```python
if booking.service.seller_id != current_user.id and booking.buyer_id != current_user.id: deny
if new_status in [...]: booking.status = new_status
```
Ownership was checked (good — no IDOR), but **either** party could pick **any** status: a buyer could mark their own booking `accepted`/`completed`, and a `completed` booking could be reopened.

**Fix:** seller may set `accepted | in_progress | completed | cancelled`; buyer may only `cancel`; `completed`/`cancelled` are terminal.

### Z3 · No administrative role — Medium
There is no way to moderate listings, suspend accounts, or reset a user's 2FA without editing the database. Any future admin route must be protected by a server-side role check, **not** by obscurity.

### Z4 · Authorization is ad-hoc — Low
Checks are inline in each view. As routes grow this pattern reliably produces missed checks. A small `require_owner(obj)` / `require_role(...)` helper or Flask-Principal-style permissions would centralise it.

### What was already correct
* `get_or_404` + ownership comparisons on `update_booking` → no horizontal privilege escalation found.
* Users cannot book their own service.
* SQLAlchemy ORM throughout → no SQL injection; Jinja autoescape on → no reflected XSS found (`description` is rendered escaped).
* `Service.seller_id` comes from `current_user`, never from the form.

---

## 4. Two-factor authentication — what was built

### Architecture
```
auth/routes.py     HTTP flows                 auth/mfa.py      factor logic
auth/crypto.py     Fernet + HMAC helpers      auth/delivery.py console | memory | smtp | twilio
auth/audit.py      event log                  models.py        User(+2FA cols), OneTimeCode,
                                                               RecoveryCode, TrustedDevice, AuthEvent
```

### Login flow
1. `POST /login` — password check (lockout aware).
2. If any factor is enabled **and** no valid trusted-device cookie: the session is replaced by a short-lived `mfa_pending` marker (5 min, user id, failure counter, safe `next` URL). **`login_user()` is not called** — nothing protected is reachable.
3. `GET/POST /2fa/verify` — user picks any enabled method (tabs), or a recovery code. E-mail/SMS codes are sent on demand ("Send code") so no message goes out until the user asks.
4. On success: session rotated, `login_user()`, optional 30-day trusted-device cookie, audit event.

### Factor details
| | Authenticator app (TOTP) | E-mail code | SMS code |
|---|---|---|---|
| Standard | RFC 6238, 6 digits, 30 s, ±1 step drift — implemented in `auth/totp.py` with the standard library and verified against the RFC 4226/6238 test vectors | 6 random digits (`secrets`) | same |
| Setup | Secret generated server-side, held **in session** until the user proves it with a live code; QR rendered locally (no third-party QR service) + manual key | Code sent to the account e-mail; success also sets `email_verified` | Phone normalised to E.164, uniqueness-checked, code sent, success sets `phone_verified` |
| At rest | Secret encrypted with Fernet (`MFA_ENCRYPTION_KEY`); stdlib HMAC-CTR + HMAC fallback when `cryptography` can't be installed (dev/test only, see below) | HMAC-SHA256(secret key) of code; 10 min TTL | same |
| Replay | `totp_last_counter` — a code (or an earlier one) can't be reused | single-use, burnt after 5 wrong guesses | same |
| Throttling | 5 wrong attempts abort the login | + resend cooldown 60 s, 6 sends/h | same |

* **Recovery codes:** 10 × `xxxx-xxxx-xxxx` (~58 bits), shown once when the *first* factor is enabled or on regeneration, stored as keyed hashes, single use, constant-time comparison across the whole set.
* **Trusted devices:** random 256-bit token in an `HttpOnly` cookie, keyed-hash stored server-side with UA/IP/expiry; listed and revocable on the Security page; auto-purged when the last factor is disabled.
* **Re-authentication ("sudo mode"):** enabling/disabling a factor, regenerating recovery codes and changing the password all require the current password in the same request.
* **Preferred method:** user can choose which factor is shown first at sign-in.
* **Delivery backends:** `console` (dev — log + `instance/auth_outbox.jsonl` + fake inbox at `/dev/outbox`), `memory` (tests), `smtp` (stdlib), `twilio` (stdlib `urllib`, no SDK). Swappable via env. `scripts/fake_smtp_server.py` and `scripts/fake_twilio_server.py` exercise the real `smtp`/`twilio` code paths without accounts.
* **Cross-platform:** no compiled dependencies are required. QR codes are SVG (no Pillow), TOTP is stdlib (no pyotp). `cryptography` and `qrcode` are optional with graceful degradation; CI runs the suite on Linux, macOS and Windows and once more with both packages removed.

### Social login (OAuth 2.0) — design notes
* **Client** (`auth/oauth.py`): authorization-code flow with `state` (CSRF), PKCE S256 and `nonce`; tokens exchanged server-to-server with client authentication; stdlib only. Google → OIDC userinfo; Facebook → Graph `/me`; Apple → `form_post` callback bounced to a same-site GET (so the `SameSite=Lax` session cookie is present), `id_token` verified against Apple's JWKS (RS256, needs `cryptography`), client secret = ES256 JWT from the `.p8` key. Only explicitly expected `alg` values are accepted.
* **Account linking policy** (`auth/oauth_routes.py`): identities map to users via `oauth_account(provider, subject)`. A new identity whose e-mail matches an existing local account is **not** auto-linked (the classic takeover: attacker registers the victim's e-mail at a lax provider) — the user must log in with password + 2FA first, then the link completes. Linking from settings needs an active session; unlinking needs the password; the last identity can't be unlinked while the password is unusable.
* **Social login is a first factor only.** Users with 2FA still complete it; trusted-device cookies apply as usual. Socially created accounts get an unusable random password (`password_is_usable=False`) and set one through the reset flow.
* **Stub provider** (`auth/fake_oauth.py`, `scripts/fake_oauth_server.py`) enforces client auth, `redirect_uri`, single-use codes, PKCE and issues HS256 `id_token`s with a DUMMY key — so the client path under test is the production one, only URLs and the signature algorithm differ. `ProductionConfig` refuses `OAUTH_MODE=fake` and dummy OAuth credentials for any listed provider.
* **Residual risks:** provider e-mail claims are trusted only when marked verified; Facebook may withhold the e-mail (we refuse to create an account without one). Provider outages/revocations are not propagated (no token storage, nothing to revoke). Consider "notify on new social link" and showing linked identities in the audit trail UI.

### Development-only surfaces (must be off in production)
* **`/dev/outbox`** exposes every e-mail/SMS code the stub backends "sent" — to anyone who can reach the server. It exists so testers on phones/tablets can read codes. `ENABLE_DEV_TOOLS` is forced off by `ProductionConfig`; never set it on a public host.
* **`/dev/env`** reveals platform, dependency versions and paths (useful for support, bad for reconnaissance). Same flag.
* **DUMMY secrets** (`DUMMY_FLASK_SECRET_KEY_CHANGE_ME`, the dummy Fernet key, `DUMMY_TWILIO_*`, …) are public knowledge by definition: sessions signed with them are forgeable. Production config rejects them; `scripts/check_env.py` and `/dev/env` warn when they're in use.
* **Stdlib cipher fallback** (`auth/crypto.py`, prefix `hs1:`) is an authenticated HMAC-SHA256 counter-mode construction — sound, but non-standard and unreviewed compared with Fernet. It exists so the app still runs where `cryptography` has no wheel. Install `cryptography` for production; `/dev/env` → *secret_encryption* shows which one is active.
* `HOST=0.0.0.0` (`--lan`) binds to every interface for phone/tablet testing. Do this on trusted networks only; the dev server has no TLS.

### Known limitations of the implementation
* **No MFA enforcement policy.** Users can choose not to enable any factor. If sellers handle payouts, consider requiring it (§5).
* **SMS is opt-in and labelled as the weakest option** in the UI, but it is still offered because the requirement asked for it. SIM-swap and SS7 interception are real; don't let SMS be the only factor for high-value accounts.
* **Rate-limit storage** defaults to `memory://` (per process). With several workers/containers use Redis, or limits are effectively multiplied by the worker count.
* **`dummy` CAPTCHA is a stub** — trivially solvable by a script. It exists for offline dev/test; production refuses it. Real providers are verified server-side but the widget needs the provider's script (CSP is extended automatically).
* **Lost-all-factors recovery** is "use a recovery code". There is no support-assisted reset process; build one *before* you have users, and make it require strong identity proofing.
* E-mail 2FA is only as strong as the mailbox. The reset flow therefore refuses e-mail codes when any other factor exists; an account whose *only* factor is e-mail is fully compromised by a mailbox takeover — nudge such users toward an authenticator app.
* `datetime.utcnow()` is used (naive UTC, inherited from the original code). It's deprecated in 3.12 — migrate to `datetime.now(UTC)` when touching the models.

---

## 5. Recommended upgrade roadmap

### Tier 0 — before anything is reachable from the internet
1. **Replace every `DUMMY_*` value** — `SECRET_KEY` and `MFA_ENCRYPTION_KEY` from a secrets manager (Vault, AWS SM, Doppler…), never from a file in the repo. Rotating `SECRET_KEY` invalidates sessions *and* the HMAC'd OTP/recovery/device hashes; plan rotations.
2. **Run under gunicorn (Linux/macOS) or waitress (Windows) behind TLS** (nginx/Caddy/IIS/ALB), `APP_ENV=production` (which also forces `ENABLE_DEV_TOOLS=false`, `SEED_DEMO_DATA=false`, `SESSION_COOKIE_SECURE=true`).
3. **Real delivery backends** (`EMAIL_BACKEND=smtp`, `SMS_BACKEND=twilio`), `cryptography` installed, and delete any `instance/auth_outbox.jsonl`.
4. **Move off SQLite** to PostgreSQL and adopt **Alembic / Flask-Migrate** (replace `migrations.py`).

### Tier 1 — complete the account lifecycle (next sprint)
5. **E-mail verification at registration** (24 h link) — block booking/posting until verified. The reset-token machinery in `auth/mfa.py` (`issue_password_reset` / `load_password_reset`) is the template.
6. ~~Password reset by e-mail~~ — **done** (A12).
7. ~~IP rate limiting + CAPTCHA~~ — **done** (A4). Remaining: point `RATELIMIT_STORAGE_URI` at Redis and pick a real CAPTCHA provider in production.
8. **Breached-password check** (Have I Been Pwned k-anonymity API) on registration and password change; optionally `zxcvbn` strength scoring.
9. **Notifications:** e-mail the user on new-device login, 2FA enabled/disabled, password changed, recovery code used. Cheap and the single most effective compromise detector.
10. **Server-side sessions** (Flask-Session on Redis) so you can list and revoke *individual* sessions. "Sign out everywhere on password change" is already done via the password stamp in the session identity.

### Tier 2 — authorization model
11. **Introduce an explicit permission layer**: `@require_role("admin")`, `can_edit(service)`, `can_transition(booking, to)` helpers in one module, unit-tested, used by every mutating route. Flask-Principal or a 40-line custom decorator both work.
12. **Admin role + admin UI** (suspend user, hide listing, reset a user's 2FA after identity verification) with mandatory MFA for admins and audit of every admin action.
13. **Make `role` meaningful or remove it.** Today it's self-assigned. Either tie "seller" to a verification/KYC step (relevant for a marketplace that will move money) or drop the restriction and just model capabilities.
14. **Step-up authentication** for sensitive actions (payout details, e-mail/phone change): require a fresh second-factor within the last N minutes, not just the password.
15. **Object-level checks for future routes**: service edit/delete, booking detail pages, payment token display (the seller currently sees the buyer's payment token on the dashboard — fine while dummy, not fine with a real PSP).

### Tier 3 — stronger & smoother authentication
16. **WebAuthn / passkeys** (`py_webauthn`) — phishing-resistant, replaces TOTP for most users and can double as a password replacement. The `TrustedDevice` / factor-selection UI is already structured so a `webauthn` method can slot in next to `totp|email|sms`.
17. **Enforce MFA** for sellers (or everyone) with a grace period and a nag banner — the navbar already shows a warning badge when 2FA is off.
18. ~~Social / OIDC login~~ — **done** (Google, Apple, Facebook; stdlib client). Next: notify users by e-mail when a new identity is linked.
19. **Risk-based prompts:** require the second factor even on trusted devices when IP country changes or after 30 days of inactivity.
20. **SMS abuse controls:** per-number and per-IP send limits, country allowlist, CAPTCHA before first send (SMS-pumping fraud is a cost attack).

### Tier 4 — operations & hygiene
21. **Dependency scanning** (`pip-audit`, Dependabot) — pins are now in `requirements.txt`; keep them current.
22. **Subresource Integrity** hashes on the Bootstrap CDN tags, or self-host the assets (then tighten CSP to `'self'` only).
23. **Audit log retention & export** (ship `auth_event` to your SIEM; purge after 90–365 days per policy) and a nightly job calling `mfa.purge_expired()`.
24. **Structured JSON logging** with request IDs; never log codes or secrets (the console backend is the only place codes are logged and it's dev-only).
25. **Security tests in CI** — `pytest` already covers lockout, CSRF, replay, single-use, open-redirect; add them to the pipeline and run `bandit`.

---

## 6. File change summary

| File | Change |
|---|---|
| `app.py` | App factory, marketplace routes kept, role/transition enforcement, security headers, debug from config |
| `config.py` | **new** — env-driven config with dev/prod/test profiles |
| `extensions.py` | **new** — `db`, `login_manager` (strong protection), `csrf` |
| `models.py` | User gains 2FA/lockout columns; new `OneTimeCode`, `RecoveryCode`, `TrustedDevice`, `AuthEvent` |
| `migrations.py` | **new** — adds columns/tables to an existing SQLite DB without data loss |
| `auth/` | **new** package — routes (incl. password reset), MFA logic, stdlib TOTP, crypto (Fernet + fallback, key rotation), CAPTCHA, delivery, audit |
| `throttle.py` | **new** — Flask-Limiter integration, ProxyFix, failure counters |
| `auth/oauth.py`, `auth/oauth_routes.py`, `auth/jwt_min.py`, `auth/fake_oauth.py`, `scripts/fake_oauth_server.py` | **new** — OAuth 2.0 social login + stub identity provider |
| `extensions.py` | built-in CSRF protection (Flask-WTF dropped) |
| `scripts/rotate_keys.py` | **new** — MFA key rotation |
| `devtools.py`, `templates/dev/*` | **new** — `/healthz`, fake inbox `/dev/outbox`, `/dev/env` (dev only) |
| `scripts/` | **new** — environment doctor, smoke test, fake authenticator / SMTP / Twilio stubs (stdlib only) |
| `run.sh`, `run.bat`, `run.ps1`, `.github/workflows/ci.yml` | **new** — platform launchers and Linux/macOS/Windows CI matrix |
| `templates/base.html` | POST logout, Security link + warning badge, CSRF tokens |
| `templates/auth/*` | **new** — login, register, 2FA verify, security settings, setup pages, recovery codes, change password |
| `templates/dashboard.html`, `service_detail.html`, `post_service.html` | CSRF tokens |
| `static/app.css` | styles moved out of inline `<style>` (CSP) |
| `tests/` | **new** — 65 tests: auth/2FA flows, RFC TOTP vectors, platform fallbacks, production guard, CSRF, rate limits, CAPTCHA, reset, key rotation |
| `requirements.txt` | + Flask-Limiter, qrcode, cryptography, pytest — **pure Python, no Pillow/pyotp/Flask-WTF**, lower-bound pins |
| `.env.example` | **new** |
