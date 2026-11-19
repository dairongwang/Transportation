"""
Authentication routes: registration, login (password + second factor), logout,
password reset (e-mail link + second factor) and the security settings pages.

Brute-force defences, layered:
  1. IP rate limits (throttle.py / Flask-Limiter) on every POST here
  2. CAPTCHA (auth/captcha.py) after CAPTCHA_AFTER_FAILURES failures per IP or account
  3. per-account lockout (models.User) as the last line
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse

from flask import (
    abort,
    current_app,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user

from clock import utcnow
from extensions import db
from models import TrustedDevice, User
from throttle import (
    client_ip,
    code_send_limit,
    login_limit,
    register_limit,
    reset_limit,
    two_factor_limit,
)

from . import bp, captcha, mfa
from .audit import record
from .delivery import DeliveryError, send_password_changed_email, send_password_reset_email, stub_hint
from .mfa import TRUSTED_DEVICE_COOKIE, MFAError

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,80}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MFA_PENDING_KEY = "mfa_pending"  # {'purpose': login|password_reset, 'uid', 'exp', 'failures', 'method', ...}
MFA_MAX_FAILURES = 5
PENDING_TOTP_KEY = "pending_totp_secret"
PENDING_PHONE_KEY = "pending_phone"
RESET_KEY = "pw_reset"  # {'uid', 'token_id', 'exp', 'mfa_ok'}
PENDING_LINK_KEY = "pending_oauth_link"
GENERIC_LOGIN_ERROR = "Invalid username or password."
GENERIC_RESET_MESSAGE = "If an account with that e-mail exists, we've sent a password-reset link."


# ================================================================= helpers

def _is_safe_url(target: str | None) -> bool:
    if not target:
        return False
    parsed = urlparse(target)
    return parsed.scheme == "" and parsed.netloc == "" and target.startswith("/") and not target.startswith("//")


def _validate_password(password: str, username: str = "", email: str = "") -> str | None:
    min_len = current_app.config["PASSWORD_MIN_LENGTH"]
    if len(password) < min_len:
        return f"Password must be at least {min_len} characters."
    if len(password) > 128:
        return "Password is too long."
    lowered = password.lower()
    if username and username.lower() in lowered:
        return "Password must not contain your username."
    if email and email.split("@")[0].lower() in lowered:
        return "Password must not contain your e-mail address."
    return None


def _captcha_gate(user_id: int | None = None) -> tuple[bool, bool]:
    """
    (required, passed) for the current POST. Records a `captcha_failed` event when a
    required CAPTCHA was answered wrongly so repeated bot attempts keep it required.
    """
    required = captcha.required(client_ip(), user_id)
    if not required:
        return False, True
    passed = captcha.verify(request.form)
    if not passed:
        record("captcha_failed", user_id)
        flash("Please complete the CAPTCHA.", "error")
    return True, passed


def _complete_login(user: User, remember_device: bool = False, extra_flash: tuple[str, str] | None = None,
                    next_url: str | None = None):
    """Finalise a fully-authenticated login: rotate session, set cookies, audit."""
    next_url = next_url or (session.get(MFA_PENDING_KEY) or {}).get("next") or request.args.get("next")
    pending_link = session.get(PENDING_LINK_KEY)  # social identity waiting to be linked (see oauth_routes)
    session.clear()  # session fixation protection
    login_user(user)
    user.last_login_at = utcnow()
    user.reset_login_failures()
    record("login_success", user.id)
    if pending_link:
        from .oauth_routes import complete_pending_link  # local import: oauth_routes imports this module

        complete_pending_link(user, pending_link)

    resp = make_response(redirect(next_url if _is_safe_url(next_url) else url_for("dashboard")))
    if remember_device and user.mfa_enabled:
        token = mfa.create_trusted_device(user, request.user_agent.string, client_ip())
        resp.set_cookie(
            TRUSTED_DEVICE_COOKIE,
            token,
            max_age=current_app.config["TRUSTED_DEVICE_DAYS"] * 86400,
            httponly=True,
            secure=current_app.config["SESSION_COOKIE_SECURE"],
            samesite="Lax",
        )
    flash(f"Welcome back, {user.username}!", "success")
    if extra_flash:
        flash(*extra_flash)
    return resp


def _start_second_factor(user: User, purpose: str, **extra) -> None:
    """Put the session into 'password verified, second factor pending' state."""
    session[MFA_PENDING_KEY] = {
        "purpose": purpose,
        "uid": user.id,
        "exp": time.time() + current_app.config["MFA_PENDING_TTL_SECONDS"],
        "failures": 0,
        **extra,
    }


def _pending_user(purpose: str) -> User | None:
    """Return the user who passed step one (for `purpose`) but not yet the second factor."""
    pending = session.get(MFA_PENDING_KEY)
    if not pending or pending.get("purpose") != purpose:
        return None
    if pending.get("exp", 0) < time.time():
        session.pop(MFA_PENDING_KEY, None)
        return None
    return db.session.get(User, pending["uid"])


def _pending_failure(user: User, purpose: str, detail: str):
    """Count a failed second-factor attempt; abort the flow after too many."""
    pending = session.get(MFA_PENDING_KEY, {})
    pending["failures"] = pending.get("failures", 0) + 1
    session[MFA_PENDING_KEY] = pending
    record("mfa_failed" if purpose == "login" else "reset_mfa_failed", user.id, detail)
    if pending["failures"] >= MFA_MAX_FAILURES:
        session.pop(MFA_PENDING_KEY, None)
        session.pop(RESET_KEY, None)
        locked = user.register_failed_login(
            current_app.config["LOGIN_MAX_FAILED_ATTEMPTS"], current_app.config["LOGIN_LOCKOUT_SECONDS"]
        )
        db.session.commit()
        record("mfa_aborted", user.id, f"{purpose}: too many failed attempts" + (" (account locked)" if locked else ""))
        flash("Too many incorrect codes. Please start again.", "error")
        return redirect(url_for("auth.login"))
    flash("Incorrect code. Please try again.", "error")
    return None


def _require_password_confirmation(form_field: str = "current_password") -> bool:
    """Re-authentication for sensitive settings changes ("sudo mode")."""
    password = request.form.get(form_field, "")
    if not current_user.check_password(password):
        record("reauth_failed", current_user.id)
        flash("Incorrect password.", "error")
        return False
    return True


def _label(method: str) -> str:
    return {"totp": "Authenticator app", "email": "E-mail codes", "sms": "SMS codes"}.get(method, method)


@bp.app_template_filter("mfa_label")
def mfa_label_filter(method: str) -> str:
    return _label(method)


@bp.app_context_processor
def _inject_helpers():
    return {
        "captcha_challenge": captcha.challenge,
        "captcha_required_for_ip": lambda: captcha.required(client_ip()),
        "stub_hint": stub_hint,  # where to find stubbed e-mails / SMS (None with real providers)
    }


def _flash_sent(message: str, channel: str) -> None:
    """Confirm a send and, in test mode, say where the code/link actually went."""
    hint = stub_hint(channel)
    flash(message, "info")
    if hint:
        flash(hint, "warning")


# ============================================================ registration

@bp.route("/register", methods=["GET", "POST"])
@register_limit
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "both")

        _, captcha_ok = _captcha_gate()
        if not captcha_ok:
            pass
        elif not USERNAME_RE.match(username):
            flash("Username must be 3-80 characters (letters, digits, . _ -).", "error")
        elif not EMAIL_RE.match(email) or len(email) > 120:
            flash("Please enter a valid e-mail address.", "error")
        elif role not in ("buyer", "seller", "both"):
            flash("Invalid role.", "error")
        elif (err := _validate_password(password, username, email)):
            flash(err, "error")
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.", "error")
        else:
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.flush()
            from background import live  # managers' Users tab updates live

            live.push_admin("user_registered", user)
            db.session.commit()
            record("register", user.id)
            flash("Registration successful! Please log in, then enable two-factor authentication in Security settings.", "success")
            return redirect(url_for("auth.login"))
        return render_template("auth/register.html", form=request.form), 400
    return render_template("auth/register.html", form={})


# ==================================================================== login

@bp.route("/login", methods=["GET", "POST"])
@login_limit
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter((User.username == identifier) | (User.email == identifier.lower())).first()

        # CAPTCHA is evaluated before the password so a bot can't probe credentials past it.
        _, captcha_ok = _captcha_gate(user.id if user else None)
        if not captcha_ok:
            return render_template("auth/login.html", show_captcha=True), 400

        if user is None:
            # Still run a hash to keep timing similar to the "user exists" path.
            User(username="x", email="x", password_hash="").set_password(password)
            record("login_failed", None, f"unknown user '{identifier[:40]}'")
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("auth/login.html", show_captcha=captcha.required(client_ip())), 401

        if user.is_locked:
            record("login_blocked_locked", user.id)
            flash("This account is temporarily locked due to too many failed attempts. "
                  "Try again later or use 'Forgot password?'.", "error")
            return render_template("auth/login.html"), 423

        if not user.password_is_usable:
            record("login_failed", user.id, "no usable password (social account)")
            flash("This account was created with a social login and has no password yet. "
                  "Use the social button, or 'Forgot password?' to set one.", "error")
            return render_template("auth/login.html"), 401

        if not user.check_password(password):
            locked = user.register_failed_login(
                current_app.config["LOGIN_MAX_FAILED_ATTEMPTS"], current_app.config["LOGIN_LOCKOUT_SECONDS"]
            )
            db.session.commit()
            record("login_failed", user.id, "bad password" + (" -> locked" if locked else ""))
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("auth/login.html", show_captcha=captcha.required(client_ip(), user.id)), 401

        # ---- password OK
        if user.mfa_enabled and not mfa.is_trusted_device(user, request.cookies.get(TRUSTED_DEVICE_COOKIE)):
            next_url = request.args.get("next")
            pending_link = session.get(PENDING_LINK_KEY)
            session.clear()
            if pending_link:
                session[PENDING_LINK_KEY] = pending_link
            _start_second_factor(user, "login", next=next_url if _is_safe_url(next_url) else None)
            record("login_password_ok", user.id, "awaiting second factor")
            return redirect(url_for("auth.two_factor"))

        if user.mfa_enabled:
            record("mfa_skipped_trusted_device", user.id)
        return _complete_login(user)

    return render_template("auth/login.html", show_captcha=captcha.required(client_ip()))


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    uid = current_user.id
    logout_user()
    session.clear()
    record("logout", uid)
    flash("Logged out.", "info")
    return redirect(url_for("index"))


# ============================================================ second factor

def _reset_factor_methods(user: User) -> list[str]:
    """
    Methods allowed to approve a password reset. The reset link already proves control
    of the mailbox, so e-mail codes add nothing - they're only offered when the user has
    no other factor (otherwise they'd be locked out).
    """
    methods = [m for m in user.enabled_mfa_methods if m != "email"]
    return methods or user.enabled_mfa_methods


@bp.route("/2fa/verify", methods=["GET", "POST"])
@two_factor_limit
def two_factor():
    return _second_factor_challenge("login")


@bp.route("/password/reset/verify", methods=["GET", "POST"])
@two_factor_limit
def reset_verify():
    return _second_factor_challenge("password_reset")


def _second_factor_challenge(purpose: str):
    user = _pending_user(purpose)
    if user is None:
        flash("Your session expired. Please start again.", "info")
        return redirect(url_for("auth.login" if purpose == "login" else "auth.forgot_password"))

    endpoint = "auth.two_factor" if purpose == "login" else "auth.reset_verify"
    methods = user.enabled_mfa_methods if purpose == "login" else _reset_factor_methods(user)
    pending = session[MFA_PENDING_KEY]
    method = request.values.get("method") or pending.get("method") or (
        user.preferred_2fa_method if user.preferred_2fa_method in methods else methods[0]
    )
    if method not in methods and method != "recovery":
        method = methods[0]
    pending["method"] = method
    session[MFA_PENDING_KEY] = pending

    if request.method == "POST":
        action = request.form.get("action", "verify")

        # --- "send me a code" for email / sms
        if action == "send":
            if method not in ("email", "sms"):
                abort(400)
            try:
                mfa.issue_code(user, method, "login")
                record("mfa_code_sent", user.id, f"{method} ({purpose})")
                _flash_sent(f"A code has been sent to your {'e-mail' if method == 'email' else 'phone'}.", method)
            except (MFAError, DeliveryError) as exc:
                flash(str(exc), "error")
            return redirect(url_for(endpoint, method=method))

        # --- verify
        code = request.form.get("code", "")
        ok = False
        extra_flash = None
        if method == "totp":
            ok = mfa.totp_verify(user, code)
        elif method in ("email", "sms"):
            ok, _ = mfa.verify_code(user, method, "login", code)
        elif method == "recovery":
            ok = mfa.verify_recovery_code(user, code)
            if ok:
                record("recovery_code_used", user.id, purpose)
                remaining = user.unused_recovery_code_count
                extra_flash = (
                    f"You used a recovery code ({remaining} left). "
                    "Consider regenerating your codes in Security settings.",
                    "warning",
                )

        if not ok:
            abort_resp = _pending_failure(user, purpose, method)
            if abort_resp is not None:
                return abort_resp
            return redirect(url_for(endpoint, method=method))

        db.session.commit()
        record("mfa_success", user.id, f"{method} ({purpose})")
        if purpose == "login":
            return _complete_login(user, remember_device=request.form.get("remember_device") == "on", extra_flash=extra_flash)

        # password reset: mark the second factor as satisfied and continue
        state = session.get(RESET_KEY) or {}
        state["mfa_ok"] = True
        session[RESET_KEY] = state
        session.pop(MFA_PENDING_KEY, None)
        if extra_flash:
            flash(*extra_flash)
        return redirect(url_for("auth.reset_new_password"))

    return render_template(
        "auth/two_factor.html",
        purpose=purpose,
        endpoint=endpoint,
        method=method,
        methods=methods,
        user=user,
        has_recovery=user.unused_recovery_code_count > 0,
    )


# ========================================================== password reset

def _reset_link(raw_token: str) -> str:
    base = current_app.config.get("APP_BASE_URL") or request.url_root.rstrip("/")
    return base + url_for("auth.reset_password", token=raw_token)


@bp.route("/password/forgot", methods=["GET", "POST"])
@reset_limit
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("auth.change_password"))
    if request.method == "POST":
        _, captcha_ok = _captcha_gate()
        if not captcha_ok:
            return render_template("auth/forgot_password.html", show_captcha=True), 400
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first() if EMAIL_RE.match(email) else None
        if user is not None:
            try:
                raw = mfa.issue_password_reset(user, client_ip())
                send_password_reset_email(user.email, _reset_link(raw))
                record("password_reset_requested", user.id)
            except MFAError as exc:
                record("password_reset_throttled", user.id, str(exc))
            except DeliveryError as exc:
                current_app.logger.error("Password reset e-mail failed: %s", exc)
        else:
            record("password_reset_requested", None, f"unknown e-mail '{email[:60]}'")
        # Same answer whether or not the account exists (no enumeration).
        _flash_sent(GENERIC_RESET_MESSAGE, "email")
        return redirect(url_for("auth.login"))
    return render_template("auth/forgot_password.html", show_captcha=captcha.required(client_ip()))


@bp.route("/password/reset/<token>")
def reset_password(token: str):
    """Entry point from the e-mail link. Validates the token and routes to the next step."""
    if current_user.is_authenticated:
        logout_user()
    session.clear()
    rec = mfa.load_password_reset(token)
    if rec is None:
        record("password_reset_invalid_token", None)
        flash("This password-reset link is invalid or has expired. Please request a new one.", "error")
        return redirect(url_for("auth.forgot_password"))
    user = rec.user
    session[RESET_KEY] = {
        "uid": user.id,
        "token_id": rec.id,
        "exp": min(time.time() + current_app.config["MFA_PENDING_TTL_SECONDS"] * 2, rec.expires_at.timestamp()),
        "mfa_ok": not user.mfa_enabled,
    }
    record("password_reset_link_opened", user.id, "2fa required" if user.mfa_enabled else "no 2fa")
    if user.mfa_enabled:
        _start_second_factor(user, "password_reset")
        flash("Confirm it's you with your second factor before choosing a new password.", "info")
        return redirect(url_for("auth.reset_verify"))
    return redirect(url_for("auth.reset_new_password"))


def _reset_state():
    """(state, user, token_record) for a valid in-progress reset, else (None, None, None)."""
    state = session.get(RESET_KEY)
    if not state or state.get("exp", 0) < time.time():
        session.pop(RESET_KEY, None)
        return None, None, None
    from models import PasswordResetToken

    rec = db.session.get(PasswordResetToken, state["token_id"])
    if rec is None or not rec.is_usable or rec.user_id != state["uid"]:
        session.pop(RESET_KEY, None)
        return None, None, None
    return state, rec.user, rec


@bp.route("/password/reset/new", methods=["GET", "POST"])
@reset_limit
def reset_new_password():
    state, user, rec = _reset_state()
    if user is None:
        flash("Your password-reset session expired. Please request a new link.", "error")
        return redirect(url_for("auth.forgot_password"))
    if not state.get("mfa_ok"):
        return redirect(url_for("auth.reset_verify"))

    if request.method == "POST":
        new = request.form.get("new_password", "")
        if new != request.form.get("confirm_password", ""):
            flash("New passwords do not match.", "error")
        elif (err := _validate_password(new, user.username, user.email)):
            flash(err, "error")
        else:
            mfa.complete_password_reset(rec, new)
            session.clear()
            record("password_reset_completed", user.id)
            try:
                send_password_changed_email(user.email)
            except DeliveryError:
                pass
            resp = make_response(redirect(url_for("auth.login")))
            resp.delete_cookie(TRUSTED_DEVICE_COOKIE)
            flash("Your password has been reset. All other sessions were signed out. Please log in.", "success")
            return resp
        return render_template("auth/reset_password.html", user=user), 400
    return render_template("auth/reset_password.html", user=user)


# ======================================================= security settings

@bp.route("/settings/security")
@login_required
def security():
    devices = TrustedDevice.query.filter_by(user_id=current_user.id).order_by(TrustedDevice.created_at.desc()).all()
    return render_template("auth/security.html", user=current_user, devices=devices)


@bp.route("/settings/security/preferred", methods=["POST"])
@login_required
def set_preferred_method():
    method = request.form.get("method")
    if method in current_user.enabled_mfa_methods:
        current_user.preferred_2fa_method = method
        db.session.commit()
        flash("Default sign-in method updated.", "success")
    return redirect(url_for("auth.security"))


# ---- authenticator app

@bp.route("/settings/security/totp/setup", methods=["GET", "POST"])
@login_required
def totp_setup():
    if current_user.totp_enabled:
        flash("Authenticator app is already enabled.", "info")
        return redirect(url_for("auth.security"))

    if request.method == "POST":
        secret = session.get(PENDING_TOTP_KEY)
        if not secret:
            flash("Setup session expired, please start again.", "error")
            return redirect(url_for("auth.totp_setup"))
        if not _require_password_confirmation():
            return redirect(url_for("auth.totp_setup"))
        if mfa.totp_confirm_setup(current_user, secret, request.form.get("code", "")):
            session.pop(PENDING_TOTP_KEY, None)
            first_factor = len(current_user.enabled_mfa_methods) == 1
            codes = mfa.generate_recovery_codes(current_user) if first_factor else None
            db.session.commit()
            record("mfa_enabled", current_user.id, "totp")
            flash("Authenticator app enabled.", "success")
            if codes:
                return render_template("auth/recovery_codes.html", codes=codes)
            return redirect(url_for("auth.security"))
        record("mfa_setup_failed", current_user.id, "totp")
        flash("That code didn't match. Check the time on your device and try again.", "error")
        return redirect(url_for("auth.totp_setup"))

    secret = session.get(PENDING_TOTP_KEY) or mfa.totp_generate_secret()
    session[PENDING_TOTP_KEY] = secret
    uri = mfa.totp_provisioning_uri(current_user, secret)
    return render_template(
        "auth/totp_setup.html",
        qr_data_uri=mfa.totp_qr_data_uri(uri),
        otpauth_uri=uri,
        manual_key=" ".join(secret[i : i + 4] for i in range(0, len(secret), 4)),
    )


# ---- e-mail codes

@bp.route("/settings/security/email/setup", methods=["GET", "POST"])
@login_required
@code_send_limit
def email_setup():
    if current_user.email_2fa_enabled:
        flash("E-mail codes are already enabled.", "info")
        return redirect(url_for("auth.security"))

    if request.method == "POST":
        action = request.form.get("action", "verify")
        if action == "send":
            try:
                mfa.issue_code(current_user, "email", "verify_email")
                _flash_sent(f"We sent a code to {current_user.email}.", "email")
            except (MFAError, DeliveryError) as exc:
                flash(str(exc), "error")
            return redirect(url_for("auth.email_setup"))

        if not _require_password_confirmation():
            return redirect(url_for("auth.email_setup"))
        ok, _ = mfa.verify_code(current_user, "email", "verify_email", request.form.get("code", ""))
        if not ok:
            record("mfa_setup_failed", current_user.id, "email")
            flash("Incorrect or expired code.", "error")
            return redirect(url_for("auth.email_setup"))
        current_user.email_verified = True
        current_user.email_2fa_enabled = True
        if not current_user.preferred_2fa_method:
            current_user.preferred_2fa_method = "email"
        first_factor = len(current_user.enabled_mfa_methods) == 1
        codes = mfa.generate_recovery_codes(current_user) if first_factor else None
        db.session.commit()
        record("mfa_enabled", current_user.id, "email")
        flash("E-mail two-factor authentication enabled.", "success")
        if codes:
            return render_template("auth/recovery_codes.html", codes=codes)
        return redirect(url_for("auth.security"))

    return render_template("auth/email_setup.html")


# ---- SMS codes

@bp.route("/settings/security/sms/setup", methods=["GET", "POST"])
@login_required
@code_send_limit
def sms_setup():
    if current_user.sms_2fa_enabled:
        flash("SMS codes are already enabled.", "info")
        return redirect(url_for("auth.security"))

    if request.method == "POST":
        action = request.form.get("action", "verify")
        if action == "send":
            try:
                phone = mfa.normalise_phone(request.form.get("phone", ""))
                other = User.query.filter(User.phone == phone, User.id != current_user.id, User.phone_verified.is_(True)).first()
                if other:
                    raise MFAError("That phone number is already in use.")
                session[PENDING_PHONE_KEY] = phone
                mfa.issue_code(current_user, "sms", "verify_phone", destination=phone)
                _flash_sent(f"We sent a code to {phone}.", "sms")
            except (MFAError, DeliveryError) as exc:
                flash(str(exc), "error")
            return redirect(url_for("auth.sms_setup"))

        phone = session.get(PENDING_PHONE_KEY)
        if not phone:
            flash("Please request a code first.", "error")
            return redirect(url_for("auth.sms_setup"))
        if not _require_password_confirmation():
            return redirect(url_for("auth.sms_setup"))
        ok, dest = mfa.verify_code(current_user, "sms", "verify_phone", request.form.get("code", ""))
        if not ok or dest != phone:
            record("mfa_setup_failed", current_user.id, "sms")
            flash("Incorrect or expired code.", "error")
            return redirect(url_for("auth.sms_setup"))
        session.pop(PENDING_PHONE_KEY, None)
        current_user.phone = phone
        current_user.phone_verified = True
        current_user.sms_2fa_enabled = True
        if not current_user.preferred_2fa_method:
            current_user.preferred_2fa_method = "sms"
        first_factor = len(current_user.enabled_mfa_methods) == 1
        codes = mfa.generate_recovery_codes(current_user) if first_factor else None
        db.session.commit()
        record("mfa_enabled", current_user.id, "sms")
        flash("SMS two-factor authentication enabled.", "success")
        if codes:
            return render_template("auth/recovery_codes.html", codes=codes)
        return redirect(url_for("auth.security"))

    return render_template("auth/sms_setup.html", pending_phone=session.get(PENDING_PHONE_KEY), current_phone=current_user.phone)


# ---- disable / recovery codes / devices / password

@bp.route("/settings/security/disable/<method>", methods=["POST"])
@login_required
def disable_method(method):
    if method not in current_user.enabled_mfa_methods:
        abort(404)
    if not _require_password_confirmation():
        return redirect(url_for("auth.security"))
    mfa.disable_method(current_user, method)
    db.session.commit()
    record("mfa_disabled", current_user.id, method)
    flash(f"{_label(method)} disabled.", "warning")
    return redirect(url_for("auth.security"))


@bp.route("/settings/security/recovery-codes", methods=["POST"])
@login_required
def regenerate_recovery_codes():
    if not current_user.mfa_enabled:
        abort(400)
    if not _require_password_confirmation():
        return redirect(url_for("auth.security"))
    codes = mfa.generate_recovery_codes(current_user)
    record("recovery_codes_regenerated", current_user.id)
    return render_template("auth/recovery_codes.html", codes=codes)


@bp.route("/settings/security/devices/revoke", methods=["POST"])
@login_required
def revoke_devices():
    n = mfa.revoke_trusted_devices(current_user)
    record("trusted_devices_revoked", current_user.id, f"{n} device(s)")
    flash("All remembered devices have been forgotten. You'll be asked for a code next time.", "info")
    resp = make_response(redirect(url_for("auth.security")))
    resp.delete_cookie(TRUSTED_DEVICE_COOKIE)
    return resp


@bp.route("/settings/security/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        if not _require_password_confirmation():
            return redirect(url_for("auth.change_password"))
        new = request.form.get("new_password", "")
        if new != request.form.get("confirm_password", ""):
            flash("New passwords do not match.", "error")
        elif (err := _validate_password(new, current_user.username, current_user.email)):
            flash(err, "error")
        else:
            user = current_user._get_current_object()
            user.set_password(new)
            db.session.commit()
            record("password_changed", user.id)
            try:
                send_password_changed_email(user.email)
            except DeliveryError:
                pass
            # Our own session must follow the new password stamp; everyone else is signed out.
            login_user(user)
            flash("Password updated. Other sessions have been signed out.", "success")
            return redirect(url_for("auth.security"))
        return redirect(url_for("auth.change_password"))
    return render_template("auth/change_password.html")
