"""
Social login routes: "Continue with Google / Apple / Facebook".

  GET  /oauth/<provider>/start         begin the flow (?next=, ?link=1 when logged in)
  GET  /oauth/<provider>/callback      provider redirects back here (Google, Facebook)
  POST /oauth/<provider>/callback      Apple's response_mode=form_post; bounced to GET
  POST /settings/security/oauth/<provider>/unlink

Policy
------
* Social login is a FIRST factor only - users with 2FA enabled still complete it.
* A social identity maps to a local user through OAuthAccount. New identities create a
  new user (e-mail must be provided by the provider), unless the e-mail already belongs
  to a local account: then we do NOT auto-link (classic takeover vector) - the user has
  to log in with their password first, after which the link is completed.
* Accounts created socially get an unusable password; they set one via "Forgot password".
  The last social identity cannot be unlinked until a password exists.
"""

from __future__ import annotations

import re
import secrets
import time

from flask import abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required

from clock import utcnow
from extensions import csrf, db
from models import OAuthAccount, User
from throttle import login_limit

from . import bp, mfa, oauth
from .audit import record
from .mfa import TRUSTED_DEVICE_COOKIE
from .oauth import LABELS, OAuthError
from .routes import _complete_login, _is_safe_url, _require_password_confirmation, _start_second_factor

PENDING_LINK_KEY = "pending_oauth_link"  # {'provider','subject','email','name','exp'}


@bp.app_context_processor
def _inject_oauth():
    return {
        "oauth_providers": oauth.enabled_providers,
        "oauth_label": lambda p: LABELS.get(p, p),
        "oauth_is_fake": oauth.is_fake,
    }


# ------------------------------------------------------------------ start

@bp.route("/oauth/<provider>/start")
@login_limit
def oauth_start(provider):
    if provider not in oauth.enabled_providers():
        abort(404)
    link = request.args.get("link") == "1" and current_user.is_authenticated
    if current_user.is_authenticated and not link:
        return redirect(url_for("dashboard"))
    next_url = request.args.get("next")
    try:
        url = oauth.begin(provider, next_url=next_url if _is_safe_url(next_url) else None, link=link)
    except OAuthError as exc:
        flash(str(exc), "error")
        return redirect(url_for("auth.security" if link else "auth.login"))
    record("oauth_start", current_user.id if link else None, f"{provider}{' (link)' if link else ''}")
    return redirect(url)


# --------------------------------------------------------------- callback

@bp.route("/oauth/<provider>/callback", methods=["GET", "POST"])
@csrf.exempt  # cross-site POST from Apple; `state` is the CSRF protection here
@login_limit
def oauth_callback(provider):
    if provider not in oauth.SUPPORTED:
        abort(404)
    if request.method == "POST":
        # Apple posts the result cross-site, so the SameSite=Lax session cookie isn't sent.
        # Bounce to a top-level GET on our origin (cookie included); the code is single-use.
        keep = {k: v for k, v in request.form.items() if k in ("code", "state", "error", "user")}
        return redirect(url_for("auth.oauth_callback", provider=provider, **keep), code=303)

    try:
        profile, flow = oauth.finish(provider, request.args)
    except OAuthError as exc:
        record("oauth_failed", None, f"{provider}: {exc}")
        flash(str(exc), "error")
        return redirect(url_for("auth.security") if current_user.is_authenticated else url_for("auth.login"))

    label = LABELS[provider]
    account = OAuthAccount.query.filter_by(provider=provider, provider_user_id=profile.subject).first()

    # ---- linking from the security page
    if flow.get("link"):
        if not current_user.is_authenticated:
            flash("Please log in first, then link your account.", "error")
            return redirect(url_for("auth.login"))
        if account is not None and account.user_id != current_user.id:
            record("oauth_link_conflict", current_user.id, provider)
            flash(f"That {label} identity is already linked to a different account.", "error")
        elif account is not None:
            flash(f"{label} is already linked to your account.", "info")
        else:
            _link(current_user._get_current_object(), profile)
            flash(f"{label} account linked. You can now sign in with it.", "success")
        return redirect(url_for("auth.security"))

    # ---- returning user
    if account is not None:
        account.last_login_at = utcnow()
        if profile.email:
            account.email = profile.email
        db.session.commit()
        return _login_via_oauth(account.user, provider, flow.get("next"))

    # ---- new identity
    if not profile.email:
        record("oauth_failed", None, f"{provider}: no e-mail shared")
        flash(f"{label} did not share an e-mail address with us. Please allow e-mail access or register with a password.", "error")
        return redirect(url_for("auth.login"))
    email = profile.email.lower()
    existing = User.query.filter_by(email=email).first()
    if existing is not None:
        # Never auto-link on e-mail alone: prove ownership of the local account first.
        session[PENDING_LINK_KEY] = {
            "provider": provider,
            "subject": profile.subject,
            "email": email,
            "name": profile.name,
            "exp": time.time() + 600,
        }
        record("oauth_link_requires_login", existing.id, provider)
        flash(
            f"An account with the e-mail {email} already exists. Log in with your password "
            f"(and second factor) to link your {label} identity to it.",
            "warning",
        )
        return redirect(url_for("auth.login"))

    user = User(
        username=_unique_username(email, profile.name),
        email=email,
        display_name=(profile.name or "")[:120] or None,
        role="both",
        email_verified=profile.email_verified,
    )
    user.set_unusable_password()
    db.session.add(user)
    db.session.commit()
    _link(user, profile)
    record("oauth_signup", user.id, provider)
    flash(f"Welcome! Your account was created with {label}. Add a second factor in Security settings.", "success")
    return _login_via_oauth(user, provider, flow.get("next"), new_user=True)


def _link(user: User, profile: oauth.Profile) -> OAuthAccount:
    account = OAuthAccount(
        user_id=user.id,
        provider=profile.provider,
        provider_user_id=profile.subject,
        email=profile.email,
        display_name=(profile.name or "")[:120] or None,
        last_login_at=utcnow(),
    )
    db.session.add(account)
    if profile.email and profile.email_verified and profile.email.lower() == user.email.lower():
        user.email_verified = True
    db.session.commit()
    record("oauth_linked", user.id, profile.provider)
    return account


def _login_via_oauth(user: User, provider: str, next_url: str | None, new_user: bool = False):
    if user.is_locked:
        record("login_blocked_locked", user.id, f"via {provider}")
        flash("This account is temporarily locked. Try again later.", "error")
        return redirect(url_for("auth.login"))
    record("oauth_login", user.id, provider)
    if user.mfa_enabled and not mfa.is_trusted_device(user, request.cookies.get(TRUSTED_DEVICE_COOKIE)):
        session.clear()
        _start_second_factor(user, "login", next=next_url)
        return redirect(url_for("auth.two_factor"))
    if user.mfa_enabled:
        record("mfa_skipped_trusted_device", user.id)
    return _complete_login(user, next_url=next_url)


def _unique_username(email: str, name: str | None) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]", "", (email.split("@")[0] or "user"))[:60] or "user"
    if len(base) < 3:
        base = (base + "user")[:60]
    candidate = base
    while User.query.filter_by(username=candidate).first() is not None:
        candidate = f"{base}-{secrets.token_hex(2)}"
    return candidate


# ------------------------------------------------- complete a pending link

def complete_pending_link(user: User, stash: dict | None) -> None:
    """Called after a successful password (+2FA) login; links the identity saved in the session."""
    if not stash or stash.get("exp", 0) < time.time():
        return
    if stash.get("email", "").lower() != user.email.lower():
        record("oauth_link_mismatch", user.id, stash.get("provider"))
        return
    if OAuthAccount.query.filter_by(provider=stash["provider"], provider_user_id=stash["subject"]).first():
        return
    _link(user, oauth.Profile(stash["provider"], stash["subject"], stash["email"], True, stash.get("name")))
    flash(f"{LABELS.get(stash['provider'], stash['provider'])} account linked. You can now sign in with it.", "success")


# ------------------------------------------------------------------ unlink

@bp.route("/settings/security/oauth/<provider>/unlink", methods=["POST"])
@login_required
def oauth_unlink(provider):
    account = OAuthAccount.query.filter_by(user_id=current_user.id, provider=provider).first()
    if account is None:
        abort(404)
    if not current_user.password_is_usable and len(current_user.oauth_accounts) == 1:
        flash("Set a password first (use 'Forgot password?' on the login page) - otherwise you could not sign in anymore.", "error")
        return redirect(url_for("auth.security"))
    if not _require_password_confirmation():
        return redirect(url_for("auth.security"))
    db.session.delete(account)
    db.session.commit()
    record("oauth_unlinked", current_user.id, provider)
    flash(f"{LABELS.get(provider, provider)} account unlinked.", "warning")
    return redirect(url_for("auth.security"))


@bp.route("/oauth/providers")
def oauth_providers_page():
    """Small helper page listing configured providers (handy on phones / for the smoke test)."""
    return render_template("auth/oauth_providers.html", providers=oauth.enabled_providers(), fake=oauth.is_fake(),
                           redirect_uris={p: oauth.redirect_uri(p) for p in oauth.enabled_providers()},
                           client_ids={p: oauth.client_id(p) for p in oauth.enabled_providers()},
                           cryptography=oauth.jwt_min.HAVE_CRYPTOGRAPHY, app_name=current_app.config["APP_NAME"])
