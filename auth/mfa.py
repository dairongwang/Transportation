"""
Core multi-factor authentication logic.

Three second factors are supported:
  * totp  - authenticator app (RFC 6238, e.g. Google Authenticator, Authy, 1Password)
  * email - 6-digit one-time code sent to the verified e-mail address
  * sms   - 6-digit one-time code sent to the verified phone number

Plus:
  * recovery codes - single-use backup codes, shown once at generation time
  * trusted devices - optional 30-day "remember this browser" token

All verification paths are throttled and all secrets are hashed/encrypted at rest.
"""

from __future__ import annotations

import base64
import re
from datetime import timedelta

from flask import current_app

from clock import utcnow
from extensions import db
from models import OneTimeCode, PasswordResetToken, RecoveryCode, TrustedDevice, User

from . import crypto, totp
from .delivery import send_code

try:  # pure-Python, but keep it optional: the manual key always works without it
    import qrcode
    import qrcode.image.svg

    HAVE_QRCODE = True
except ImportError:  # pragma: no cover
    qrcode = None  # type: ignore[assignment]
    HAVE_QRCODE = False

E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")


class MFAError(Exception):
    """User-presentable MFA failure."""


# =============================================================== TOTP (app)

def totp_generate_secret() -> str:
    return totp.random_base32()


def totp_provisioning_uri(user: User, secret: str) -> str:
    return totp.provisioning_uri(secret, account=user.email, issuer=current_app.config["APP_NAME"])


def totp_qr_data_uri(uri: str) -> str | None:
    """
    Render the provisioning URI as an inline SVG (pure Python, no Pillow, never hits a
    third-party QR service). Returns None if the optional `qrcode` package is missing;
    the setup page then shows the manual key only.
    """
    if not HAVE_QRCODE:
        return None
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    svg = img.to_string(encoding="unicode") if hasattr(img, "to_string") else img.to_string().decode()
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()


def _totp_verify_with_secret(secret: str, code: str, user: User | None = None) -> bool:
    """Verify a code within the drift window; record the matched time step to block replays."""
    counter = totp.verify(secret, code, window=current_app.config["TOTP_VALID_WINDOW"])
    if counter is None:
        return False
    if user is not None:
        if user.totp_last_counter is not None and counter <= user.totp_last_counter:
            return False  # replay of a code that was already accepted
        user.totp_last_counter = counter
    return True


def totp_confirm_setup(user: User, pending_secret: str, code: str) -> bool:
    """Verify the first code against a not-yet-saved secret; on success persist it."""
    if not _totp_verify_with_secret(pending_secret, code):
        return False
    user.totp_secret_enc = crypto.encrypt_secret(pending_secret)
    user.totp_enabled = True
    user.totp_last_counter = totp.counter_for()
    if not user.preferred_2fa_method:
        user.preferred_2fa_method = "totp"
    return True


def totp_verify(user: User, code: str) -> bool:
    if not user.totp_enabled or not user.totp_secret_enc:
        return False
    secret = crypto.decrypt_secret(user.totp_secret_enc)
    if not secret:
        current_app.logger.error("Could not decrypt TOTP secret for user %s", user.id)
        return False
    return _totp_verify_with_secret(secret, code, user)


def totp_disable(user: User) -> None:
    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_counter = None
    _fix_preferred(user)


# ====================================================== one-time codes (email/sms)

def _destination_for(user: User, channel: str, override: str | None = None) -> str:
    if override:
        return override
    if channel == "email":
        return user.email
    if channel == "sms":
        if not user.phone:
            raise MFAError("No phone number on file.")
        return user.phone
    raise MFAError("Unknown channel.")


def issue_code(user: User, channel: str, purpose: str, destination: str | None = None) -> None:
    """
    Generate, store (hashed) and deliver a one-time code.

    Raises MFAError if rate limits are hit. Any previously active codes for the
    same user/channel/purpose are invalidated.
    """
    cfg = current_app.config
    dest = _destination_for(user, channel, destination)
    now = utcnow()

    recent = (
        OneTimeCode.query.filter_by(user_id=user.id, channel=channel, purpose=purpose)
        .filter(OneTimeCode.created_at > now - timedelta(hours=1))
        .order_by(OneTimeCode.created_at.desc())
        .all()
    )
    if len(recent) >= cfg["OTP_MAX_SENDS_PER_HOUR"]:
        raise MFAError("Too many codes requested. Please try again later.")
    if recent and (now - recent[0].created_at).total_seconds() < cfg["OTP_RESEND_COOLDOWN_SECONDS"]:
        wait = cfg["OTP_RESEND_COOLDOWN_SECONDS"] - int((now - recent[0].created_at).total_seconds())
        raise MFAError(f"Please wait {wait}s before requesting another code.")

    # Invalidate older live codes for this purpose.
    for old in recent:
        if old.consumed_at is None:
            old.consumed_at = now

    code = crypto.generate_numeric_code(cfg["OTP_CODE_LENGTH"])
    db.session.add(
        OneTimeCode(
            user_id=user.id,
            channel=channel,
            purpose=purpose,
            destination=dest,
            code_hash=crypto.keyed_hash(f"{user.id}:{channel}:{purpose}:{code}"),
            expires_at=now + timedelta(seconds=cfg["OTP_CODE_TTL_SECONDS"]),
        )
    )
    db.session.commit()
    send_code(channel, dest, code, purpose)


def verify_code(user: User, channel: str, purpose: str, code: str) -> tuple[bool, str | None]:
    """
    Check a submitted code. Returns (ok, destination).

    Wrong attempts are counted; after OTP_MAX_ATTEMPTS the code is burnt and a
    new one must be requested.
    """
    code = code.strip().replace(" ", "")
    record = (
        OneTimeCode.query.filter_by(user_id=user.id, channel=channel, purpose=purpose, consumed_at=None)
        .order_by(OneTimeCode.created_at.desc())
        .first()
    )
    if record is None or record.is_expired:
        return False, None

    record.attempts += 1
    if crypto.keyed_hash_matches(f"{user.id}:{channel}:{purpose}:{code}", record.code_hash):
        record.consumed_at = utcnow()
        db.session.commit()
        return True, record.destination

    if record.attempts >= current_app.config["OTP_MAX_ATTEMPTS"]:
        record.consumed_at = utcnow()  # burn it
    db.session.commit()
    return False, None


# ============================================================ recovery codes

def generate_recovery_codes(user: User) -> list[str]:
    """Replace all existing recovery codes. Returns the plaintext codes (show once!)."""
    RecoveryCode.query.filter_by(user_id=user.id).delete()
    codes = [crypto.generate_recovery_code() for _ in range(current_app.config["RECOVERY_CODE_COUNT"])]
    for c in codes:
        db.session.add(RecoveryCode(user_id=user.id, code_hash=crypto.keyed_hash(f"rc:{user.id}:{c}")))
    db.session.commit()
    return codes


def verify_recovery_code(user: User, raw: str) -> bool:
    candidate = crypto.normalise_recovery_code(raw)
    if not candidate:
        return False
    matched = None
    # Iterate all (not .filter_by(code_hash=...)) so timing does not leak which index matched.
    for rc in RecoveryCode.query.filter_by(user_id=user.id, used_at=None).all():
        if crypto.keyed_hash_matches(f"rc:{user.id}:{candidate}", rc.code_hash):
            matched = rc
    if matched is None:
        return False
    matched.used_at = utcnow()
    db.session.commit()
    return True


def clear_recovery_codes(user: User) -> None:
    RecoveryCode.query.filter_by(user_id=user.id).delete()


# ============================================================ trusted devices

TRUSTED_DEVICE_COOKIE = "su_trusted_device"


def create_trusted_device(user: User, user_agent: str | None, ip: str | None) -> str:
    token = crypto.generate_device_token()
    days = current_app.config["TRUSTED_DEVICE_DAYS"]
    db.session.add(
        TrustedDevice(
            user_id=user.id,
            token_hash=crypto.keyed_hash(f"td:{token}"),
            user_agent=(user_agent or "")[:255],
            ip_address=(ip or "")[:45],
            expires_at=utcnow() + timedelta(days=days),
        )
    )
    db.session.commit()
    return token


def is_trusted_device(user: User, token: str | None) -> bool:
    if not token:
        return False
    candidates = crypto.keyed_hash_candidates(f"td:{token}")
    device = TrustedDevice.query.filter(
        TrustedDevice.user_id == user.id, TrustedDevice.token_hash.in_(candidates)
    ).first()
    if device is None or not device.is_valid:
        return False
    device.last_used_at = utcnow()
    if device.token_hash != candidates[0]:
        device.token_hash = candidates[0]  # re-key to the current MFA_ENCRYPTION_KEY
    db.session.commit()
    return True


def revoke_trusted_devices(user: User) -> int:
    n = TrustedDevice.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return n


# ============================================================ password reset

def issue_password_reset(user: User, ip: str | None) -> str:
    """
    Create a single-use reset token (hashed at rest) and return the raw token for the
    e-mail link. Raises MFAError when the per-user hourly cap is hit.
    """
    cfg = current_app.config
    now = utcnow()
    recent = PasswordResetToken.query.filter(
        PasswordResetToken.user_id == user.id, PasswordResetToken.created_at > now - timedelta(hours=1)
    ).count()
    if recent >= cfg["PASSWORD_RESET_MAX_PER_HOUR"]:
        raise MFAError("Too many reset requests. Please try again later.")
    # Only one live token at a time.
    for old in PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).all():
        old.used_at = now
    raw = crypto.generate_token()
    db.session.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=crypto.keyed_hash(f"pr:{raw}"),
            expires_at=now + timedelta(seconds=cfg["PASSWORD_RESET_TTL_SECONDS"]),
            ip_address=(ip or "")[:45],
        )
    )
    db.session.commit()
    return raw


def load_password_reset(raw: str) -> PasswordResetToken | None:
    """Return the live token record for a raw token, or None."""
    if not raw or len(raw) > 200:
        return None
    record = PasswordResetToken.query.filter(
        PasswordResetToken.token_hash.in_(crypto.keyed_hash_candidates(f"pr:{raw}"))
    ).first()
    if record is None or not record.is_usable:
        return None
    return record


def complete_password_reset(record: PasswordResetToken, new_password: str) -> None:
    """Set the new password and invalidate everything that trusted the old one."""
    user = record.user
    user.set_password(new_password)  # bumps password_stamp -> all existing sessions die
    user.reset_login_failures()
    record.used_at = utcnow()
    for other in PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).all():
        other.used_at = utcnow()
    TrustedDevice.query.filter_by(user_id=user.id).delete()
    db.session.commit()


# =================================================================== helpers

def normalise_phone(raw: str) -> str:
    cleaned = re.sub(r"[\s\-().]", "", raw or "")
    if not E164_RE.match(cleaned):
        raise MFAError("Phone number must be in international format, e.g. +15551234567.")
    return cleaned


def _fix_preferred(user: User) -> None:
    if user.preferred_2fa_method not in user.enabled_mfa_methods:
        user.preferred_2fa_method = user.enabled_mfa_methods[0] if user.enabled_mfa_methods else None
    if not user.mfa_enabled:
        # No factors left -> recovery codes and trusted devices are meaningless.
        clear_recovery_codes(user)
        TrustedDevice.query.filter_by(user_id=user.id).delete()


def disable_method(user: User, method: str) -> None:
    if method == "totp":
        totp_disable(user)
    elif method == "email":
        user.email_2fa_enabled = False
        _fix_preferred(user)
    elif method == "sms":
        user.sms_2fa_enabled = False
        _fix_preferred(user)
    else:
        raise MFAError("Unknown method.")


def purge_expired() -> None:
    """Housekeeping: delete stale one-time codes and expired trusted devices."""
    cutoff = utcnow() - timedelta(days=1)
    OneTimeCode.query.filter(OneTimeCode.expires_at < cutoff).delete()
    PasswordResetToken.query.filter(PasswordResetToken.expires_at < cutoff).delete()
    TrustedDevice.query.filter(TrustedDevice.expires_at < utcnow()).delete()
    db.session.commit()
