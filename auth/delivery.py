"""
Pluggable delivery backends for one-time codes.

Backends are selected with EMAIL_BACKEND / SMS_BACKEND:

  console  - logs the message and appends it to <instance>/auth_outbox.jsonl; readable
             from any device at /dev/outbox (development / manual testing)
  memory   - keeps messages in a list (automated tests)
  smtp     - e-mail through SMTP_* settings (stdlib smtplib). Works against a real
             server or against scripts/fake_smtp_server.py
  twilio   - SMS through the Twilio REST API (stdlib urllib, no SDK). Works against
             the real API or against scripts/fake_twilio_server.py (TWILIO_API_BASE)

No backend needs anything outside the standard library.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import smtplib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from email.message import EmailMessage

from flask import current_app

from clock import utcnow

log = logging.getLogger("auth.delivery")


class DeliveryError(Exception):
    """Raised when a code could not be delivered."""


@dataclass
class OutboundMessage:
    channel: str  # email | sms
    to: str
    subject: str
    body: str
    sent_at: str


def outbox_path() -> str:
    path = current_app.config.get("OUTBOX_PATH") or "auth_outbox.jsonl"
    if not os.path.isabs(path):
        path = os.path.join(current_app.instance_path, path)
    return path


class ConsoleBackend:
    def send(self, msg: OutboundMessage) -> None:
        log.warning("[%s -> %s] %s: %s", msg.channel.upper(), msg.to, msg.subject, msg.body)
        path = outbox_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(msg)) + "\n")

    def recent(self, limit: int = 20) -> list[OutboundMessage]:
        path = outbox_path()
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            lines = [ln for ln in fh.read().splitlines() if ln.strip()]
        return [OutboundMessage(**json.loads(ln)) for ln in lines[-limit:]][::-1]

    def clear(self) -> None:
        path = outbox_path()
        if os.path.exists(path):
            os.remove(path)


class MemoryBackend:
    def __init__(self) -> None:
        self.messages: list[OutboundMessage] = []

    def send(self, msg: OutboundMessage) -> None:
        self.messages.append(msg)

    def last_for(self, to: str) -> OutboundMessage | None:
        for m in reversed(self.messages):
            if m.to == to:
                return m
        return None

    def recent(self, limit: int = 20) -> list[OutboundMessage]:
        return self.messages[-limit:][::-1]

    def clear(self) -> None:
        self.messages.clear()


class SMTPBackend:
    def send(self, msg: OutboundMessage) -> None:
        cfg = current_app.config
        email = EmailMessage()
        email["From"] = cfg["MAIL_FROM"]
        email["To"] = msg.to
        email["Subject"] = msg.subject
        email.set_content(msg.body)
        try:
            with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=15) as smtp:
                if cfg["SMTP_USE_TLS"]:
                    smtp.starttls()
                if cfg["SMTP_USE_AUTH"]:
                    smtp.login(cfg["SMTP_USERNAME"], cfg["SMTP_PASSWORD"] or "")
                smtp.send_message(email)
        except (smtplib.SMTPException, OSError) as exc:
            log.error("SMTP delivery failed: %s", exc)
            raise DeliveryError("E-mail could not be sent") from exc


class TwilioBackend:
    def send(self, msg: OutboundMessage) -> None:
        cfg = current_app.config
        sid, token, sender = cfg["TWILIO_ACCOUNT_SID"], cfg["TWILIO_AUTH_TOKEN"], cfg["TWILIO_FROM_NUMBER"]
        if not all((sid, token, sender)):
            raise DeliveryError("SMS backend is not configured")
        url = f"{cfg['TWILIO_API_BASE'].rstrip('/')}/2010-04-01/Accounts/{sid}/Messages.json"
        data = urllib.parse.urlencode({"To": msg.to, "From": sender, "Body": msg.body}).encode()
        auth = base64.b64encode(f"{sid}:{token}".encode()).decode()
        req = urllib.request.Request(url, data=data, headers={"Authorization": f"Basic {auth}"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
                if resp.status >= 300:
                    raise DeliveryError(f"SMS provider returned {resp.status}")
        except urllib.error.HTTPError as exc:
            log.error("Twilio delivery failed: HTTP %s", exc.code)
            raise DeliveryError("SMS could not be sent") from exc
        except OSError as exc:
            log.error("Twilio delivery failed: %s", exc)
            raise DeliveryError("SMS could not be sent") from exc


_BACKENDS = {
    "console": ConsoleBackend,
    "memory": MemoryBackend,
    "smtp": SMTPBackend,
    "twilio": TwilioBackend,
}


def get_backend(channel: str):
    """Return the (cached per-app) backend instance for a channel."""
    key = "EMAIL_BACKEND" if channel == "email" else "SMS_BACKEND"
    name = current_app.config.get(key, "console")
    if name not in _BACKENDS:
        raise DeliveryError(f"Unknown {key} '{name}' (choose: {', '.join(_BACKENDS)})")
    cache = current_app.extensions.setdefault("auth_delivery", {})
    if channel not in cache:
        cache[channel] = _BACKENDS[name]()
    return cache[channel]


def recent_messages(limit: int = 20) -> list[OutboundMessage]:
    """
    Messages for the fake inbox (/dev/outbox): everything in the outbox file (written by
    the console backend AND by scripts/fake_smtp_server.py / fake_twilio_server.py) plus
    anything held by memory backends.
    """
    msgs: list[OutboundMessage] = ConsoleBackend().recent(limit)
    seen = {id(None)}
    for channel in ("email", "sms"):
        backend = get_backend(channel)
        if id(backend) in seen or not isinstance(backend, MemoryBackend):
            continue
        seen.add(id(backend))
        msgs.extend(backend.recent(limit))
    msgs.sort(key=lambda m: m.sent_at, reverse=True)
    return msgs[:limit]


def clear_messages() -> None:
    ConsoleBackend().clear()
    for channel in ("email", "sms"):
        backend = get_backend(channel)
        if isinstance(backend, MemoryBackend):
            backend.clear()


STUB_BACKENDS = ("console", "memory")


def is_stub(channel: str) -> bool:
    """True when this channel is served by a fake backend (nothing is really delivered)."""
    key = "EMAIL_BACKEND" if channel == "email" else "SMS_BACKEND"
    return current_app.config.get(key, "console") in STUB_BACKENDS


def stub_hint(channel: str) -> str | None:
    """
    Plain-text note for the user telling them where a stubbed e-mail/SMS actually went.
    None when a real provider is configured.
    """
    if not is_stub(channel):
        return None
    what = "e-mail" if channel == "email" else "SMS"
    places = [f"the server console/log (look for a line starting with [{channel.upper()} -> ...])"]
    if current_app.config.get("EMAIL_BACKEND" if channel == "email" else "SMS_BACKEND") == "console":
        places.append(f"the file {outbox_path()}")
    if current_app.config.get("ENABLE_DEV_TOOLS"):
        places.append("the fake inbox page at /dev/outbox")
    return f"TEST MODE: no real {what} is sent. Find it in " + ", or ".join(places) + "."


def send_code(channel: str, to: str, code: str, purpose: str) -> None:
    app_name = current_app.config["APP_NAME"]
    ttl_min = current_app.config["OTP_CODE_TTL_SECONDS"] // 60
    purpose_text = {
        "login": "sign in",
        "verify_email": "verify your e-mail address",
        "verify_phone": "verify your phone number",
    }.get(purpose, purpose)
    if channel == "email":
        subject = f"{app_name}: your verification code"
        body = (
            f"Your {app_name} code to {purpose_text} is: {code}\n\n"
            f"It expires in {ttl_min} minutes. If you did not request this, "
            f"ignore this message and consider changing your password."
        )
    else:
        subject = "sms"
        body = f"{app_name} code: {code} (expires in {ttl_min} min). Never share this code."
    send_message(channel, to, subject, body)


def send_message(channel: str, to: str, subject: str, body: str) -> None:
    msg = OutboundMessage(channel=channel, to=to, subject=subject, body=body, sent_at=utcnow().isoformat())
    get_backend(channel).send(msg)


def send_password_reset_email(to: str, link: str) -> None:
    app_name = current_app.config["APP_NAME"]
    ttl_min = current_app.config["PASSWORD_RESET_TTL_SECONDS"] // 60
    send_message(
        "email",
        to,
        f"{app_name}: reset your password",
        f"Someone (hopefully you) asked to reset the password for your {app_name} account.\n\n"
        f"Open this link within {ttl_min} minutes to choose a new password:\n{link}\n\n"
        "If two-factor authentication is enabled you'll be asked for a code as well.\n"
        "If you did not request this, you can ignore this e-mail - your password will not change.",
    )


def send_password_changed_email(to: str) -> None:
    app_name = current_app.config["APP_NAME"]
    send_message(
        "email",
        to,
        f"{app_name}: your password was changed",
        f"The password for your {app_name} account was just changed and all other sessions and "
        "remembered devices were signed out.\n\n"
        "If this wasn't you, reset your password immediately and review your security settings.",
    )
