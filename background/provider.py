"""
Background-check provider abstraction + the offline FAKE provider.

A real integration (Checkr, Sterling, HireRight, ...) works like this, and so does the stub:

  our server ──(applicant: legal name, date of birth, [licence], consent)──▶ provider.submit()
             ◀── report {ref, status, screens}   (status is often "pending" at first)
  provider  ──(signed webhook: report.completed {ref, status, screens})──▶ POST /background-check/webhook
             our server verifies the HMAC signature and stores the result.

The FAKE provider never leaves the process and decides the outcome from the applicant data,
like the test cards of the fake payment vault (see README "Test identities"):

  legal LAST name contains   result
  ------------------------   ----------------------------------------------------------------
  "consider"                 criminal screen = consider       -> status consider (manual review)
  "pending"                  every screen pending             -> status pending (complete it from
                                                                 /dev/background-checks or via the webhook)
  "unverified"               identity screen = unverified     -> status unverified (user may resubmit)
  licence number contains
  "SUSPENDED"                motor_vehicle screen = consider  -> status consider
  anything else              every screen clear               -> status clear

All names, references and keys produced here are DUMMY values (bgc_DUMMY_...).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import date

from flask import current_app

from models import BACKGROUND_CHECK_SCREENS


class BackgroundCheckError(Exception):
    """The provider could not take the request. str(exc) is user-facing."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        self.message = message or {
            "not_configured": ("Real background checks are not configured (BACKGROUND_CHECK_PROVIDER=real needs a "
                               "provider implementation). Use BACKGROUND_CHECK_PROVIDER=fake for development."),
            "invalid_api_key": "The background-check provider rejected our API key.",
        }.get(code, f"The background check could not be submitted ({code}).")
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class Applicant:
    candidate_ref: str  # our stable id for the person at the provider (cand_DUMMY_<user id>)
    first_name: str
    last_name: str
    date_of_birth: date
    package: str  # standard | driver
    licence_number: str | None = None
    licence_region: str | None = None


@dataclass(frozen=True)
class Report:
    ref: str
    status: str  # pending | clear | consider | unverified
    screens: dict[str, str] = field(default_factory=dict)
    note: str | None = None


def overall_status(screens: dict[str, str]) -> str:
    """The report status is the worst screen result."""
    values = set(screens.values())
    for status in ("unverified", "consider", "pending"):
        if status in values:
            return status
    return "clear"


NOTES = {
    "clear": "No records found.",
    "consider": "The report contains information that needs review by our Trust & Safety team.",
    "unverified": "We could not verify your identity with the details provided. Check them and submit again.",
    "pending": "The provider is still working on your report.",
}


# ------------------------------------------------------------------ interface

class BackgroundCheckProvider:
    name = "abstract"

    def submit(self, applicant: Applicant) -> Report:
        raise NotImplementedError  # pragma: no cover


class FakeBackgroundCheckProvider(BackgroundCheckProvider):
    """Offline stub. Deterministic: the outcome depends only on the applicant data."""

    name = "fake"

    def submit(self, applicant: Applicant) -> Report:
        if not current_app.config.get("BACKGROUND_CHECK_API_KEY"):
            raise BackgroundCheckError("invalid_api_key")
        screens = {s: "clear" for s in BACKGROUND_CHECK_SCREENS[applicant.package]}
        last = applicant.last_name.lower()
        if "pending" in last:
            screens = {s: "pending" for s in screens}
        if "consider" in last:
            screens["criminal"] = "consider"
        if "unverified" in last:
            screens["identity"] = "unverified"
        if applicant.package == "driver" and "SUSPENDED" in (applicant.licence_number or "").upper():
            screens["motor_vehicle"] = "consider"
        status = overall_status(screens)
        return Report(ref=f"bgc_DUMMY_{secrets.token_hex(8)}", status=status, screens=screens, note=NOTES[status])


class NotConfiguredProvider(BackgroundCheckProvider):
    """BACKGROUND_CHECK_PROVIDER=real without an implementation: fail loudly instead of pretending."""

    name = "real (not configured)"

    def submit(self, applicant: Applicant) -> Report:
        raise BackgroundCheckError("not_configured")


_BACKENDS = {"fake": FakeBackgroundCheckProvider, "real": NotConfiguredProvider}


def get_provider() -> BackgroundCheckProvider:
    mode = current_app.config.get("BACKGROUND_CHECK_PROVIDER", "fake")
    return _BACKENDS.get(mode, NotConfiguredProvider)()


# ------------------------------------------------------------------ webhooks

SIGNATURE_HEADER = "X-Background-Check-Signature"


def sign_webhook(body: bytes, secret: str | None = None) -> str:
    """`sha256=<hex hmac>` of the raw request body (what the provider sends in SIGNATURE_HEADER)."""
    key = (secret or current_app.config.get("BACKGROUND_CHECK_WEBHOOK_SECRET") or "").encode()
    return "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()


def verify_webhook(body: bytes, signature: str | None) -> bool:
    if not signature or not current_app.config.get("BACKGROUND_CHECK_WEBHOOK_SECRET"):
        return False
    return hmac.compare_digest(sign_webhook(body), signature.strip())


def webhook_body(ref: str, status: str, screens: dict[str, str]) -> bytes:
    """The JSON document the (fake) provider posts when a report completes."""
    return json.dumps({"type": "report.completed", "data": {"ref": ref, "status": status, "screens": screens}},
                      separators=(",", ":"), sort_keys=True).encode()
