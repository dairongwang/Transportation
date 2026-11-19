"""
Background-check rules: who has passed, who may drive, submitting a check, disputes,
applying the provider's result (webhook) and manager decisions (admin dashboard).

Clearance rule
--------------
A user's standing is decided by their most recent DECISIVE check (status clear, consider or
rejected, and not held for review); pending and unverified checks say nothing about the person
yet, and neither does a dispute re-check until a manager has decided the dispute:

  passed     decisive check is clear and not expired (BACKGROUND_CHECK_VALID_DAYS)
  can_drive  passed AND that check used the "driver" package (adds the motor-vehicle-record
             screen and BACKGROUND_CHECK_MIN_DRIVER_AGE)

Disputes
--------
A REJECTED user may dispute (BACKGROUND_CHECK_MAX_DISPUTES times, default once): they explain
why and may correct their details; the dispute escalates to another background check (the
"re-check", held for review) and then to a manager in the admin dashboard, who sees the
statement, the original report and the re-check and decides approve (-> clear) or reject
(final). The re-check alone never grants access.

Only users who passed may use the app (background/__init__.py installs the gate). When a
user stops passing (adverse result, rejection, expiry) their driving is switched off right
away: they go offline, pending ride requests are declined, accepted rides are handed back.
"""

from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass
from datetime import date, timedelta

from flask import current_app

from clock import utcnow
from extensions import db
from models import BACKGROUND_CHECK_STATUSES, BackgroundCheck, BackgroundDispute, User

from . import live
from .provider import NOTES, Applicant, get_provider, overall_status

log = logging.getLogger("background")


class BackgroundCheckInputError(ValueError):
    """The submitted form / decision is not acceptable. str(exc) is user-facing."""


class DecisionConflictError(BackgroundCheckInputError):
    """The decision is not possible in the report's / dispute's current state (HTTP 409)."""


# ------------------------------------------------------------------ config

def required() -> bool:
    return bool(current_app.config.get("BACKGROUND_CHECK_REQUIRED", True))


def _valid_days() -> int:
    return int(current_app.config.get("BACKGROUND_CHECK_VALID_DAYS", 365) or 0)


def max_disputes() -> int:
    return max(0, int(current_app.config.get("BACKGROUND_CHECK_MAX_DISPUTES", 1)))


def min_age(package: str) -> int:
    if package == "driver":
        return int(current_app.config.get("BACKGROUND_CHECK_MIN_DRIVER_AGE", 21))
    return int(current_app.config.get("BACKGROUND_CHECK_MIN_AGE", 18))


def may_drive(user: User) -> bool:
    """Roles that can drive (and therefore may ask for the driver package)."""
    return user.role != "buyer"


def candidate_ref(user_id: int) -> str:
    """Our stable id for the person at the provider."""
    return f"cand_DUMMY_{user_id}"


# ------------------------------------------------------------------ standing

@dataclass
class Clearance:
    required: bool
    passed: bool
    can_drive: bool
    state: str  # not_required | not_started | pending | unverified | clear | expired | consider | rejected | disputed
    latest: BackgroundCheck | None
    decisive: BackgroundCheck | None
    pending: BackgroundCheck | None
    can_submit: bool
    message: str
    can_dispute: bool = False
    dispute: BackgroundDispute | None = None  # the most recent dispute (open or decided)

    def as_dict(self) -> dict:
        d = self.decisive or self.latest
        return {
            "required": self.required, "passed": self.passed, "can_drive": self.can_drive, "state": self.state,
            "can_submit": self.can_submit, "can_dispute": self.can_dispute, "message": self.message,
            "package": d.package if d else None,
            "status": d.status if d else None,
            "expires_at": d.expires_at.isoformat() if d is not None and d.expires_at else None,
            "pending_check": self.pending is not None,
            "dispute": None if self.dispute is None else {
                "id": self.dispute.id, "status": self.dispute.status, "decision_note": self.dispute.decision_note,
                "created_at": self.dispute.created_at.isoformat(),
                "decided_at": self.dispute.decided_at.isoformat() if self.dispute.decided_at else None,
            },
        }


MESSAGES = {
    "not_required": "Background checks are switched off (BACKGROUND_CHECK_REQUIRED=false).",
    "not_started": "Complete a background check to start using ServiceUber.",
    "pending": "Your background check is in progress. You can use ServiceUber as soon as it comes back clear.",
    "unverified": NOTES["unverified"],
    "clear": "Background check passed.",
    "expired": "Your background check has expired. Submit a new one to keep using ServiceUber.",
    "consider": "Your background check needs review by our Trust & Safety team. You cannot use ServiceUber until it is approved.",
    "rejected": "Your background check did not pass. Your account cannot use ServiceUber.",
    "disputed": ("Your dispute is being handled: a new background check is run and a manager will review it. "
                 "We will e-mail you the decision."),
}


def _decisive(checks: list[BackgroundCheck]) -> BackgroundCheck | None:
    return next((c for c in reversed(checks) if c.is_decisive), None)


def disputes_used(user: User) -> int:
    return len(user.background_disputes)


def open_dispute(user: User) -> BackgroundDispute | None:
    return next((d for d in reversed(user.background_disputes) if d.is_open), None)


def clearance(user: User) -> Clearance:
    """Everything the gate, the pages and the JSON API need to know about a user's standing."""
    if not required():
        return Clearance(False, True, True, "not_required", None, None, None, False, MESSAGES["not_required"])
    checks = sorted((c for c in user.background_checks if not c.held_for_review), key=lambda c: c.id)
    latest = checks[-1] if checks else None
    decisive = _decisive(checks)
    pending = next((c for c in reversed(checks) if c.status == "pending"), None)
    disputes = list(user.background_disputes)
    last_dispute = disputes[-1] if disputes else None
    current_dispute = open_dispute(user)

    if decisive is None:
        state = "pending" if pending else ("unverified" if latest is not None and latest.status == "unverified" else "not_started")
    elif decisive.status == "clear":
        state = "expired" if decisive.is_expired else "clear"
    elif decisive.status == "rejected" and current_dispute is not None:
        state = "disputed"
    else:
        state = decisive.status
    passed = state == "clear"
    can_drive = passed and decisive.covers_driving

    if pending is not None or state in ("consider", "rejected", "disputed"):
        can_submit = False
    elif state == "clear":  # only to add the driving screen
        can_submit = not decisive.covers_driving and may_drive(user)
    else:
        can_submit = True
    can_dispute = state == "rejected" and disputes_used(user) < max_disputes()

    message = MESSAGES[state]
    if state == "clear" and pending is not None:
        message += " A newer check is in progress."
    elif state == "clear" and not can_drive and may_drive(user):
        message += " To drive, add your driving licence (driver background check)."
    elif state == "rejected":
        message += " You can raise a dispute on the background-check page." if can_dispute else " This decision is final."
    return Clearance(True, passed, can_drive, state, latest, decisive, pending, can_submit, message,
                     can_dispute, last_dispute)


def is_cleared(user) -> bool:
    return user is not None and clearance(user).passed


def passed_user_ids(user_ids) -> set[int]:
    """
    Batch / fast version of clearance(user).passed: the latest decisive check (clear / consider /
    rejected, not held for a manager) is clear and not expired. (An open dispute only matters when
    the decisive check is a rejection, i.e. not passed anyway.) One light query, no ORM objects -
    used by the gate on every request. tests/test_load_optimisations.py keeps it identical to clearance().
    """
    from sqlalchemy import select

    ids = {int(u) for u in user_ids if u is not None}
    if not ids:
        return set()
    if not required():
        return ids
    t = BackgroundCheck.__table__
    now = utcnow()
    decisive: dict[int, tuple] = {}
    for user_id, status, expires_at in db.session.execute(
        select(t.c.user_id, t.c.status, t.c.expires_at)
        .where(t.c.user_id.in_(ids), t.c.status.in_(("clear", "consider", "rejected")), t.c.held_for_review.is_(False))
        .order_by(t.c.id)
    ).all():
        decisive[user_id] = (status, expires_at)
    return {uid for uid, (status, expires_at) in decisive.items()
            if status == "clear" and (expires_at is None or now < expires_at)}


def can_drive(user) -> bool:
    return user is not None and clearance(user).can_drive


def driving_cleared_user_ids(user_ids) -> set[int]:
    """Batch version of can_drive() for the matcher (one query for every candidate)."""
    ids = {int(u) for u in user_ids if u is not None}
    if not ids:
        return set()
    if not required():
        return ids
    # Same rule as can_drive() / _decisive(), evaluated on plain rows (no ORM objects): the decisive
    # check is the latest one that is clear / consider / rejected and not held for a manager; the
    # user may drive when it is clear, not expired and of the driver package.
    # (tests/test_load_optimisations.py keeps this identical to can_drive().)
    from sqlalchemy import select

    t = BackgroundCheck.__table__
    now = utcnow()
    decisive: dict[int, tuple] = {}
    rows = db.session.execute(
        select(t.c.user_id, t.c.status, t.c.package, t.c.expires_at)
        .where(t.c.user_id.in_(ids), t.c.status.in_(("clear", "consider", "rejected")), t.c.held_for_review.is_(False))
        .order_by(t.c.id)
    ).all()
    for user_id, status, package, expires_at in rows:
        decisive[user_id] = (status, package, expires_at)  # later rows win -> the latest decisive check
    return {uid for uid, (status, package, expires_at) in decisive.items()
            if status == "clear" and package == "driver" and (expires_at is None or now < expires_at)}


# ------------------------------------------------------------------ form validation

_NAME_RE = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ '.\-])*$", re.UNICODE)  # letters, spaces, apostrophes, dots, hyphens
_LICENCE_RE = re.compile(r"^[A-Za-z0-9\-]{4,20}$")
STATEMENT_MIN, STATEMENT_MAX = 20, 2000


def _age_on(dob: date, today: date) -> int:
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def _clean_name(value: str, what: str) -> str:
    value = " ".join((value or "").split())[:80]
    if not value or not _NAME_RE.match(value):
        raise BackgroundCheckInputError(f"Please enter your legal {what} (letters, spaces, apostrophes and hyphens only).")
    return value


def validate_form(user: User, form) -> dict:
    """Form -> clean applicant data. Raises BackgroundCheckInputError with a user-facing message."""
    from payments.cards import looks_like_pan

    if any(looks_like_pan(v) for v in form.values()):
        # never let payment data end up in a background-check record
        raise BackgroundCheckInputError("Card numbers are never needed for a background check. Please remove it.")
    first = _clean_name(form.get("legal_first_name", ""), "first name")
    last = _clean_name(form.get("legal_last_name", ""), "last name")
    try:
        dob = date.fromisoformat((form.get("date_of_birth") or "").strip())
    except ValueError:
        raise BackgroundCheckInputError("Please enter your date of birth (YYYY-MM-DD).") from None
    today = utcnow().date()
    if dob >= today or _age_on(dob, today) > 120:
        raise BackgroundCheckInputError("Please enter a valid date of birth.")

    licence = (form.get("licence_number") or "").strip().upper()
    region = " ".join((form.get("licence_region") or "").split())[:40]
    package = "standard"
    if licence:
        if not may_drive(user):
            raise BackgroundCheckInputError("Buyer-only accounts cannot drive - leave the driving licence empty.")
        if not _LICENCE_RE.match(licence):
            raise BackgroundCheckInputError("The driving licence number must be 4-20 letters, digits or dashes.")
        if len(region) < 2:
            raise BackgroundCheckInputError("Please enter the state / region that issued your driving licence.")
        package = "driver"
    age = _age_on(dob, today)
    if age < min_age("standard"):
        raise BackgroundCheckInputError(f"You must be at least {min_age('standard')} years old to use ServiceUber.")
    if package == "driver" and age < min_age("driver"):
        raise BackgroundCheckInputError(
            f"Drivers must be at least {min_age('driver')} years old. Leave the driving licence empty to be checked as a rider.")
    if (form.get("consent") or "").lower() not in ("1", "on", "yes", "true"):
        raise BackgroundCheckInputError("Please read the disclosure and authorise the background check.")
    return {"first": first, "last": last, "dob": dob, "licence": licence or None, "region": region or None, "package": package}


def _run_check(user: User, data: dict, ip: str | None, *, held: bool = False) -> BackgroundCheck:
    """Send the applicant to the provider and store the report (does not commit)."""
    applicant = Applicant(candidate_ref=candidate_ref(user.id), first_name=data["first"], last_name=data["last"],
                          date_of_birth=data["dob"], package=data["package"], licence_number=data["licence"],
                          licence_region=data["region"])
    provider = get_provider()
    report = provider.submit(applicant)  # raises BackgroundCheckError
    now = utcnow()
    check = BackgroundCheck(
        user=user, package=data["package"], status=report.status, provider=provider.name,
        provider_ref=report.ref, legal_first_name=data["first"], legal_last_name=data["last"],
        licence_region=data["region"], consent_at=now, consent_ip=(ip or "")[:45] or None,
        result_note=report.note, submitted_at=now, held_for_review=held,
    )
    check.date_of_birth = data["dob"]
    check.licence_number = data["licence"]
    check.screens = report.screens
    _set_completion(check, report.status, now)
    db.session.add(check)
    db.session.flush()
    return check


# ------------------------------------------------------------------ submit

def submit(user: User, form, ip: str | None = None) -> BackgroundCheck:
    """
    Validate, send to the provider, store the report. Raises BackgroundCheckInputError (bad
    form / not allowed right now) or BackgroundCheckError (provider problem). Commits.
    """
    st = clearance(user)
    if not st.required:
        raise BackgroundCheckInputError("Background checks are switched off.")
    if not st.can_submit:
        raise BackgroundCheckInputError(st.message if st.state != "clear" else "Your background check has already passed.")
    data = validate_form(user, form)
    if st.state == "clear" and data["package"] != "driver":
        raise BackgroundCheckInputError("You already passed the rider check. Add your driving licence to be checked as a driver.")
    check = _run_check(user, data, ip)
    _enforce(user)
    live.push(user, "check_submitted", check=check)
    db.session.commit()
    _audit("background_check_submitted", user.id, f"{check.package}: {check.status} ({check.provider_ref})")
    log.info("background check user=%s package=%s status=%s ref=%s", user.id, check.package, check.status, check.provider_ref)
    return check


def submit_dispute(user: User, form, ip: str | None = None) -> BackgroundDispute:
    """
    A rejected user disputes: store the statement, escalate to a new background check (held for
    review, with the details from the form - corrections allowed) and queue it for a manager.
    Raises BackgroundCheckInputError / BackgroundCheckError. Commits.
    """
    st = clearance(user)
    if not st.can_dispute:
        if st.state == "disputed":
            raise BackgroundCheckInputError("Your dispute is already being handled.")
        if st.state == "rejected":
            raise BackgroundCheckInputError("This decision is final: you already used your dispute.")
        raise BackgroundCheckInputError("Only a rejected background check can be disputed.")
    statement = (form.get("statement") or "").strip()
    if len(statement) < STATEMENT_MIN:
        raise BackgroundCheckInputError(f"Please explain why you dispute the decision (at least {STATEMENT_MIN} characters).")
    if len(statement) > STATEMENT_MAX:
        raise BackgroundCheckInputError(f"Please keep your explanation under {STATEMENT_MAX} characters.")
    data = validate_form(user, form)  # also refuses card numbers anywhere, including the statement
    recheck = _run_check(user, data, ip, held=True)
    dispute = BackgroundDispute(user=user, check_id=st.decisive.id, recheck_id=recheck.id, statement=statement,
                                status="rechecking" if recheck.status == "pending" else "under_review")
    db.session.add(dispute)
    db.session.flush()
    live.push(user, "dispute_opened", check=recheck, dispute=dispute)
    db.session.commit()
    _audit("background_dispute_opened", user.id, f"dispute #{dispute.id}: re-check {recheck.status} ({recheck.provider_ref})")
    _notify(user, "we received your dispute",
            "We received your dispute of the background-check decision. A new background check has been "
            "started and a manager will review it together with your explanation. We will e-mail you the decision.")
    return dispute


def _set_completion(check: BackgroundCheck, status: str, now) -> None:
    check.status = status
    if status == "pending":
        check.completed_at = None
        check.expires_at = None
        return
    check.completed_at = now
    days = _valid_days()
    check.expires_at = now + timedelta(days=days) if status == "clear" and days > 0 else None


# ------------------------------------------------------------------ provider results

def apply_report(ref: str, status: str, screens: dict | None = None) -> BackgroundCheck | None:
    """
    Store a result pushed by the provider (webhook). Pending checks are completed, and a clear
    check can be downgraded (continuous monitoring found something); checks under manual review
    or rejected are never overwritten by the provider. A dispute re-check is only completed -
    the decision stays with the manager. Commits.
    """
    check = BackgroundCheck.query.filter_by(provider_ref=ref).first()
    if check is None:
        return None
    screens = {str(k): str(v) for k, v in (screens or {}).items()} or dict(check.screens)
    status = status if status in BACKGROUND_CHECK_STATUSES and status != "rejected" else overall_status(screens)
    if check.held_for_review:
        if check.status != "pending" or status == "pending":
            return check
    elif check.status not in ("pending", "clear") or (check.status == "clear" and status == "clear"):
        return check
    check.screens = screens
    check.result_note = NOTES.get(status)
    _set_completion(check, status, utcnow())
    dispute = None
    if check.held_for_review:
        dispute = BackgroundDispute.query.filter_by(recheck_id=check.id, status="rechecking").first()
        if dispute is not None:
            dispute.status = "under_review"  # the manager can decide now
    _enforce(check.user)
    live.push(check.user, "recheck_completed" if check.held_for_review else "check_completed", check=check, dispute=dispute)
    db.session.commit()
    _audit("background_check_result", check.user_id, f"{check.status} ({check.provider_ref})")
    return check


# ------------------------------------------------------------------ manager decisions (admin dashboard)

def _clean_note(note: str | None, decision: str) -> str | None:
    note = " ".join((note or "").split())[:500] or None
    if decision == "reject" and (note is None or len(note) < 5):
        raise BackgroundCheckInputError("A rejection needs a reason (at least 5 characters) - it is shown to the user.")
    return note


def adjudicate(check: BackgroundCheck, decision: str, *, actor: str = "system", note: str | None = None) -> BackgroundCheck:
    """
    Manual review by a manager.
      approve -> clear (valid for BACKGROUND_CHECK_VALID_DAYS)    from consider
      reject  -> rejected (the user may dispute it)                from consider / clear / pending
    Dispute re-checks are decided through decide_dispute().
    """
    if check.held_for_review:
        raise DecisionConflictError("This report belongs to an open dispute - decide the dispute instead.")
    note = _clean_note(note, decision)
    now = utcnow()
    if decision == "approve" and check.status == "consider":
        check.adjudication = "approved"
        check.result_note = "Approved after manual review." + (f" {note}" if note else "")
        _set_completion(check, "clear", now)
    elif decision == "reject" and check.status in ("consider", "clear", "pending"):
        check.adjudication = "rejected"
        check.result_note = f"Not approved after review: {note}"
        _set_completion(check, "rejected", now)
    else:
        raise DecisionConflictError(f"Cannot {decision} a check that is {check.status}.")
    check.adjudicated_at = now
    check.adjudicated_by = (actor or "system")[:80]
    _enforce(check.user)
    live.push(check.user, "check_approved" if decision == "approve" else "check_rejected", check=check,
              actor=check.adjudicated_by)
    db.session.commit()
    _audit("background_check_adjudicated", check.user_id, f"{decision} by {check.adjudicated_by} ({check.provider_ref})")
    if decision == "reject":
        can = clearance(check.user).can_dispute
        _notify(check.user, "your background check was not approved",
                f"Reason: {note}\n\n" + ("If you believe this is wrong you can raise a dispute on the background-check "
                                         "page; a new check will be run and a manager will review it."
                                         if can else "This decision is final."))
    else:
        _notify(check.user, "your background check was approved", "You can now use ServiceUber.")
    return check


def decide_dispute(dispute: BackgroundDispute, decision: str, *, actor: str, note: str | None = None) -> BackgroundDispute:
    """
    The manager's decision on a dispute (only once the re-check is back):
      approve -> the re-check becomes clear -> the user passes
      reject  -> the re-check becomes rejected -> final (unless disputes remain)
    """
    if decision not in ("approve", "reject"):
        raise BackgroundCheckInputError("The decision must be 'approve' or 'reject'.")
    if dispute.status == "rechecking":
        raise DecisionConflictError("The re-check is still in progress at the provider - wait for its result.")
    if dispute.status != "under_review":
        raise DecisionConflictError(f"This dispute is already {dispute.status}.")
    note = _clean_note(note, decision)
    now = utcnow()
    recheck = dispute.recheck
    recheck.held_for_review = False
    recheck.adjudicated_at = now
    recheck.adjudicated_by = (actor or "system")[:80]
    if decision == "approve":
        recheck.adjudication = "approved"
        recheck.result_note = "Approved after dispute review." + (f" {note}" if note else "")
        _set_completion(recheck, "clear", now)
        dispute.status = "approved"
    else:
        recheck.adjudication = "rejected"
        recheck.result_note = f"Dispute not upheld: {note}"
        _set_completion(recheck, "rejected", now)
        dispute.status = "rejected"
    dispute.decided_at = now
    dispute.decided_by = recheck.adjudicated_by
    dispute.decision_note = note
    _enforce(dispute.user)
    live.push(dispute.user, f"dispute_{dispute.status}", check=recheck, dispute=dispute, actor=dispute.decided_by)
    db.session.commit()
    _audit("background_dispute_decided", dispute.user_id, f"dispute #{dispute.id} {dispute.status} by {dispute.decided_by}")
    if decision == "approve":
        _notify(dispute.user, "your dispute was approved",
                "After reviewing your dispute and the new background check, a manager approved your account. "
                "You can now use ServiceUber." + (f"\n\nNote: {note}" if note else ""))
    else:
        more = clearance(dispute.user).can_dispute
        _notify(dispute.user, "your dispute was not upheld",
                f"Reason: {note}\n\n" + ("You can dispute again on the background-check page." if more
                                         else "This decision is final."))
    return dispute


def _enforce(user: User) -> None:
    """A user who may no longer drive stops driving now (does not commit)."""
    drv = user.driver_profile
    if drv is None or can_drive(user):
        return
    from rides import matching
    from rides.matching import RideError
    from models import RideOffer, RideRequest

    drv.is_online = False
    for offer in RideOffer.query.filter_by(driver_id=drv.id, status="pending").all():
        try:
            matching.decline_offer(offer, drv)  # the rider is told at once and dispatch moves on
        except RideError:
            pass
    for ride in RideRequest.query.filter_by(driver_id=drv.id, status="accepted").all():
        try:
            matching.cancel_ride(ride, user)  # hand the ride back to the search
        except RideError:
            pass
    log.info("driving disabled for user=%s (background check no longer covers driving)", user.id)


def _audit(event: str, user_id: int, detail: str) -> None:
    from flask import has_request_context

    if has_request_context():
        from auth.audit import record

        record(event, user_id, detail)
    else:
        log.info("%s user_id=%s %s", event, user_id, detail)


def _notify(user: User, subject: str, body: str) -> None:
    """E-mail the user about their background check (best effort: a delivery problem never blocks a decision)."""
    from flask import has_request_context, url_for

    from auth.delivery import DeliveryError, send_message

    app_name = current_app.config.get("APP_NAME", "ServiceUber")
    link = ""
    base = current_app.config.get("APP_BASE_URL")
    if base:
        link = base + "/background-check"
    elif has_request_context():
        try:
            link = url_for("background.check", _external=True)
        except Exception:  # noqa: BLE001
            link = ""
    try:
        send_message("email", user.email, f"{app_name}: {subject}",
                     body + (f"\n\nYour background check: {link}" if link else ""))
    except (DeliveryError, OSError) as exc:
        log.warning("could not e-mail user=%s about '%s': %s", user.id, subject, exc)


# ------------------------------------------------------------------ serialisation (admin API)

def check_json(check: BackgroundCheck) -> dict:
    """What a manager sees of a report: never the date of birth, the licence only masked."""
    dispute = BackgroundDispute.query.filter_by(recheck_id=check.id).first()  # set for dispute re-checks
    return {
        "id": check.id, "package": check.package, "status": check.status, "held_for_review": check.held_for_review,
        "provider": check.provider, "provider_ref": check.provider_ref, "legal_name": check.legal_name,
        "licence": f"••••{check.licence_last4} ({check.licence_region})" if check.licence_last4 else None,
        "screens": check.screens, "result_note": check.result_note, "adjudication": check.adjudication,
        "adjudicated_by": check.adjudicated_by,
        "adjudicated_at": check.adjudicated_at.isoformat() if check.adjudicated_at else None,
        "submitted_at": check.submitted_at.isoformat(), "completed_at": check.completed_at.isoformat() if check.completed_at else None,
        "expires_at": check.expires_at.isoformat() if check.expires_at else None, "expired": check.is_expired,
        "recheck_for_dispute": dispute.id if dispute is not None else None,
        "user": user_json(check.user),
        "allowed_decisions": allowed_check_decisions(check),
    }


def user_json(user: User) -> dict:
    return {"id": user.id, "username": user.username, "email": user.email, "display_name": user.display_name,
            "role": user.role, "state": clearance(user).state}


# user states a manager can filter on (the background-check standing, see clearance())
USER_STATES = ("not_started", "pending", "unverified", "clear", "expired", "consider", "rejected", "disputed")


def user_age(user: User, today: date | None = None) -> int | None:
    """
    Age in whole years from the date of birth of the user's latest ACCEPTED background check (a
    dispute re-check counts only once the manager approved it). None when no check exists.
    The date of birth itself never leaves this app - only the age does.
    """
    for check in sorted(user.background_checks, key=lambda c: c.id, reverse=True):
        if check.held_for_review:
            continue
        dob = check.date_of_birth
        if dob is not None:
            return _age_on(dob, today or utcnow().date())
    return None


def user_summary(user: User, today: date | None = None) -> dict:
    """One row of the admin dashboard's Users tab (no date of birth, no licence, no payment data)."""
    st = clearance(user)
    drv = user.driver_profile
    return {
        "id": user.id, "username": user.username, "display_name": user.display_name, "email": user.email,
        "role": user.role, "age": user_age(user, today), "state": st.state, "passed": st.passed,
        "can_drive": st.can_drive, "driver": None if drv is None else {"online": drv.is_online, "vehicle": drv.vehicle},
        "mfa_enabled": user.mfa_enabled, "locked": user.is_locked, "email_verified": user.email_verified,
        "social_login": bool(user.oauth_accounts), "password_login": user.password_is_usable,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def allowed_check_decisions(check: BackgroundCheck) -> list[str]:
    if check.held_for_review:
        return []
    out = []
    if check.status == "consider":
        out.append("approve")
    if check.status in ("consider", "clear", "pending"):
        out.append("reject")
    return out


def dispute_json(dispute: BackgroundDispute, detail: bool = True) -> dict:
    data = {
        "id": dispute.id, "status": dispute.status, "created_at": dispute.created_at.isoformat(),
        "decided_at": dispute.decided_at.isoformat() if dispute.decided_at else None,
        "decided_by": dispute.decided_by, "decision_note": dispute.decision_note, "user": user_json(dispute.user),
        "recheck_status": dispute.recheck.status if dispute.recheck else None,
        "allowed_decisions": ["approve", "reject"] if dispute.status == "under_review" else [],
    }
    if detail:
        data["statement"] = dispute.statement
        data["original_check"] = check_json(dispute.check)
        data["recheck"] = check_json(dispute.recheck) if dispute.recheck else None
    return data


# ------------------------------------------------------------------ demo data

def seed_clear_check(user: User, *, package: str, first: str, last: str, dob: date,
                     licence: str | None = None, region: str | None = None) -> BackgroundCheck:
    """A pre-passed DUMMY check for seeded demo accounts (does not call the provider; does not commit)."""
    from models import BACKGROUND_CHECK_SCREENS

    now = utcnow()
    check = BackgroundCheck(
        user_id=user.id, package=package, provider="fake", provider_ref=f"bgc_DUMMY_seed_{user.id}_{secrets.token_hex(4)}",
        legal_first_name=first, legal_last_name=last, licence_region=region, consent_at=now,
        result_note="DUMMY demo account - seeded as clear.", submitted_at=now,
    )
    check.date_of_birth = dob
    check.licence_number = licence
    check.screens = {s: "clear" for s in BACKGROUND_CHECK_SCREENS[package]}
    _set_completion(check, "clear", now)
    db.session.add(check)
    return check
