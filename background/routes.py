"""
Background-check routes.

  GET/POST /background-check                  status + the form (legal name, date of birth,
                                              optional driving licence, consent)
  POST     /background-check/dispute          a REJECTED user disputes: statement + (corrected)
                                              details -> a new check, then a manager decides
  GET      /api/background-check              JSON standing of the logged-in user
  GET      /events/account                    push channel of the logged-in user (SSE): every change of
                                              their background check / dispute, on every page
  POST     /background-check/webhook          provider -> us: report.completed (HMAC-signed)

Manager decisions (approve / reject flagged reports, decide disputes) are made in the SEPARATE
admin dashboard (admin_dashboard/), which calls /admin-api/v1 (background/admin_api.py).

Dev only (ENABLE_DEV_TOOLS) - stand-in for the PROVIDER finishing reports:
  GET      /dev/background-provider           pending reports
  POST     /dev/background-provider/<id>/<result>   clear | consider | unverified, delivered
                                              through the same signed webhook a real provider calls
  GET      /dev/background-checks             (old review page) -> redirects to the admin dashboard
"""

from __future__ import annotations

import json

from flask import abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from extensions import csrf, db
from models import BACKGROUND_CHECK_SCREENS, SCREEN_LABELS, BackgroundCheck
from throttle import client_ip, code_send_limit

from . import bp, dev_bp, live, service
from .provider import SIGNATURE_HEADER, BackgroundCheckError, sign_webhook, verify_webhook, webhook_body
from .service import BackgroundCheckInputError


def _form_defaults() -> dict:
    name = (current_user.display_name or "").split(" ", 1)
    return {"legal_first_name": name[0] if name and name[0] else "", "legal_last_name": name[1] if len(name) > 1 else "",
            "date_of_birth": "", "licence_number": "", "licence_region": "", "consent": ""}


def _dispute_defaults(st, form: dict) -> dict:
    """Pre-fill the dispute form from the rejected report (name / region only - never DOB or licence)."""
    d = st.decisive
    if d is None:
        return {**form, "statement": ""}
    return {**form, "statement": "", "legal_first_name": d.legal_first_name, "legal_last_name": d.legal_last_name,
            "licence_region": d.licence_region or ""}


def _render(form: dict, status: int = 200, dispute_form: dict | None = None):
    st = service.clearance(current_user)
    history = sorted(current_user.background_checks, key=lambda c: c.id, reverse=True)
    return render_template(
        "background/check.html", st=st, history=history, form=form, may_drive=service.may_drive(current_user),
        dispute_form=dispute_form or _dispute_defaults(st, form), disputes=list(reversed(current_user.background_disputes)),
        max_disputes=service.max_disputes(), statement_min=service.STATEMENT_MIN, statement_max=service.STATEMENT_MAX,
        screens=BACKGROUND_CHECK_SCREENS, screen_labels=SCREEN_LABELS,
        min_age=service.min_age("standard"), min_driver_age=service.min_age("driver"),
        valid_days=current_app.config.get("BACKGROUND_CHECK_VALID_DAYS", 365),
        provider_mode=current_app.config.get("BACKGROUND_CHECK_PROVIDER", "fake"),
    ), status


@bp.route("/background-check", methods=["GET", "POST"])
@login_required
@code_send_limit  # each submission calls (and in real life: is billed by) the provider
def check():
    if request.method == "GET":
        return _render(_form_defaults())
    keep = ("legal_first_name", "legal_last_name", "licence_region", "consent")  # never echo DOB / licence back
    form = {k: request.form.get(k, "") for k in _form_defaults()}
    try:
        result = service.submit(current_user, request.form, ip=client_ip())
    except (BackgroundCheckInputError, BackgroundCheckError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _render({**_form_defaults(), **{k: form[k] for k in keep}}, 400)
    if result.status == "clear":
        flash("Background check passed - welcome to ServiceUber!"
              + (" You can drive, too." if result.covers_driving else ""), "success")
        return redirect(url_for("dashboard"))
    flash({"pending": "Background check submitted. We will let you in as soon as the result is clear.",
           "consider": "Your background check needs a manual review before you can use ServiceUber.",
           "unverified": "We could not verify your identity. Please check your details and submit again."}
          .get(result.status, "Background check submitted."), "warning" if result.status != "pending" else "info")
    return redirect(url_for("background.check"))


@bp.route("/background-check/dispute", methods=["POST"])
@login_required
@code_send_limit  # a dispute also calls the provider (re-check)
def dispute():
    keep = ("legal_first_name", "legal_last_name", "licence_region", "consent", "statement")  # never echo DOB / licence
    try:
        d = service.submit_dispute(current_user, request.form, ip=client_ip())
    except (BackgroundCheckInputError, BackgroundCheckError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return _render(_form_defaults(), 400, dispute_form={**_form_defaults(), **{k: request.form.get(k, "") for k in keep}})
    flash("Dispute submitted. A new background check has been started"
          + (" and is waiting for the provider" if d.status == "rechecking" else "")
          + "; a manager will review it and we will e-mail you the decision.", "info")
    return redirect(url_for("background.check"))


@bp.route("/api/background-check")
@login_required
def api_status():
    return jsonify({**service.clearance(current_user).as_dict(), "version": live.version(current_user)})


@bp.route("/events/account")
@login_required
def events_account():
    """
    Push channel of the logged-in user (static/account_live.js subscribes on every page). Reachable
    before the check has passed (this blueprint is exempt from the gate) - that is exactly when the
    user waits for news. The `hello` carries the current version so a reconnecting page catches up.
    """
    return live.sse_response(live.user_channel(current_user.id), live.user_state(current_user))


def process_webhook(body: bytes, signature: str | None) -> tuple[dict, int]:
    """Verify + apply one provider webhook. Returns (json body, http status)."""
    if not verify_webhook(body, signature):
        current_app.logger.warning("background-check webhook with a missing / invalid signature rejected")
        return {"error": "invalid_signature"}, 401
    try:
        event = json.loads(body)
        data = event["data"]
        ref, status = str(data["ref"]), str(data["status"])
        screens = data.get("screens") or {}
    except (ValueError, KeyError, TypeError):
        return {"error": "malformed_event"}, 400
    if event.get("type") != "report.completed":
        return {"ignored": True}, 200
    check = service.apply_report(ref, status, screens if isinstance(screens, dict) else {})
    if check is None:
        return {"error": "unknown_report"}, 404
    return {"ref": check.provider_ref, "status": check.status}, 200


@bp.route("/background-check/webhook", methods=["POST"])
@csrf.exempt  # server-to-server: authenticated by the HMAC signature, not by a browser session
def webhook():
    body, status = process_webhook(request.get_data(cache=True), request.headers.get(SIGNATURE_HEADER))
    return jsonify(body), status


# ================================================================= dev: fake provider console

@dev_bp.route("")
def provider_console():
    pending = BackgroundCheck.query.filter_by(status="pending").order_by(BackgroundCheck.id.desc()).all()
    return render_template("dev/background_provider.html", checks=pending, screen_labels=SCREEN_LABELS)


@dev_bp.route("/<int:check_id>/<result>", methods=["POST"])
def provider_complete(check_id: int, result: str):
    """Play the provider: finish a PENDING report through the signed webhook path."""
    check = db.session.get(BackgroundCheck, check_id) or abort(404)
    if result not in ("clear", "consider", "unverified"):
        abort(404)
    if check.status != "pending":
        flash(f"Report #{check.id} is not pending (it is {check.status}).", "error")
        return redirect(url_for("dev_background.provider_console"))
    screens = {s: "clear" for s in BACKGROUND_CHECK_SCREENS[check.package]}
    if result == "consider":
        screens["criminal"] = "consider"
    elif result == "unverified":
        screens["identity"] = "unverified"
    body = webhook_body(check.provider_ref, result, screens)
    data, code = process_webhook(body, sign_webhook(body))
    flash(f"Provider webhook processed (HTTP {code}): report #{check.id} is now {data.get('status', check.status)}"
          + (" - held for the manager (dispute re-check)." if check.held_for_review else "."), "info")
    return redirect(url_for("dev_background.provider_console"))


def register_legacy_redirect(app) -> None:
    """The review console moved to the separate admin dashboard; keep the old dev URL working."""

    @app.route("/dev/background-checks")
    def legacy_background_review():
        return redirect(current_app.config.get("ADMIN_DASHBOARD_URL", "http://127.0.0.1:5001") + "/background-checks/reports")
