"""
Dashboard pages. Three tabs:

  🛡 Background checks  (everything about background checks, with sub-tabs)
    GET  /background-checks                       Overview: queues at a glance
    GET  /background-checks/reports?status=&q=    Reports (default: needs review)
    GET  /background-checks/reports/<id>          one report + the user's history;  POST .../decision (managers)
    GET  /background-checks/disputes?status=      Disputes (default: waiting for a decision)
    GET  /background-checks/disputes/<id>         statement + original report + re-check;  POST .../decision (managers)
  👥 Users
    GET  /users?role=&status=&q=&min_age=&max_age=&sort=   every user account of ServiceUber
    GET  /users/<id>?date_from=&date_to=&method=&type=    profile, background-check history, disputes, activity
                                                  + the FINANCIAL TRANSACTION REPORT (filters: date range,
                                                  payment method, type: buy / sell / refund / hold / verification)
    GET  /users/<id>/transactions.csv?...         the same report as CSV
    GET/POST /users/<id>/transactions/<tx>/refund refund (part of) a payment (managers)
  Audit log
    GET  /audit                                   this dashboard's own audit log

  GET  /                  -> the Background checks tab
  GET  /reviews[/<id>], /disputes[/<id>]   old URLs -> redirect to the new ones
  GET  /events            push stream for the browsers (SSE), relayed from ServiceUber
  GET  /healthz           liveness (+ ?deep=1 also checks the Admin API)
"""

from __future__ import annotations

import csv
import io
from datetime import date

from flask import (Blueprint, Response, abort, current_app, flash, g, jsonify, redirect, render_template, request,
                   url_for)

from . import api, live
from .auth import audit, login_required, manager_required
from .client import MainAppError
from .models import AuditEntry

bp = Blueprint("views", __name__)

CHECK_FILTERS = {
    "needs_review": "Needs review", "pending": "Pending at provider", "clear": "Clear", "consider": "Consider (all)",
    "rejected": "Rejected", "unverified": "Unverified", "": "All",
}
DISPUTE_FILTERS = {"under_review": "To decide", "rechecking": "Re-check running", "approved": "Approved",
                   "rejected": "Rejected", "": "All"}
USER_ROLES = {"": "All roles", "buyer": "Buyer (rider)", "seller": "Seller (driver / provider)", "both": "Both"}
USER_STATUSES = {
    "": "All statuses", "clear": "Active (check passed)", "not_started": "No check yet", "pending": "Check pending",
    "unverified": "Unverified", "consider": "Needs review", "rejected": "Rejected", "disputed": "Disputed",
    "expired": "Check expired",
}
USER_SORTS = {"newest": "Newest first", "oldest": "Oldest first", "username": "Username", "age_asc": "Age ↑",
              "age_desc": "Age ↓"}
PAGE = 50


@bp.route("/healthz")
def healthz():
    body = {"status": "ok", "service": "uber-admin-dashboard"}
    if request.args.get("deep"):
        try:
            api().health()
            body["main_app"] = "reachable"
        except MainAppError as exc:
            body["main_app"] = f"error: {exc.message}"
    return jsonify(body)


@bp.route("/events")
@login_required
def events():
    """Live updates for this operator's pages (static/live.js)."""
    relay = live.ensure_relay(current_app._get_current_object())
    status = relay.status if relay else {"connected": False, "error": "live updates are switched off"}
    resp = Response(live.stream({"relay": status}), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


@bp.route("/")
@login_required
def dashboard():
    return redirect(url_for("views.bgc_overview"))


# ================================================================== 🛡 Background checks tab

@bp.route("/background-checks")
@login_required
def bgc_overview():
    return render_template("bgc_overview.html", summary=api().summary(), api_url=api().base_url, sub="overview")


@bp.route("/background-checks/reports")
@login_required
def reviews():
    status = request.args.get("status", "needs_review")
    status = status if status in CHECK_FILTERS else "needs_review"
    q = request.args.get("q", "").strip()[:80]
    page = max(request.args.get("page", 1, type=int) or 1, 1)
    data = api().list_checks(status=status or None, q=q or None, limit=PAGE, offset=(page - 1) * PAGE)
    return render_template("reviews.html", data=data, status=status, q=q, page=page, filters=CHECK_FILTERS,
                           summary=api().summary(), sub="reports")


@bp.route("/background-checks/reports/<int:check_id>")
@login_required
def review_detail(check_id: int):
    return render_template("review_detail.html", data=api().get_check(check_id), summary=api().summary(), sub="reports")


@bp.route("/background-checks/reports/<int:check_id>/decision", methods=["POST"])
@manager_required
def review_decision(check_id: int):
    decision = request.form.get("decision", "")
    note = request.form.get("note", "").strip()
    try:
        result = api().decide_check(check_id, decision, note, actor=g.admin.username)
    except MainAppError as exc:
        audit(f"check_{decision or 'decision'}", f"check #{check_id}", "error", exc.message)
        raise
    audit(f"check_{decision}", f"check #{check_id}", "ok",
          f"{result['check']['user']['username']} -> {result['check']['status']}" + (f"; note: {note}" if note else ""))
    done = {"approve": "approved", "reject": "rejected"}.get(decision, decision)
    flash(f"Report #{check_id} ({result['check']['user']['username']}): {done} -> {result['check']['status']}.", "success")
    return redirect(url_for("views.review_detail", check_id=check_id))


@bp.route("/background-checks/disputes")
@login_required
def disputes():
    status = request.args.get("status", "under_review")
    status = status if status in DISPUTE_FILTERS else "under_review"
    page = max(request.args.get("page", 1, type=int) or 1, 1)
    data = api().list_disputes(status=status or None, limit=PAGE, offset=(page - 1) * PAGE)
    return render_template("disputes.html", data=data, status=status, page=page, filters=DISPUTE_FILTERS,
                           summary=api().summary(), sub="disputes")


@bp.route("/background-checks/disputes/<int:dispute_id>")
@login_required
def dispute_detail(dispute_id: int):
    return render_template("dispute_detail.html", data=api().get_dispute(dispute_id), summary=api().summary(), sub="disputes")


@bp.route("/background-checks/disputes/<int:dispute_id>/decision", methods=["POST"])
@manager_required
def dispute_decision(dispute_id: int):
    decision = request.form.get("decision", "")
    note = request.form.get("note", "").strip()
    try:
        result = api().decide_dispute(dispute_id, decision, note, actor=g.admin.username)
    except MainAppError as exc:
        audit(f"dispute_{decision or 'decision'}", f"dispute #{dispute_id}", "error", exc.message)
        raise
    d = result["dispute"]
    audit(f"dispute_{decision}", f"dispute #{dispute_id}", "ok",
          f"{d['user']['username']} -> {d['status']}" + (f"; note: {note}" if note else ""))
    flash(f"Dispute #{dispute_id} ({d['user']['username']}): {d['status']}.", "success")
    return redirect(url_for("views.dispute_detail", dispute_id=dispute_id))


# ---- old URLs (before the Background checks tab) keep working
def _legacy(endpoint: str, **kw):
    return redirect(url_for(endpoint, **kw, **request.args.to_dict()), code=301)


bp.add_url_rule("/reviews", "legacy_reviews", lambda: _legacy("views.reviews"))
bp.add_url_rule("/reviews/<int:check_id>", "legacy_review", lambda check_id: _legacy("views.review_detail", check_id=check_id))
bp.add_url_rule("/disputes", "legacy_disputes", lambda: _legacy("views.disputes"))
bp.add_url_rule("/disputes/<int:dispute_id>", "legacy_dispute",
                lambda dispute_id: _legacy("views.dispute_detail", dispute_id=dispute_id))


# ================================================================== 👥 Users tab

def _age_param(name: str) -> tuple[str, int | None, str | None]:
    """(raw text for the form, value, error)."""
    raw = request.args.get(name, "").strip()[:3]
    if not raw:
        return "", None, None
    if not raw.isdigit() or int(raw) > 150:
        return raw, None, "Ages must be whole numbers between 0 and 150."
    return raw, int(raw), None


@bp.route("/users")
@login_required
def users():
    role = request.args.get("role", "")
    role = role if role in USER_ROLES else ""
    status = request.args.get("status", "")
    status = status if status in USER_STATUSES else ""
    q = request.args.get("q", "").strip()[:80]
    sort = request.args.get("sort", "newest")
    sort = sort if sort in USER_SORTS else "newest"
    min_raw, min_age, err1 = _age_param("min_age")
    max_raw, max_age, err2 = _age_param("max_age")
    error = err1 or err2
    if not error and min_age is not None and max_age is not None and min_age > max_age:
        error = "The minimum age must not be greater than the maximum age."
    page = max(request.args.get("page", 1, type=int) or 1, 1)
    form = {"role": role, "status": status, "q": q, "min_age": min_raw, "max_age": max_raw, "sort": sort}
    data = {"total": 0, "offset": 0, "items": []}
    if error:
        flash(error, "error")
    else:
        data = api().list_users(role=role or None, status=status or None, q=q or None, min_age=min_age,
                                max_age=max_age, sort=sort, limit=PAGE, offset=(page - 1) * PAGE)
    filtered = any(v for k, v in form.items() if k != "sort")
    args = {k: v for k, v in form.items() if v}  # for the pagination links
    return render_template("users.html", data=data, form=form, args=args, page=page, filtered=filtered,
                           roles=USER_ROLES, statuses=USER_STATUSES, sorts=USER_SORTS)


TX_FILTER_KEYS = ("date_from", "date_to", "method", "type")
TX_PAGE = 50


def _tx_filters() -> tuple[dict, str | None]:
    """Transaction-report filters from the query string (+ an error message for bad dates)."""
    f = {k: request.args.get(k, "").strip()[:40] for k in TX_FILTER_KEYS}
    for k in ("date_from", "date_to"):
        if f[k]:
            try:
                date.fromisoformat(f[k])
            except ValueError:
                return f, "Dates must be given as YYYY-MM-DD."
    if f["date_from"] and f["date_to"] and f["date_from"] > f["date_to"]:
        return f, "The start date must not be after the end date."
    return f, None


def _tx_report(user_id: int, f: dict, limit: int, offset: int) -> dict:
    return api().list_user_transactions(user_id, date_from=f["date_from"] or None, date_to=f["date_to"] or None,
                                        method=f["method"] or None, ttype=f["type"] or None, limit=limit, offset=offset)


@bp.route("/users/<int:user_id>")
@login_required
def user_detail(user_id: int):
    data = api().get_user(user_id)
    f, error = _tx_filters()
    page = max(request.args.get("page", 1, type=int) or 1, 1)
    tx = None
    if not error:
        try:
            tx = _tx_report(user_id, f, TX_PAGE, (page - 1) * TX_PAGE)
        except MainAppError as exc:
            if exc.status != 400:
                raise
            error = f"Invalid filter: {exc.message}"
    if error:
        flash(error, "error")
        tx = api().list_user_transactions(user_id, limit=1)  # the filter options; no rows for invalid filters
        tx.update(items=[], total=0, offset=0, totals=None)
    args = {k: v for k, v in f.items() if v}
    return render_template("user_detail.html", data=data, statuses=USER_STATUSES, tx=tx, tx_form=f, tx_args=args,
                           tx_page=page, tx_filtered=bool(args))


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formulas (CSV injection) in user-controlled text."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@bp.route("/users/<int:user_id>/transactions.csv")
@login_required
def user_transactions_csv(user_id: int):
    f, error = _tx_filters()
    if error:
        flash(error, "error")
        return redirect(url_for("views.user_detail", user_id=user_id))
    rows, offset = [], 0
    while True:
        page = _tx_report(user_id, f, 200, offset)
        rows += page["items"]
        offset += 200
        if offset >= page["total"]:
            break
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["date_utc", "type", "category", "description", "counterparty", "payment_method", "status", "amount",
                "currency", "direction", "reference", "refunded", "refund_reason", "issued_by"])
    for r in rows:
        w.writerow([_csv_safe(r["date"]), r["type"], r["category"], _csv_safe(r["description"]), _csv_safe(r["counterparty"]),
                    _csv_safe(r["method_label"]), r["status"], f"{r['amount']:.2f}", r["currency"], r["direction"],
                    _csv_safe(r["reference"]), f"{r['refunded_amount']:.2f}", _csv_safe(r["refund_reason"]),
                    _csv_safe(r["issued_by"])])
    audit("export_transactions", f"user #{user_id}", "ok", f"{len(rows)} row(s); filters: {f}")
    name = f"transactions-user-{user_id}-{date.today().isoformat()}.csv"
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@bp.route("/users/<int:user_id>/transactions/<int:tx_id>/refund", methods=["GET", "POST"])
@manager_required
def refund(user_id: int, tx_id: int):
    data = api().get_transaction(tx_id)
    if data["user"]["id"] != user_id:
        abort(404)
    t = data["transaction"]
    if request.method == "POST":
        amount = request.form.get("amount", "").strip()
        reason = request.form.get("reason", "").strip()
        try:
            result = api().refund_transaction(tx_id, amount, reason, actor=g.admin.username)
        except MainAppError as exc:
            audit("refund", f"transaction #{tx_id}", "error", f"{amount} - {exc.message}")
            flash(exc.message, "error")
            return render_template("refund.html", t=t, user=data["user"], form={"amount": amount, "reason": reason}), \
                400 if exc.status in (400, 409, 402) else exc.status
        r = result["refund"]
        audit("refund", f"transaction #{tx_id}", "ok", f"{r['currency']} {r['amount']:.2f} to {data['user']['username']}: {reason}")
        flash(f"Refunded {r['currency']} {r['amount']:.2f} to {data['user']['username']} ({t['method_label']}).", "success")
        return redirect(url_for("views.user_detail", user_id=user_id, type="refund") + "#transactions")
    return render_template("refund.html", t=t, user=data["user"], form={"amount": f"{t['refundable_amount']:.2f}", "reason": ""})


# ================================================================== audit

@bp.route("/audit")
@login_required
def audit_log():
    entries = AuditEntry.query.order_by(AuditEntry.id.desc()).limit(300).all()
    return render_template("audit.html", entries=entries)
