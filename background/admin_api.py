"""
Admin API v1 - the ONLY interface between this app and the separate admin dashboard
(admin_dashboard/). Service-to-service JSON; no cookies, no sessions.

Authentication
  Authorization: Bearer <ADMIN_API_TOKEN>        (constant-time compared; DUMMY in development,
                                                  production refuses a DUMMY token)
  X-Admin-Actor: <manager username>              required on every decision - recorded in the
                                                  report and in the audit trail

  GET  /admin-api/v1/events                          push stream (SSE) of every background-check change
                                                      (new / completed reports, decisions, disputes)
  GET  /admin-api/v1/health
  GET  /admin-api/v1/summary                          queue sizes for the dashboard home
  GET  /admin-api/v1/background-checks?status=&q=&limit=&offset=
  GET  /admin-api/v1/background-checks/<id>           + the user's other reports and disputes
  POST /admin-api/v1/background-checks/<id>/decision  {"decision": "approve"|"reject", "note": "..."}
  GET  /admin-api/v1/users?role=&status=&q=&min_age=&max_age=&sort=&limit=&offset=
                                                      every user account; status = background-check
                                                      standing; age from the encrypted date of birth
  GET  /admin-api/v1/users/<id>                       profile + reports + disputes + activity counts
  GET  /admin-api/v1/users/<id>/transactions?date_from=&date_to=&method=&type=&limit=&offset=
                                                      the user's financial transaction report
                                                      (payments/ledger.py): buy / sell / refund / hold /
                                                      verification, with totals
  GET  /admin-api/v1/transactions/<id>                one payment transaction (report row)
  POST /admin-api/v1/transactions/<id>/refund         {"amount": 5.50, "reason": "..."} refund (part of)
                                                      a successful payment; X-Admin-Actor required
  GET  /admin-api/v1/disputes?status=
  GET  /admin-api/v1/disputes/<id>                    statement + original report + re-check
  POST /admin-api/v1/disputes/<id>/decision           {"decision": "approve"|"reject", "note": "..."}

Errors: 400 invalid input, 401 bad / missing token, 404 unknown id or API disabled,
409 the decision is not possible in the current state. Body: {"error": "..."}.
Managers never see a date of birth or a full licence number.
"""

from __future__ import annotations

import hmac

from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import func, or_
from sqlalchemy.orm import selectinload

from extensions import csrf, db
from models import (BACKGROUND_CHECK_STATUSES, DISPUTE_STATUSES, BackgroundCheck, BackgroundDispute,
                    PaymentMethod, PaymentTransaction, RideRequest, User)

from . import live, service
from .service import BackgroundCheckInputError, DecisionConflictError

admin_api_bp = Blueprint("admin_api", __name__, url_prefix="/admin-api/v1")
MAX_LIMIT = 200


@admin_api_bp.before_request
def _authenticate():
    if not current_app.config.get("ADMIN_API_ENABLED", True):
        return jsonify(error="not_found"), 404
    expected = current_app.config.get("ADMIN_API_TOKEN") or ""
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.startswith("Bearer ") else ""
    if not expected or not token or not hmac.compare_digest(token.encode(), expected.encode()):
        current_app.logger.warning("admin API: rejected request without a valid token from %s", request.remote_addr)
        return jsonify(error="unauthorized"), 401
    g.admin_actor = " ".join((request.headers.get("X-Admin-Actor") or "").split())[:80]
    return None


@admin_api_bp.after_request
def _no_store(resp):
    if resp.mimetype != "text/event-stream":
        resp.headers["Cache-Control"] = "no-store"
    return resp


def _actor():
    if not g.get("admin_actor"):
        return None, (jsonify(error="X-Admin-Actor header (the deciding manager) is required"), 400)
    return g.admin_actor, None


def _page_args() -> tuple[int, int]:
    limit = min(max(request.args.get("limit", 50, type=int) or 50, 1), MAX_LIMIT)
    offset = max(request.args.get("offset", 0, type=int) or 0, 0)
    return limit, offset


def _decision_body():
    data = request.get_json(silent=True) or {}
    return str(data.get("decision", "")).strip().lower(), data.get("note")


# ------------------------------------------------------------------ meta

@admin_api_bp.route("/health")
def health():
    return jsonify(status="ok", app=current_app.config.get("APP_NAME", "ServiceUber"), api="v1")


@admin_api_bp.route("/events")
def events():
    """
    Server-Sent Events for the admin dashboard's SERVER (it relays them to its browsers - the token
    never reaches a browser). Events: check_submitted, check_completed, check_approved,
    check_rejected, dispute_opened, recheck_completed, dispute_approved, dispute_rejected.
    """
    return live.sse_response(live.ADMIN_CHANNEL, {"api": "v1", "needs_review": BackgroundCheck.query.filter_by(
        status="consider", held_for_review=False).count()})


@admin_api_bp.route("/summary")
def summary():
    checks = dict(db.session.query(BackgroundCheck.status, func.count()).group_by(BackgroundCheck.status).all())
    disputes = dict(db.session.query(BackgroundDispute.status, func.count()).group_by(BackgroundDispute.status).all())
    needs_review = BackgroundCheck.query.filter_by(status="consider", held_for_review=False).count()
    return jsonify(
        checks={s: checks.get(s, 0) for s in BACKGROUND_CHECK_STATUSES},
        disputes={s: disputes.get(s, 0) for s in DISPUTE_STATUSES},
        needs_review=needs_review, disputes_to_decide=disputes.get("under_review", 0),
        users=User.query.count(),
    )


# ------------------------------------------------------------------ background checks

@admin_api_bp.route("/background-checks")
def list_checks():
    limit, offset = _page_args()
    q = BackgroundCheck.query.join(User, BackgroundCheck.user_id == User.id)
    status = request.args.get("status", "").strip()
    if status == "needs_review":
        q = q.filter(BackgroundCheck.status == "consider", BackgroundCheck.held_for_review.is_(False))
    elif status:
        if status not in BACKGROUND_CHECK_STATUSES:
            return jsonify(error=f"unknown status '{status}'"), 400
        q = q.filter(BackgroundCheck.status == status)
    text = request.args.get("q", "").strip()[:80]
    if text:
        like = f"%{text}%"
        q = q.filter(or_(User.username.ilike(like), User.email.ilike(like), BackgroundCheck.legal_last_name.ilike(like),
                         BackgroundCheck.provider_ref.ilike(like)))
    total = q.count()
    rows = q.order_by(BackgroundCheck.id.desc()).offset(offset).limit(limit).all()
    return jsonify(total=total, limit=limit, offset=offset, items=[service.check_json(c) for c in rows])


@admin_api_bp.route("/background-checks/<int:check_id>")
def get_check(check_id: int):
    check = db.session.get(BackgroundCheck, check_id)
    if check is None:
        return jsonify(error="not_found"), 404
    user = check.user
    return jsonify(
        check=service.check_json(check),
        user_checks=[service.check_json(c) for c in sorted(user.background_checks, key=lambda c: c.id, reverse=True)],
        user_disputes=[service.dispute_json(d, detail=False) for d in reversed(user.background_disputes)],
        clearance=service.clearance(user).as_dict(),
    )


@admin_api_bp.route("/background-checks/<int:check_id>/decision", methods=["POST"])
@csrf.exempt  # bearer-token API: no browser, no cookies
def decide_check(check_id: int):
    actor, err = _actor()
    if err:
        return err
    check = db.session.get(BackgroundCheck, check_id)
    if check is None:
        return jsonify(error="not_found"), 404
    decision, note = _decision_body()
    if decision not in ("approve", "reject"):
        return jsonify(error="decision must be 'approve' or 'reject'"), 400
    try:
        service.adjudicate(check, decision, actor=actor, note=note)
    except DecisionConflictError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 409
    except BackgroundCheckInputError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 400
    return jsonify(check=service.check_json(check), clearance=service.clearance(check.user).as_dict())


# ------------------------------------------------------------------ disputes

@admin_api_bp.route("/disputes")
def list_disputes():
    limit, offset = _page_args()
    q = BackgroundDispute.query
    status = request.args.get("status", "").strip()
    if status == "open":
        q = q.filter(BackgroundDispute.status.in_(("rechecking", "under_review")))
    elif status:
        if status not in DISPUTE_STATUSES:
            return jsonify(error=f"unknown status '{status}'"), 400
        q = q.filter(BackgroundDispute.status == status)
    total = q.count()
    rows = q.order_by(BackgroundDispute.id.desc()).offset(offset).limit(limit).all()
    return jsonify(total=total, limit=limit, offset=offset, items=[service.dispute_json(d, detail=False) for d in rows])


@admin_api_bp.route("/disputes/<int:dispute_id>")
def get_dispute(dispute_id: int):
    dispute = db.session.get(BackgroundDispute, dispute_id)
    if dispute is None:
        return jsonify(error="not_found"), 404
    return jsonify(dispute=service.dispute_json(dispute), clearance=service.clearance(dispute.user).as_dict())


@admin_api_bp.route("/disputes/<int:dispute_id>/decision", methods=["POST"])
@csrf.exempt  # bearer-token API: no browser, no cookies
def decide_dispute(dispute_id: int):
    actor, err = _actor()
    if err:
        return err
    dispute = db.session.get(BackgroundDispute, dispute_id)
    if dispute is None:
        return jsonify(error="not_found"), 404
    decision, note = _decision_body()
    if decision not in ("approve", "reject"):
        return jsonify(error="decision must be 'approve' or 'reject'"), 400
    try:
        service.decide_dispute(dispute, decision, actor=actor, note=note)
    except DecisionConflictError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 409
    except BackgroundCheckInputError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 400
    return jsonify(dispute=service.dispute_json(dispute), clearance=service.clearance(dispute.user).as_dict())


# ------------------------------------------------------------------ users

USER_ROLES = ("buyer", "seller", "both")
USER_SORTS = ("newest", "oldest", "username", "age_asc", "age_desc")


def _age_arg(name: str):
    raw = request.args.get(name, "").strip()
    if raw == "":
        return None
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be a whole number") from None
    if not 0 <= value <= 150:
        raise ValueError(f"{name} must be between 0 and 150")
    return value


@admin_api_bp.route("/users")
def list_users():
    """
    All user accounts, filterable by role, status (background-check standing), name and age range.
    Role and name are filtered in SQL; status and age need the standing / the decrypted date of
    birth, so they are evaluated here (related rows are eager-loaded: no query per user).
    """
    limit, offset = _page_args()
    role = request.args.get("role", "").strip()
    status = request.args.get("status", "").strip()
    text = request.args.get("q", "").strip()[:80]
    sort = request.args.get("sort", "newest").strip() or "newest"
    try:
        min_age, max_age = _age_arg("min_age"), _age_arg("max_age")
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if role and role not in USER_ROLES:
        return jsonify(error=f"unknown role '{role}'"), 400
    if status and status not in service.USER_STATES:
        return jsonify(error=f"unknown status '{status}'"), 400
    if sort not in USER_SORTS:
        return jsonify(error=f"unknown sort '{sort}'"), 400
    if min_age is not None and max_age is not None and min_age > max_age:
        return jsonify(error="min_age must not be greater than max_age"), 400

    q = User.query.options(selectinload(User.background_checks), selectinload(User.background_disputes),
                           selectinload(User.oauth_accounts), selectinload(User.driver_profile))
    if role:
        q = q.filter(User.role == role)
    if text:
        like = f"%{text}%"
        q = q.filter(or_(User.username.ilike(like), User.display_name.ilike(like), User.email.ilike(like)))
    rows = [service.user_summary(u) for u in q.all()]
    if status:
        rows = [r for r in rows if r["state"] == status]
    if min_age is not None or max_age is not None:
        rows = [r for r in rows if r["age"] is not None
                and (min_age is None or r["age"] >= min_age) and (max_age is None or r["age"] <= max_age)]
    if sort in ("newest", "oldest"):
        rows.sort(key=lambda r: (r["created_at"] or "", r["id"]), reverse=sort == "newest")
    elif sort == "username":
        rows.sort(key=lambda r: r["username"].lower())
    else:  # by age; users without an age last
        known = sorted((r for r in rows if r["age"] is not None), key=lambda r: r["age"], reverse=sort == "age_desc")
        rows = known + [r for r in rows if r["age"] is None]
    return jsonify(total=len(rows), limit=limit, offset=offset, items=rows[offset:offset + limit],
                   filters={"role": role or None, "status": status or None, "q": text or None,
                            "min_age": min_age, "max_age": max_age, "sort": sort},
                   roles=list(USER_ROLES), statuses=list(service.USER_STATES), sorts=list(USER_SORTS))


@admin_api_bp.route("/users/<int:user_id>")
def get_user(user_id: int):
    user = db.session.get(User, user_id)
    if user is None:
        return jsonify(error="not_found"), 404
    drv = user.driver_profile
    rides_as_driver = RideRequest.query.filter_by(driver_id=drv.id).count() if drv is not None else 0
    return jsonify(
        user=service.user_summary(user),
        clearance=service.clearance(user).as_dict(),
        checks=[service.check_json(c) for c in sorted(user.background_checks, key=lambda c: c.id, reverse=True)],
        disputes=[service.dispute_json(d, detail=False) for d in reversed(user.background_disputes)],
        driver=None if drv is None else {
            "vehicle": drv.vehicle, "online": drv.is_online, "rating": round(drv.rating, 2),
            "rating_count": drv.rating_count, "acceptance_rate": round(drv.acceptance_rate, 3),
        },
        activity={
            "rides_as_rider": RideRequest.query.filter_by(rider_id=user.id).count(),
            "rides_as_driver": rides_as_driver,
            "payment_methods": PaymentMethod.query.filter_by(user_id=user.id, deleted_at=None).count(),
        },
    )


# ------------------------------------------------------------------ financial transactions

@admin_api_bp.route("/users/<int:user_id>/transactions")
def user_transactions(user_id: int):
    from payments import ledger

    user = db.session.get(User, user_id)
    if user is None:
        return jsonify(error="not_found"), 404
    limit, offset = _page_args()
    try:
        rep = ledger.report(user, date_from=request.args.get("date_from"), date_to=request.args.get("date_to"),
                            method=request.args.get("method"), ttype=request.args.get("type"))
    except ledger.LedgerFilterError as exc:
        return jsonify(error=str(exc)), 400
    items = rep.pop("items")
    return jsonify(total=len(items), limit=limit, offset=offset, items=items[offset:offset + limit],
                   user={"id": user.id, "username": user.username}, **rep)


@admin_api_bp.route("/transactions/<int:tx_id>")
def get_transaction(tx_id: int):
    from payments import ledger

    tx = db.session.get(PaymentTransaction, tx_id)
    if tx is None:
        return jsonify(error="not_found"), 404
    return jsonify(transaction=ledger.transaction_row(tx), user={"id": tx.user_id, "username": tx.user.username})


@admin_api_bp.route("/transactions/<int:tx_id>/refund", methods=["POST"])
@csrf.exempt  # bearer-token API: no browser, no cookies
def refund_transaction(tx_id: int):
    from payments import ledger
    from payments.service import RefundError, refund_charge

    actor, err = _actor()
    if err:
        return err
    tx = db.session.get(PaymentTransaction, tx_id)
    if tx is None:
        return jsonify(error="not_found"), 404
    data = request.get_json(silent=True) or {}
    try:
        refund = refund_charge(tx, data.get("amount"), str(data.get("reason") or ""), actor)
    except RefundError as exc:
        db.session.rollback()
        return jsonify(error=str(exc)), 409 if exc.conflict else 400
    from auth.audit import record

    record("payment_refunded" if refund.status == "succeeded" else "payment_refund_failed", tx.user_id,
           f"{refund.currency} {refund.amount:.2f} of tx #{tx.id} by {actor}")
    body = {"refund": ledger.transaction_row(refund), "transaction": ledger.transaction_row(tx)}
    if refund.status != "succeeded":
        from payments.cards import failure_message

        return jsonify(error=f"The refund failed: {failure_message(refund.failure_reason)}", **body), 402
    return jsonify(body)
