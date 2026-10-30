"""Security audit logging."""

import logging

from flask import request

from extensions import db
from models import AuthEvent

log = logging.getLogger("auth.audit")


def record(event: str, user_id: int | None = None, detail: str | None = None, commit: bool = True) -> None:
    """Persist an auth event and mirror it to the application log."""
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")[:45] if request else None
    ua = (request.user_agent.string or "")[:255] if request else None
    db.session.add(AuthEvent(user_id=user_id, event=event, detail=detail, ip_address=ip, user_agent=ua))
    if commit:
        db.session.commit()
    log.info("auth_event=%s user_id=%s ip=%s detail=%s", event, user_id, ip, detail)
