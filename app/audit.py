"""Журнал аудита."""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models import AuditLog

log = logging.getLogger("audit")


def audit(db: Session, action: str, details: str = "", username: str = "system", ip: str = "") -> None:
    db.add(AuditLog(action=action, details=details[:4000], username=username, ip=ip))
    db.commit()
    log.info("audit user=%s ip=%s action=%s details=%s", username, ip, action, details)
