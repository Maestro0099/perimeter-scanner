"""Ограничение числа неудачных попыток входа (по логину и по IP)."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import LoginAttempt, utcnow


def is_locked(db: Session, username: str, ip: str) -> bool:
    s = get_settings()
    since = utcnow() - timedelta(minutes=max(s.login_window_minutes, s.login_lockout_minutes))
    for col, val, limit in (
        (LoginAttempt.username, username.lower(), s.login_max_attempts),
        (LoginAttempt.ip, ip, s.login_max_attempts * 4),
    ):
        last_success = db.scalar(
            select(func.max(LoginAttempt.ts)).where(col == val, LoginAttempt.success.is_(True))
        )
        start = max(since, last_success) if last_success else since
        failures = db.scalar(
            select(func.count()).where(col == val, LoginAttempt.success.is_(False), LoginAttempt.ts > start)
        )
        if (failures or 0) >= limit:
            return True
    return False


def record_attempt(db: Session, username: str, ip: str, success: bool) -> None:
    db.add(LoginAttempt(username=username.lower()[:64], ip=ip[:64], success=success))
    # Чистим старые записи, чтобы таблица не росла бесконечно.
    db.execute(delete(LoginAttempt).where(LoginAttempt.ts < utcnow() - timedelta(days=7)))
    db.commit()
