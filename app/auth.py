"""Аутентификация, сессии и проверка ролей."""

from __future__ import annotations

from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import Role, User, UserSession, utcnow
from app.security.passwords import hash_password
from app.security.tokens import hash_token, new_token

SESSION_COOKIE = "ps_session"


class LoginRequired(Exception):
    """Перенаправление на страницу входа."""


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def create_session(db: Session, user: User, request: Request) -> str:
    token = new_token()
    s = get_settings()
    db.add(
        UserSession(
            token_hash=hash_token(token),
            user_id=user.id,
            expires_at=utcnow() + timedelta(hours=s.session_ttl_hours),
            ip=client_ip(request),
            user_agent=request.headers.get("user-agent", "")[:255],
        )
    )
    db.execute(delete(UserSession).where(UserSession.expires_at < utcnow()))
    user.last_login = utcnow()
    db.commit()
    return token


def destroy_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(UserSession).where(UserSession.token_hash == hash_token(token)))
        db.commit()


def destroy_user_sessions(db: Session, user_id: int) -> None:
    db.execute(delete(UserSession).where(UserSession.user_id == user_id))
    db.commit()


def user_from_request(db: Session, request: Request) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token or len(token) > 128:
        return None
    sess = db.scalar(select(UserSession).where(UserSession.token_hash == hash_token(token)))
    if not sess or sess.expires_at < utcnow():
        return None
    user = db.get(User, sess.user_id)
    if not user or not user.is_active:
        return None
    return user


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = user_from_request(db, request)
    if user is None:
        if request.headers.get("hx-request"):
            raise HTTPException(status_code=401, headers={"HX-Redirect": "/login"})
        raise LoginRequired()
    request.state.user = user
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Действие доступно только администратору")
    return user


def ensure_initial_admin(db: Session) -> str | None:
    """Создаёт администратора из .env при первом запуске. Возвращает сообщение для лога."""
    if db.scalar(select(User.id).limit(1)) is not None:
        return None
    s = get_settings()
    if not s.admin_password:
        return (
            "Пользователей нет и ADMIN_PASSWORD не задан. Создайте администратора: "
            "docker compose exec app python -m app.cli create-user --admin <логин>"
        )
    from app.validation import validate_password, validate_username

    db.add(
        User(
            username=validate_username(s.admin_username),
            password_hash=hash_password(validate_password(s.admin_password)),
            role=Role.ADMIN.value,
        )
    )
    db.commit()
    return f"Создан администратор {s.admin_username}. Удалите ADMIN_PASSWORD из .env после первого входа."
