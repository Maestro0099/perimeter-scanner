"""Вход и выход."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import SESSION_COOKIE, client_ip, create_session, destroy_session, user_from_request
from app.config import get_settings
from app.db import get_db
from app.models import User
from app.security.passwords import hash_password, needs_rehash, verify_password
from app.security.ratelimit import is_locked, record_attempt
from app.templating import render

router = APIRouter()


def _safe_next(value: str | None) -> str:
    if value and value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return "/"


@router.get("/login")
def login_page(request: Request, next: str = "/", db: Session = Depends(get_db)) -> Response:
    if user_from_request(db, request):
        return RedirectResponse(_safe_next(next), status_code=303)
    return render(request, "auth/login.html", {"next": _safe_next(next), "error": None})


@router.post("/login")
def login(
    request: Request,
    username: str = Form(..., max_length=64),
    password: str = Form(..., max_length=256),
    next: str = Form("/"),
    db: Session = Depends(get_db),
) -> Response:
    ip = client_ip(request)
    username = username.strip()
    if is_locked(db, username, ip):
        audit(db, "login_locked", f"Блокировка входа для «{username}»", username=username, ip=ip)
        s = get_settings()
        return render(
            request,
            "auth/login.html",
            {
                "next": _safe_next(next),
                "error": f"Слишком много неудачных попыток. Повторите через {s.login_lockout_minutes} мин.",
                "username": username,
            },
            status_code=429,
        )
    user = db.scalar(select(User).where(func.lower(User.username) == username.lower()))
    ok = verify_password(user.password_hash if user else None, password)
    if not user or not ok or not user.is_active:
        record_attempt(db, username, ip, success=False)
        audit(db, "login_failed", f"Неудачный вход «{username}»", username=username, ip=ip)
        return render(
            request,
            "auth/login.html",
            {"next": _safe_next(next), "error": "Неверный логин или пароль", "username": username},
            status_code=401,
        )
    record_attempt(db, username, ip, success=True)
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    token = create_session(db, user, request)
    audit(db, "login", "Успешный вход", username=user.username, ip=ip)
    resp = RedirectResponse(_safe_next(next), status_code=303)
    s = get_settings()
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=s.session_ttl_hours * 3600,
        httponly=True,
        secure=s.cookie_secure,
        samesite="strict",
        path="/",
    )
    return resp


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)) -> Response:
    user = user_from_request(db, request)
    destroy_session(db, request.cookies.get(SESSION_COOKIE))
    if user:
        audit(db, "logout", "Выход", username=user.username, ip=client_ip(request))
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp
