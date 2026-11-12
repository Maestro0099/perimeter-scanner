"""Управление пользователями (только администратор) и смена своего пароля."""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import client_ip, current_user, destroy_user_sessions, require_admin
from app.db import get_db
from app.models import Role, User
from app.security.passwords import hash_password, verify_password
from app.templating import render
from app.validation import ValidationError, validate_password, validate_username

router = APIRouter()


def _redirect(url: str, msg: str = "", err: str = "") -> RedirectResponse:
    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    return RedirectResponse(url + ("?" + urlencode(params) if params else ""), status_code=303)


@router.get("/users")
def users_page(
    request: Request, msg: str = "", err: str = "", user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    users = list(db.scalars(select(User).order_by(User.username)))
    return render(request, "settings/users.html", {"users": users, "msg": msg, "err": err})


@router.post("/users")
def create_user(
    request: Request,
    username: str = Form(..., max_length=64),
    password: str = Form(..., max_length=256),
    role: str = Form("viewer"),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    try:
        username = validate_username(username)
        validate_password(password)
        if role not in (Role.ADMIN.value, Role.VIEWER.value):
            raise ValidationError("Некорректная роль")
        if db.scalar(select(User).where(func.lower(User.username) == username.lower())):
            raise ValidationError("Пользователь с таким логином уже существует")
    except ValidationError as exc:
        return _redirect("/users", err=str(exc))
    db.add(User(username=username, password_hash=hash_password(password), role=role))
    db.commit()
    audit(db, "user_create", f"{username} ({role})", username=user.username, ip=client_ip(request))
    return _redirect("/users", msg=f"Пользователь {username} создан")


@router.post("/users/{user_id}/update")
def update_user(
    request: Request,
    user_id: int,
    role: str = Form(...),
    is_active: str = Form(""),
    new_password: str = Form("", max_length=256),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if role not in (Role.ADMIN.value, Role.VIEWER.value):
        return _redirect("/users", err="Некорректная роль")
    active = is_active == "on"
    if target.id == user.id and (role != Role.ADMIN.value or not active):
        return _redirect("/users", err="Нельзя понизить роль или отключить собственную учётную запись")
    if target.is_admin and (role != Role.ADMIN.value or not active):
        admins = db.scalar(select(func.count()).where(User.role == Role.ADMIN.value, User.is_active.is_(True)))
        if (admins or 0) <= 1:
            return _redirect("/users", err="Должен остаться хотя бы один активный администратор")
    target.role = role
    target.is_active = active
    if new_password:
        try:
            target.password_hash = hash_password(validate_password(new_password))
        except ValidationError as exc:
            return _redirect("/users", err=str(exc))
    db.commit()
    if not active or new_password:
        destroy_user_sessions(db, target.id)
    audit(
        db,
        "user_update",
        f"{target.username}: роль={role}, активен={active}, пароль_сменён={bool(new_password)}",
        username=user.username,
        ip=client_ip(request),
    )
    return _redirect("/users", msg=f"Пользователь {target.username} обновлён")


@router.post("/users/{user_id}/delete")
def delete_user(
    request: Request, user_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if target.id == user.id:
        return _redirect("/users", err="Нельзя удалить собственную учётную запись")
    name = target.username
    db.delete(target)
    db.commit()
    audit(db, "user_delete", name, username=user.username, ip=client_ip(request))
    return _redirect("/users", msg=f"Пользователь {name} удалён")


@router.get("/account")
def account_page(request: Request, msg: str = "", err: str = "", user: User = Depends(current_user)) -> Response:
    return render(request, "settings/account.html", {"msg": msg, "err": err})


@router.post("/account/password")
def change_password(
    request: Request,
    current_password: str = Form(..., max_length=256),
    new_password: str = Form(..., max_length=256),
    confirm_password: str = Form(..., max_length=256),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    if not verify_password(user.password_hash, current_password):
        return _redirect("/account", err="Текущий пароль указан неверно")
    if new_password != confirm_password:
        return _redirect("/account", err="Пароли не совпадают")
    try:
        validate_password(new_password)
    except ValidationError as exc:
        return _redirect("/account", err=str(exc))
    db_user = db.get(User, user.id)
    assert db_user is not None
    db_user.password_hash = hash_password(new_password)
    db.commit()
    audit(db, "password_change", "Смена собственного пароля", username=user.username, ip=client_ip(request))
    return _redirect("/account", msg="Пароль изменён")
