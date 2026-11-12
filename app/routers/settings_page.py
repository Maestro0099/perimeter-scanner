"""Настройки: уведомления и параметры сканирования."""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app import app_settings
from app.audit import audit
from app.auth import client_ip, require_admin
from app.config import get_settings
from app.db import get_db
from app.models import User
from app.notify.dispatcher import Notification, deliver
from app.notify.email import email_configured
from app.notify.telegram import telegram_configured
from app.scanner.nmap_runner import nmap_available
from app.templating import render
from app.validation import ValidationError, validate_timing

router = APIRouter()


def _redirect(msg: str = "", err: str = "") -> RedirectResponse:
    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    return RedirectResponse("/settings" + ("?" + urlencode(params) if params else ""), status_code=303)


@router.get("/settings")
def settings_page(
    request: Request, msg: str = "", err: str = "", user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    s = get_settings()
    return render(
        request,
        "settings/settings.html",
        {
            "rs": app_settings.load(db),
            "env": s,
            "telegram_ok": telegram_configured(),
            "email_ok": email_configured(),
            "nmap_ok": nmap_available(s.nmap_path),
            "msg": msg,
            "err": err,
        },
    )


@router.post("/settings")
def save_settings(
    request: Request,
    notify_telegram: str = Form(""),
    notify_email: str = Form(""),
    notify_on_failure: str = Form(""),
    notify_min_severity: str = Form("high"),
    nmap_timing: str = Form("3"),
    max_parallel_scans: str = Form("2"),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    try:
        timing = validate_timing(nmap_timing)
        if not max_parallel_scans.isdigit() or not 1 <= int(max_parallel_scans) <= 16:
            raise ValidationError("Лимит параллельных сканов: от 1 до 16")
        if notify_min_severity not in ("critical", "high", "medium", "low", "info"):
            raise ValidationError("Некорректный уровень")
    except ValidationError as exc:
        return _redirect(err=str(exc))
    values = {
        "notify_telegram": "true" if notify_telegram == "on" else "false",
        "notify_email": "true" if notify_email == "on" else "false",
        "notify_on_failure": "true" if notify_on_failure == "on" else "false",
        "notify_min_severity": notify_min_severity,
        "nmap_timing": str(timing),
        "max_parallel_scans": str(int(max_parallel_scans)),
    }
    app_settings.save(db, values)
    audit(db, "settings_update", ", ".join(f"{k}={v}" for k, v in values.items()), username=user.username, ip=client_ip(request))
    return _redirect(msg="Настройки сохранены")


@router.post("/settings/test")
def test_notifications(
    request: Request, channel: str = Form(...), user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    if channel not in ("telegram", "email"):
        return _redirect(err="Неизвестный канал")
    n = Notification(
        subject="[Периметр] Тестовое уведомление",
        header="Тестовое уведомление",
        lines=[("info", f"Проверка канала. Отправил: {user.username}")],
        link=get_settings().public_url,
    )
    errors = deliver(n, telegram=channel == "telegram", email=channel == "email")
    audit(db, "notify_test", channel, username=user.username, ip=client_ip(request))
    configured = telegram_configured() if channel == "telegram" else email_configured()
    if not configured:
        return _redirect(err="Канал не настроен: заполните параметры в .env и перезапустите приложение")
    return _redirect(err="; ".join(errors)) if errors else _redirect(msg="Тестовое сообщение отправлено")
