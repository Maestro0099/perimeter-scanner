"""Журнал аудита."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import require_admin
from app.db import get_db
from app.models import AuditLog, User
from app.templating import render

router = APIRouter()

ACTION_LABELS = {
    "login": "Вход",
    "login_failed": "Неудачный вход",
    "login_locked": "Блокировка входа",
    "logout": "Выход",
    "password_change": "Смена пароля",
    "target_add": "Добавление целей",
    "target_import": "Импорт целей",
    "target_edit": "Изменение цели",
    "target_delete": "Удаление цели",
    "group_create": "Создание группы",
    "group_delete": "Удаление группы",
    "user_create": "Создание пользователя",
    "user_update": "Изменение пользователя",
    "user_delete": "Удаление пользователя",
    "scan_start": "Запуск сканирования",
    "scan_cancel": "Отмена сканирования",
    "scan_delete": "Удаление скана",
    "schedule_create": "Создание расписания",
    "schedule_update": "Изменение расписания",
    "schedule_delete": "Удаление расписания",
    "settings_update": "Изменение настроек",
    "notify_test": "Тест уведомлений",
    "report_export": "Экспорт отчёта",
    "subdomain_promote": "Поддомен добавлен в цели",
    "active_test_start": "Запуск активной проверки",
    "active_test_finding": "Находка активной проверки",
    "active_test_cancel": "Отмена активной проверки",
    "active_test_delete": "Удаление активной проверки",
}


@router.get("/audit")
def audit_page(
    request: Request,
    action: str = "",
    username: str = "",
    page: int = 1,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    per_page = 100
    page = max(1, page)
    q = select(AuditLog).order_by(AuditLog.ts.desc())
    if action:
        q = q.where(AuditLog.action == action)
    if username:
        q = q.where(AuditLog.username == username[:64])
    rows = list(db.scalars(q.offset((page - 1) * per_page).limit(per_page + 1)))
    return render(
        request,
        "settings/audit.html",
        {
            "rows": rows[:per_page],
            "has_next": len(rows) > per_page,
            "page": page,
            "f_action": action,
            "f_username": username,
            "ACTION_LABELS": ACTION_LABELS,
        },
    )
