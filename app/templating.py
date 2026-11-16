"""Настройка Jinja2: фильтры, глобальные переменные, русская локализация."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import Request
from fastapi.templating import Jinja2Templates

from app.config import BASE_DIR, get_settings
from app.analysis.severity import SEVERITY_LABELS, SEVERITY_ORDER_LIST
from app.models import ACTIVE_TEST_LABELS

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

STATUS_LABELS = {
    "queued": "В очереди",
    "running": "Выполняется",
    "done": "Завершён",
    "failed": "Ошибка",
    "cancelled": "Отменён",
}
PROFILE_LABELS = {"quick": "Быстрый", "full": "Полный", "aggressive": "Агрессивный", "checks": "Проверки"}
KIND_LABELS = {"ip": "IP-адрес", "cidr": "Подсеть", "domain": "Домен"}
CATEGORY_LABELS = {
    "port": "Порт/сервис",
    "vuln": "Уязвимость",
    "dns": "DNS",
    "mail": "Почта",
    "web": "Веб",
    "tls": "TLS",
    "whois": "WHOIS",
}
CHANGE_LABELS = {
    "port_opened": "Новый порт",
    "port_closed": "Порт закрыт",
    "service_changed": "Сменилась версия",
    "vuln_new": "Новая уязвимость",
    "vuln_fixed": "Уязвимость устранена",
    "subdomain_new": "Новый поддомен",
    "subdomain_gone": "Поддомен исчез",
    "host_up": "Новый хост",
    "host_down": "Хост недоступен",
    "finding_new": "Новая находка",
    "finding_resolved": "Находка устранена",
}


def _tz() -> ZoneInfo:
    try:
        return ZoneInfo(get_settings().timezone)
    except Exception:  # noqa: BLE001
        return ZoneInfo("UTC")


def fmt_dt(value: datetime | None, fmt: str = "%d.%m.%Y %H:%M") -> str:
    if not value:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_tz()).strftime(fmt)


def fmt_duration(seconds: int | None) -> str:
    if seconds is None:
        return "—"
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} ч {m} мин"
    if m:
        return f"{m} мин {s} с"
    return f"{s} с"


def plural(n: int, one: str, few: str, many: str) -> str:
    n = abs(int(n))
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def csrf_token(request: Request) -> str:
    return getattr(request.state, "csrf_token", "")


templates.env.filters.update(dt=fmt_dt, duration=fmt_duration)
templates.env.globals.update(
    app_name=get_settings().app_name,
    SEVERITY_LABELS=SEVERITY_LABELS,
    SEVERITY_ORDER_LIST=SEVERITY_ORDER_LIST,
    STATUS_LABELS=STATUS_LABELS,
    PROFILE_LABELS=PROFILE_LABELS,
    KIND_LABELS=KIND_LABELS,
    CATEGORY_LABELS=CATEGORY_LABELS,
    CHANGE_LABELS=CHANGE_LABELS,
    ACTIVE_TEST_LABELS=ACTIVE_TEST_LABELS,
    plural=plural,
    csrf_token=csrf_token,
)


def render(request: Request, name: str, context: dict[str, Any] | None = None, status_code: int = 200):  # type: ignore[no-untyped-def]
    ctx: dict[str, Any] = {
        "user": getattr(request.state, "user", None),
        "active_tests_enabled": get_settings().active_tests_enabled,
    }
    if context:
        ctx.update(context)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)
