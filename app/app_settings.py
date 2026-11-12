"""Настройки, изменяемые через интерфейс (хранятся в БД). Секреты здесь не хранятся."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import session_scope
from app.models import AppSetting

DEFAULTS: dict[str, str] = {
    "notify_telegram": "false",
    "notify_email": "false",
    "notify_min_severity": "high",
    "notify_on_failure": "true",
    "nmap_timing": "",
    "max_parallel_scans": "",
}


@dataclass
class RuntimeSettings:
    notify_telegram: bool
    notify_email: bool
    notify_min_severity: str
    notify_on_failure: bool
    nmap_timing: int
    max_parallel_scans: int


def _raw(db: Session) -> dict[str, str]:
    values = dict(DEFAULTS)
    for row in db.query(AppSetting).all():
        values[row.key] = row.value
    return values


def load(db: Session | None = None) -> RuntimeSettings:
    if db is None:
        with session_scope() as s:
            return load(s)
    v = _raw(db)
    env = get_settings()
    timing = int(v["nmap_timing"]) if v["nmap_timing"].isdigit() else env.nmap_timing
    parallel = int(v["max_parallel_scans"]) if v["max_parallel_scans"].isdigit() else env.max_parallel_scans
    return RuntimeSettings(
        notify_telegram=v["notify_telegram"] == "true",
        notify_email=v["notify_email"] == "true",
        notify_min_severity=v["notify_min_severity"] if v["notify_min_severity"] in ("critical", "high", "medium", "low", "info") else "high",
        notify_on_failure=v["notify_on_failure"] == "true",
        nmap_timing=min(max(timing, 0), 5),
        max_parallel_scans=min(max(parallel, 1), 16),
    )


def save(db: Session, values: dict[str, str]) -> None:
    for key, value in values.items():
        if key not in DEFAULTS:
            raise KeyError(key)
        row = db.get(AppSetting, key)
        if row is None:
            db.add(AppSetting(key=key, value=value))
        else:
            row.value = value
    db.commit()
