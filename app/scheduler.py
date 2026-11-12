"""Регулярные сканирования групп целей (APScheduler)."""

from __future__ import annotations

import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from app.config import get_settings
from app.db import session_scope
from app.models import Schedule, Scan, ScanStatus, utcnow
from app.validation import ValidationError, validate_cron

log = logging.getLogger("scheduler")

_scheduler: BackgroundScheduler | None = None
JOB_PREFIX = "schedule-"


def make_trigger(cron: str) -> CronTrigger:
    """Проверяет cron-выражение и возвращает триггер (ValidationError при ошибке)."""
    cron = validate_cron(cron)
    try:
        return CronTrigger.from_crontab(cron, timezone=get_settings().timezone)
    except ValueError as exc:
        raise ValidationError(f"Некорректное расписание: {exc}") from exc


def run_schedule(schedule_id: int) -> None:
    from app.scanner.engine import ScanRequestError, create_scan

    with session_scope() as db:
        sch = db.get(Schedule, schedule_id)
        if sch is None or not sch.enabled:
            return
        group = sch.group
        busy = db.scalar(
            select(Scan.id).where(
                Scan.group_id == group.id,
                Scan.status.in_([ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]),
            )
        )
        if busy:
            log.info("Расписание #%s пропущено: по группе «%s» уже идёт скан #%s", sch.id, group.name, busy)
            return
        target_ids = [t.id for t in group.targets if t.approved]
        sch.last_run = utcnow()
        if not target_ids:
            log.info("Расписание #%s: в группе «%s» нет утверждённых целей", sch.id, group.name)
            return
        try:
            scan = create_scan(
                db,
                target_ids=target_ids,
                profile=sch.profile,
                timing=None,
                username="расписание",
                trigger="schedule",
                group_id=group.id,
            )
            log.info("Расписание #%s запустило скан #%s", sch.id, scan.id)
        except ScanRequestError as exc:
            log.warning("Расписание #%s не запущено: %s", sch.id, exc)


def sync_jobs() -> None:
    if _scheduler is None:
        return
    with session_scope() as db:
        schedules = list(db.scalars(select(Schedule)))
        wanted = {f"{JOB_PREFIX}{s.id}": s for s in schedules if s.enabled}
        for job in _scheduler.get_jobs():
            if job.id.startswith(JOB_PREFIX) and job.id not in wanted:
                job.remove()
        for job_id, s in wanted.items():
            try:
                trigger = make_trigger(s.cron)
            except ValidationError as exc:
                log.warning("Расписание #%s пропущено: %s", s.id, exc)
                continue
            _scheduler.add_job(
                run_schedule,
                trigger=trigger,
                args=[s.id],
                id=job_id,
                replace_existing=True,
                coalesce=True,
                max_instances=1,
                misfire_grace_time=3600,
            )


def next_run(schedule_id: int) -> datetime | None:
    if _scheduler is None:
        return None
    job = _scheduler.get_job(f"{JOB_PREFIX}{schedule_id}")
    return job.next_run_time if job else None


def start_scheduler() -> None:
    global _scheduler
    if not get_settings().scheduler_enabled or _scheduler is not None:
        return
    _scheduler = BackgroundScheduler(timezone=get_settings().timezone)
    _scheduler.start()
    sync_jobs()
    log.info("Планировщик запущен, заданий: %s", len(_scheduler.get_jobs()))


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
