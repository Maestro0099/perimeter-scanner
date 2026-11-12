"""Расписание регулярных сканирований по группам целей."""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import client_ip, require_admin
from app.db import get_db
from app.models import Group, Schedule, User
from app.scanner.nmap_profiles import PROFILES, SCHEDULABLE_PROFILES
from app.scheduler import make_trigger, next_run, run_schedule, sync_jobs
from app.templating import render
from app.validation import ValidationError

router = APIRouter()

PRESETS = [
    ("0 3 * * *", "Ежедневно в 03:00"),
    ("0 2 * * 6", "Еженедельно, суббота 02:00"),
    ("0 1 1 * *", "Ежемесячно, 1-го числа в 01:00"),
    ("0 */6 * * *", "Каждые 6 часов"),
]


def _redirect(msg: str = "", err: str = "") -> RedirectResponse:
    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    return RedirectResponse("/schedules" + ("?" + urlencode(params) if params else ""), status_code=303)


@router.get("/schedules")
def schedules_page(
    request: Request, msg: str = "", err: str = "", user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    schedules = list(db.scalars(select(Schedule).join(Group).order_by(Group.name, Schedule.profile)))
    return render(
        request,
        "settings/schedules.html",
        {
            "schedules": schedules,
            "next_runs": {s.id: next_run(s.id) for s in schedules},
            "groups": list(db.scalars(select(Group).order_by(Group.name))),
            "profiles": {k: PROFILES[k] for k in SCHEDULABLE_PROFILES},
            "presets": PRESETS,
            "msg": msg,
            "err": err,
        },
    )


@router.post("/schedules")
def create_schedule(
    request: Request,
    group_id: int = Form(...),
    profile: str = Form(...),
    cron: str = Form(..., max_length=100),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    group = db.get(Group, group_id)
    if not group:
        return _redirect(err="Группа не найдена")
    if profile not in SCHEDULABLE_PROFILES:
        return _redirect(err="Этот профиль нельзя запускать по расписанию")
    try:
        make_trigger(cron)
    except ValidationError as exc:
        return _redirect(err=str(exc))
    if db.scalar(select(Schedule).where(Schedule.group_id == group_id, Schedule.profile == profile)):
        return _redirect(err="Для этой группы и профиля расписание уже существует — измените его")
    sch = Schedule(group_id=group_id, profile=profile, cron=" ".join(cron.split()), enabled=True)
    db.add(sch)
    db.commit()
    sync_jobs()
    audit(db, "schedule_create", f"{group.name}: {PROFILES[profile].title}, «{sch.cron}»", username=user.username, ip=client_ip(request))
    return _redirect(msg="Расписание создано")


@router.post("/schedules/{schedule_id}/update")
def update_schedule(
    request: Request,
    schedule_id: int,
    cron: str = Form(..., max_length=100),
    enabled: str = Form(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    sch = db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(404, "Расписание не найдено")
    try:
        make_trigger(cron)
    except ValidationError as exc:
        return _redirect(err=str(exc))
    sch.cron = " ".join(cron.split())
    sch.enabled = enabled == "on"
    db.commit()
    sync_jobs()
    audit(db, "schedule_update", f"#{sch.id} {sch.group.name}: «{sch.cron}», включено={sch.enabled}", username=user.username, ip=client_ip(request))
    return _redirect(msg="Расписание обновлено")


@router.post("/schedules/{schedule_id}/run")
def run_now(
    request: Request, schedule_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    sch = db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(404, "Расписание не найдено")
    audit(db, "scan_start", f"Внеплановый запуск расписания #{sch.id} ({sch.group.name})", username=user.username, ip=client_ip(request))
    run_schedule(sch.id)
    return RedirectResponse("/scans", status_code=303)


@router.post("/schedules/{schedule_id}/delete")
def delete_schedule(
    request: Request, schedule_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    sch = db.get(Schedule, schedule_id)
    if not sch:
        raise HTTPException(404, "Расписание не найдено")
    desc = f"#{sch.id} {sch.group.name}"
    db.delete(sch)
    db.commit()
    sync_jobs()
    audit(db, "schedule_delete", desc, username=user.username, ip=client_ip(request))
    return _redirect(msg="Расписание удалено")
