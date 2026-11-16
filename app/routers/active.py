"""Активные проверки: подбор учётных данных (Hydra). Только администратор, только вручную."""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.active.engine import (
    WORDLISTS,
    ActiveTestError,
    active_test_manager,
    active_tests,
    create_hydra_test,
    wordlists_by_kind,
)
from app.active.hydra_runner import SERVICES, hydra_available
from app.audit import audit
from app.auth import client_ip, current_user, require_admin
from app.config import get_settings
from app.db import get_db
from app.models import ActiveTest, ScanStatus, Target, User
from app.templating import render

router = APIRouter()


def _redirect(url: str, msg: str = "", err: str = "") -> RedirectResponse:
    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    return RedirectResponse(url + ("?" + urlencode(params) if params else ""), status_code=303)


def _guard() -> None:
    s = get_settings()
    if not s.active_tests_enabled:
        raise HTTPException(404, "Активные проверки отключены")


@router.get("/active")
def active_page(
    request: Request, msg: str = "", err: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    _guard()
    tests = list(db.scalars(select(ActiveTest).order_by(ActiveTest.created_at.desc()).limit(300)))
    return render(request, "active/list.html", {"tests": tests, "msg": msg, "err": err})


@router.get("/active/hydra/new")
def hydra_new(
    request: Request, target: int | None = None, err: str = "", user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    _guard()
    s = get_settings()
    if not s.hydra_enabled:
        raise HTTPException(404, "Подбор учётных данных отключён")
    targets = list(
        db.scalars(select(Target).where(Target.approved.is_(True), Target.kind != "cidr").order_by(Target.kind, Target.value))
    )
    return render(
        request,
        "active/hydra_new.html",
        {
            "targets": targets,
            "services": SERVICES,
            "login_lists": wordlists_by_kind("login"),
            "password_lists": wordlists_by_kind("password"),
            "combo_lists": wordlists_by_kind("combo"),
            "wordlists": WORDLISTS,
            "default_tasks": s.hydra_default_tasks,
            "max_tasks": s.hydra_max_tasks,
            "max_attempts": s.hydra_max_attempts,
            "preselect_target": target,
            "hydra_ok": hydra_available(s.hydra_path),
            "err": err,
        },
    )


@router.post("/active/hydra")
async def hydra_start(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)) -> Response:
    _guard()
    form = await request.form()

    def val(name: str, default: str = "") -> str:
        v = form.get(name)
        return v if isinstance(v, str) else default

    try:
        target_raw = val("target_id")
        if not target_raw.isdigit():
            raise ActiveTestError("Выберите цель")
        port_raw = val("port")
        test = create_hydra_test(
            db,
            target_id=int(target_raw),
            service=val("service"),
            port=int(port_raw) if port_raw.isdigit() else None,
            login_list=val("login_list"),
            password_list=val("password_list"),
            combo_list=val("combo_list"),
            module_option=val("module_option"),
            tasks=int(val("tasks")) if val("tasks").isdigit() else 0,
            stop_on_first=val("stop_on_first") == "on",
            authorization=val("authorization"),
            confirm=val("confirm") == "on",
            confirm_text=val("confirm_text"),
            username=user.username,
            ip=client_ip(request),
        )
    except ActiveTestError as exc:
        return _redirect("/active/hydra/new", err=str(exc))
    return RedirectResponse(f"/active/{test.id}", status_code=303)


@router.get("/active/indicator")
def active_indicator(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    return render(request, "active/_indicator.html", {"active": active_tests(db)})


@router.get("/active/{test_id}")
def active_detail(
    request: Request, test_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    _guard()
    test = db.get(ActiveTest, test_id)
    if not test:
        raise HTTPException(404, "Проверка не найдена")
    return render(request, "active/detail.html", {"test": test, "services": SERVICES})


@router.get("/active/{test_id}/progress")
def active_progress(
    request: Request, test_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    test = db.get(ActiveTest, test_id)
    if not test:
        raise HTTPException(404, "Проверка не найдена")
    resp = render(request, "active/_progress.html", {"test": test})
    if not test.is_active and request.headers.get("hx-request"):
        resp.headers["HX-Refresh"] = "true"
    return resp


@router.post("/active/{test_id}/cancel")
def active_cancel(
    request: Request, test_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    test = db.get(ActiveTest, test_id)
    if not test:
        raise HTTPException(404, "Проверка не найдена")
    if test.is_active:
        active_test_manager.cancel(test_id)
        audit(db, "active_test_cancel", f"#{test_id}", username=user.username, ip=client_ip(request))
    return _redirect(f"/active/{test_id}")


@router.post("/active/{test_id}/delete")
def active_delete(
    request: Request, test_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    test = db.get(ActiveTest, test_id)
    if not test:
        raise HTTPException(404, "Проверка не найдена")
    if test.is_active:
        return _redirect("/active", err="Нельзя удалить выполняющуюся проверку — сначала отмените её")
    db.delete(test)
    db.commit()
    workdir = get_settings().data_dir / "active" / str(test_id)
    if workdir.is_dir():
        for f in workdir.iterdir():
            f.unlink(missing_ok=True)
        workdir.rmdir()
    audit(db, "active_test_delete", f"#{test_id}", username=user.username, ip=client_ip(request))
    return _redirect("/active", msg=f"Проверка #{test_id} удалена")


_ = ScanStatus
