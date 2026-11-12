"""Страницы активов: IP-адреса и домены."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import client_ip, require_admin
from app.models import Target
from app.targets_service import create_or_update_target

from app.analysis.state import asset_index
from app.auth import current_user
from app.db import get_db
from app.models import User, utcnow
from app.reports.builder import domain_report, ip_report
from app.routers.exports import export_response
from app.templating import render
from app.validation import ValidationError, is_subdomain_of, normalize_domain

router = APIRouter()


def _check_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(404, "Некорректный IP-адрес") from exc


def _check_domain(name: str) -> str:
    try:
        return normalize_domain(name)
    except ValidationError as exc:
        raise HTTPException(404, "Некорректное доменное имя") from exc


@router.get("/assets/ip")
def ip_list(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    assets = [a for a in asset_index(db) if a["type"] == "ip"]
    return render(request, "assets/list.html", {"assets": assets, "kind": "ip"})


@router.get("/assets/domain")
def domain_list(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    assets = [a for a in asset_index(db) if a["type"] == "domain"]
    return render(request, "assets/list.html", {"assets": assets, "kind": "domain"})


@router.get("/assets/ip/{ip}")
def ip_page(request: Request, ip: str, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    report = ip_report(db, _check_ip(ip))
    if report is None:
        raise HTTPException(404, "По этому адресу ещё нет результатов сканирования")
    return render(request, "assets/ip.html", {"r": report})


@router.get("/assets/ip/{ip}/export.{fmt}")
def ip_export(
    request: Request, ip: str, fmt: str, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    ip = _check_ip(ip)
    report = ip_report(db, ip)
    if report is None:
        raise HTTPException(404, "Нет данных")
    return export_response(request, db, user, report, fmt, f"ip-{ip}-{utcnow():%Y%m%d}")


@router.get("/assets/domain/{name}")
def domain_page(request: Request, name: str, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    report = domain_report(db, _check_domain(name))
    if report is None:
        raise HTTPException(404, "По этому домену ещё нет результатов")
    return render(request, "assets/domain.html", {"r": report})


@router.get("/assets/domain/{name}/export.{fmt}")
def domain_export(
    request: Request, name: str, fmt: str, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    name = _check_domain(name)
    report = domain_report(db, name)
    if report is None:
        raise HTTPException(404, "Нет данных")
    return export_response(request, db, user, report, fmt, f"domain-{name}-{utcnow():%Y%m%d}")


@router.post("/assets/domain/{name}/promote")
def promote_subdomain(
    request: Request,
    name: str,
    sub: str = Form("", alias="name"),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    """Добавить обнаруженный поддомен в утверждённые цели (только поддомены уже утверждённого домена)."""
    parent = _check_domain(name)
    try:
        child = normalize_domain(sub)
    except ValidationError as exc:
        raise HTTPException(400, str(exc)) from exc
    parent_target = db.scalar(select(Target).where(Target.value == parent, Target.approved.is_(True)))
    if parent_target is None or not is_subdomain_of(child, parent) or child == parent:
        raise HTTPException(400, "Можно добавить только поддомен утверждённого домена")
    try:
        target, created = create_or_update_target(
            db, child, group=parent_target.group, description=f"Поддомен {parent}", source="promoted",
            created_by=user.username,
        )
    except ValidationError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.commit()
    audit(db, "subdomain_promote", child, username=user.username, ip=client_ip(request))
    return RedirectResponse(f"/assets/domain/{parent}", status_code=303)
