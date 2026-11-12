"""Страницы активов: IP-адреса и домены."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.analysis.state import asset_index
from app.auth import current_user
from app.db import get_db
from app.models import User, utcnow
from app.reports.builder import domain_report, ip_report
from app.routers.exports import export_response
from app.templating import render
from app.validation import ValidationError, normalize_domain

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
