"""Сводный отчёт по периметру и экспорт."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.auth import current_user
from app.db import get_db
from app.models import User, utcnow
from app.reports.builder import perimeter_report
from app.routers.exports import export_response
from app.templating import render

router = APIRouter()


@router.get("/reports")
def reports_page(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    return render(request, "reports/index.html", {"r": perimeter_report(db)})


@router.get("/reports/perimeter.{fmt}")
def perimeter_export(
    request: Request, fmt: str, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    return export_response(request, db, user, perimeter_report(db), fmt, f"perimeter-{utcnow():%Y%m%d-%H%M}")
