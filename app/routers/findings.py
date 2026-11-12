"""Актуальные находки и лента изменений."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.state import count_by_severity, current_findings
from app.auth import current_user
from app.db import get_db
from app.models import Change, User
from app.templating import render

router = APIRouter()


@router.get("/findings")
def findings_page(
    request: Request, severity: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    findings = current_findings(db)
    return render(
        request,
        "findings/list.html",
        {"findings": findings, "counts": count_by_severity(findings), "f_severity": severity},
    )


@router.get("/changes")
def changes_page(
    request: Request,
    severity: str = "",
    page: int = 1,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    per_page = 100
    page = max(1, page)
    q = select(Change).order_by(Change.id.desc())
    if severity in ("critical", "high", "medium", "low", "info"):
        q = q.where(Change.severity == severity)
    rows = list(db.scalars(q.offset((page - 1) * per_page).limit(per_page + 1)))
    return render(
        request,
        "findings/changes.html",
        {"changes": rows[:per_page], "has_next": len(rows) > per_page, "page": page, "f_severity": severity},
    )
