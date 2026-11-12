"""Дашборд."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import current_user
from app.db import get_db
from app.models import Target, User
from app.templating import render

router = APIRouter()


@router.get("/")
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    counts = dict(db.execute(select(Target.kind, func.count()).group_by(Target.kind)).all())
    return render(request, "dashboard.html", {"counts": counts})
