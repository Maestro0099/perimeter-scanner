"""Общая функция отдачи экспортированного отчёта."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import client_ip
from app.models import User
from app.reports.exporters import EXPORTERS


def export_response(
    request: Request, db: Session, user: User, report: dict[str, Any], fmt: str, filename: str
) -> Response:
    if fmt not in EXPORTERS:
        raise HTTPException(404, "Неизвестный формат экспорта")
    func, media = EXPORTERS[fmt]
    try:
        content = func(report)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    audit(db, "report_export", f"{report.get('title')} ({fmt.upper()})", username=user.username, ip=client_ip(request))
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in filename)
    disposition = "inline" if fmt == "html" else "attachment"
    return Response(
        content,
        media_type=media,
        headers={"Content-Disposition": f'{disposition}; filename="{safe}.{fmt}"'},
    )
