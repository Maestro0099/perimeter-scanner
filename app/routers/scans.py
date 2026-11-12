"""Сканирования: запуск, ход выполнения, результаты."""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import client_ip, current_user, require_admin
from app.config import get_settings
from app.db import get_db
from app.models import SEVERITY_ORDER, Change, Finding, Group, Scan, ScanStatus, Target, User
from app.scanner.engine import ScanRequestError, active_scans, create_scan, scan_manager, scan_xml_path
from app.scanner.nmap_profiles import PROFILES
from app.scanner.nmap_runner import nmap_available
from app.templating import render

router = APIRouter()


def _redirect(url: str, msg: str = "", err: str = "") -> RedirectResponse:
    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    return RedirectResponse(url + ("?" + urlencode(params) if params else ""), status_code=303)


def severity_counts(db: Session, scan_id: int) -> dict[str, int]:
    rows = db.execute(
        select(Finding.severity, func.count()).where(Finding.scan_id == scan_id).group_by(Finding.severity)
    ).all()
    return {sev: cnt for sev, cnt in rows}


@router.get("/scans")
def scans_page(
    request: Request,
    msg: str = "",
    err: str = "",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    scans = list(db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(300)))
    counts: dict[int, dict[str, int]] = {}
    if scans:
        rows = db.execute(
            select(Finding.scan_id, Finding.severity, func.count())
            .where(Finding.scan_id.in_([s.id for s in scans]))
            .group_by(Finding.scan_id, Finding.severity)
        ).all()
        for sid, sev, cnt in rows:
            counts.setdefault(sid, {})[sev] = cnt
    return render(request, "scans/list.html", {"scans": scans, "counts": counts, "msg": msg, "err": err})


@router.get("/scans/new")
def new_scan_page(
    request: Request,
    group: int | None = None,
    target: int | None = None,
    err: str = "",
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    targets = list(db.scalars(select(Target).where(Target.approved.is_(True)).order_by(Target.kind, Target.value)))
    groups = list(db.scalars(select(Group).order_by(Group.name)))
    return render(
        request,
        "scans/new.html",
        {
            "targets": targets,
            "groups": groups,
            "profiles": PROFILES,
            "default_timing": get_settings().nmap_timing,
            "preselect_group": group,
            "preselect_target": target,
            "nmap_ok": nmap_available(get_settings().nmap_path),
            "privileged": get_settings().nmap_privileged,
            "err": err,
        },
    )


@router.post("/scans")
async def start_scan(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)) -> Response:
    form = await request.form()
    try:
        target_ids = sorted({int(v) for v in form.getlist("target_ids") if str(v).isdigit()})
        group_raw = str(form.get("group_id") or "")
        group_id = int(group_raw) if group_raw.isdigit() else None
        if group_id and not target_ids:
            group = db.get(Group, group_id)
            if not group:
                raise ScanRequestError("Группа не найдена")
            target_ids = [t.id for t in group.targets if t.approved]
        profile = str(form.get("profile") or "quick")
        timing_raw = str(form.get("timing") or "")
        timing = int(timing_raw) if timing_raw.isdigit() else None
        confirmed = form.get("confirm_aggressive") == "on" and str(form.get("confirm_text", "")).strip().upper() == "ПОДТВЕРЖДАЮ"
        scan = create_scan(
            db,
            target_ids=target_ids,
            profile=profile,
            timing=timing,
            username=user.username,
            ip=client_ip(request),
            trigger="manual",
            group_id=group_id,
            aggressive_confirmed=confirmed,
        )
    except ScanRequestError as exc:
        return _redirect("/scans/new", err=str(exc))
    return RedirectResponse(f"/scans/{scan.id}", status_code=303)


@router.get("/scans/indicator")
def scans_indicator(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    return render(request, "scans/_indicator.html", {"active": active_scans(db)})


@router.get("/scans/{scan_id}")
def scan_detail(
    request: Request, scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Скан не найден")
    findings = sorted(scan.findings, key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.asset, f.port or 0))
    changes = list(db.scalars(select(Change).where(Change.scan_id == scan_id).order_by(Change.id)))
    from app.models import DomainResult, TlsResult, WebResult

    return render(
        request,
        "scans/detail.html",
        {
            "scan": scan,
            "profile": PROFILES.get(scan.profile),
            "hosts": sorted(scan.hosts, key=lambda h: h.ip),
            "findings": findings,
            "counts": severity_counts(db, scan_id),
            "changes": changes,
            "domains": list(db.scalars(select(DomainResult).where(DomainResult.scan_id == scan_id))),
            "web": list(db.scalars(select(WebResult).where(WebResult.scan_id == scan_id))),
            "tls": list(db.scalars(select(TlsResult).where(TlsResult.scan_id == scan_id))),
            "has_xml": scan_xml_path(scan_id).is_file(),
        },
    )


@router.get("/scans/{scan_id}/progress")
def scan_progress(
    request: Request, scan_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Скан не найден")
    resp = render(request, "scans/_progress.html", {"scan": scan})
    if not scan.is_active and request.headers.get("hx-request"):
        # скан завершился — перезагружаем страницу, чтобы показать результаты
        resp.headers["HX-Refresh"] = "true"
    return resp


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(
    request: Request, scan_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Скан не найден")
    if scan.is_active:
        scan_manager.cancel(scan_id)
        audit(db, "scan_cancel", f"Скан #{scan_id}", username=user.username, ip=client_ip(request))
    return _redirect(f"/scans/{scan_id}")


@router.post("/scans/{scan_id}/delete")
def delete_scan(
    request: Request, scan_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Скан не найден")
    if scan.is_active:
        return _redirect("/scans", err="Нельзя удалить выполняющийся скан — сначала отмените его")
    db.delete(scan)
    db.commit()
    xml = scan_xml_path(scan_id)
    if xml.parent.is_dir():
        for f in xml.parent.iterdir():
            f.unlink(missing_ok=True)
        xml.parent.rmdir()
    audit(db, "scan_delete", f"Скан #{scan_id}", username=user.username, ip=client_ip(request))
    return _redirect("/scans", msg=f"Скан #{scan_id} удалён")


@router.get("/scans/{scan_id}/nmap.xml")
def scan_xml(scan_id: int, user: User = Depends(require_admin)) -> Response:
    path = scan_xml_path(scan_id)
    if not path.is_file():
        raise HTTPException(404, "XML-вывод nmap не найден")
    return FileResponse(path, media_type="application/xml", filename=f"scan-{scan_id}-nmap.xml")


_ = ScanStatus  # для шаблонов
