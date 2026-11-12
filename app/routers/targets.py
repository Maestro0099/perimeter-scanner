"""Цели сканирования и группы."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import audit
from app.auth import client_ip, current_user, require_admin
from app.db import get_db
from app.models import Group, Tag, Target, User
from app.targets_service import create_or_update_target, get_or_create_group, get_or_create_tags, import_targets_yaml
from app.templating import render
from app.validation import ValidationError, validate_description, validate_name, validate_tags

router = APIRouter()

MAX_YAML_SIZE = 1_000_000


def _flash_redirect(url: str, msg: str = "", err: str = "") -> RedirectResponse:
    from urllib.parse import urlencode

    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    return RedirectResponse(url + ("?" + urlencode(params) if params else ""), status_code=303)


@router.get("/targets")
def targets_page(
    request: Request,
    group: int | None = None,
    tag: str = "",
    kind: str = "",
    msg: str = "",
    err: str = "",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    q = select(Target).order_by(Target.kind, Target.value)
    if group:
        q = q.where(Target.group_id == group)
    if kind in ("ip", "cidr", "domain"):
        q = q.where(Target.kind == kind)
    if tag:
        q = q.where(Target.tags.any(Tag.name == tag))
    targets = list(db.scalars(q))
    groups = list(db.scalars(select(Group).order_by(Group.name)))
    tags = list(db.scalars(select(Tag).order_by(Tag.name)))
    return render(
        request,
        "targets/list.html",
        {
            "targets": targets,
            "groups": groups,
            "tags": tags,
            "f_group": group,
            "f_tag": tag,
            "f_kind": kind,
            "msg": msg,
            "err": err,
        },
    )


@router.post("/targets")
def add_targets(
    request: Request,
    values: str = Form(..., max_length=100_000),
    group_id: str = Form(""),
    new_group: str = Form("", max_length=100),
    tags: str = Form("", max_length=500),
    description: str = Form("", max_length=1000),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    errors: list[str] = []
    added: list[str] = []
    try:
        group = _resolve_group(db, group_id, new_group)
        tag_list = validate_tags(tags)
    except ValidationError as exc:
        return _flash_redirect("/targets", err=str(exc))
    lines = [ln.strip() for ln in values.replace(",", "\n").splitlines() if ln.strip()]
    if len(lines) > 1000:
        return _flash_redirect("/targets", err="Не более 1000 целей за один раз")
    for line in lines:
        try:
            t, _ = create_or_update_target(
                db, line, group=group, description=description, tags=tag_list, created_by=user.username
            )
            added.append(t.value)
        except ValidationError as exc:
            errors.append(f"{line}: {exc}")
    db.commit()
    if added:
        audit(db, "target_add", ", ".join(added)[:3000], username=user.username, ip=client_ip(request))
    return _flash_redirect(
        "/targets",
        msg=f"Добавлено/обновлено целей: {len(added)}" if added else "",
        err="; ".join(errors)[:1500],
    )


def _resolve_group(db: Session, group_id: str, new_group: str) -> Group | None:
    if new_group.strip():
        return get_or_create_group(db, new_group)
    if group_id.strip():
        try:
            gid = int(group_id)
        except ValueError as exc:
            raise ValidationError("Некорректная группа") from exc
        group = db.get(Group, gid)
        if not group:
            raise ValidationError("Группа не найдена")
        return group
    return None


@router.post("/targets/import")
async def import_yaml(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    content = await file.read(MAX_YAML_SIZE + 1)
    if len(content) > MAX_YAML_SIZE:
        return _flash_redirect("/targets", err="Файл слишком большой (максимум 1 МБ)")
    result = import_targets_yaml(db, content, created_by=user.username)
    audit(
        db,
        "target_import",
        f"Импорт YAML: создано {result.created}, обновлено {result.updated}, ошибок {len(result.errors)}",
        username=user.username,
        ip=client_ip(request),
    )
    return _flash_redirect(
        "/targets",
        msg=f"Импорт: создано {result.created}, обновлено {result.updated}",
        err="; ".join(result.errors)[:1500],
    )


@router.get("/targets/{target_id}/edit")
def edit_target_form(
    request: Request, target_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Цель не найдена")
    groups = list(db.scalars(select(Group).order_by(Group.name)))
    return render(request, "targets/edit.html", {"target": target, "groups": groups})


@router.post("/targets/{target_id}/edit")
def edit_target(
    request: Request,
    target_id: int,
    group_id: str = Form(""),
    tags: str = Form("", max_length=500),
    description: str = Form("", max_length=1000),
    approved: str = Form(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Цель не найдена")
    try:
        target.group = _resolve_group(db, group_id, "")
        target.tags = get_or_create_tags(db, validate_tags(tags))
        target.description = validate_description(description)
    except ValidationError as exc:
        return _flash_redirect("/targets", err=str(exc))
    target.approved = approved == "on"
    db.commit()
    audit(
        db,
        "target_edit",
        f"{target.value}: утверждена={target.approved}",
        username=user.username,
        ip=client_ip(request),
    )
    return _flash_redirect("/targets", msg=f"Цель {target.value} обновлена")


@router.post("/targets/{target_id}/delete")
def delete_target(
    request: Request, target_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Цель не найдена")
    value = target.value
    db.delete(target)
    db.commit()
    audit(db, "target_delete", value, username=user.username, ip=client_ip(request))
    return _flash_redirect("/targets", msg=f"Цель {value} удалена")


# --------------------------------------------------------------------------- группы


@router.post("/groups")
def create_group(
    request: Request,
    name: str = Form(..., max_length=100),
    description: str = Form("", max_length=1000),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> Response:
    try:
        name = validate_name(name, "Группа")
        if db.scalar(select(Group).where(Group.name == name)):
            raise ValidationError("Группа с таким названием уже существует")
        db.add(Group(name=name, description=validate_description(description)))
        db.commit()
    except ValidationError as exc:
        return _flash_redirect("/targets", err=str(exc))
    audit(db, "group_create", name, username=user.username, ip=client_ip(request))
    return _flash_redirect("/targets", msg=f"Группа «{name}» создана")


@router.post("/groups/{group_id}/delete")
def delete_group(
    request: Request, group_id: int, user: User = Depends(require_admin), db: Session = Depends(get_db)
) -> Response:
    group = db.get(Group, group_id)
    if not group:
        raise HTTPException(404, "Группа не найдена")
    name = group.name
    for t in group.targets:
        t.group_id = None
    db.delete(group)
    db.commit()
    audit(db, "group_delete", name, username=user.username, ip=client_ip(request))
    return _flash_redirect("/targets", msg=f"Группа «{name}» удалена, цели остались без группы")
