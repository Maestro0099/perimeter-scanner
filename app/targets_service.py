"""Операции с целями: создание, импорт из targets.yaml, теги, группы."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Group, Tag, Target
from app.validation import (
    ValidationError,
    parse_scope,
    validate_description,
    validate_in_scope,
    validate_name,
    validate_tags,
)


@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    errors: list[str] = field(default_factory=list)


def get_or_create_group(db: Session, name: str, description: str = "") -> Group:
    name = validate_name(name, "Группа")
    group = db.scalar(select(Group).where(Group.name == name))
    if group is None:
        group = Group(name=name, description=validate_description(description))
        db.add(group)
        db.flush()
    return group


def get_or_create_tags(db: Session, names: list[str]) -> list[Tag]:
    result: list[Tag] = []
    for name in names:
        tag = db.scalar(select(Tag).where(Tag.name == name))
        if tag is None:
            tag = Tag(name=name)
            db.add(tag)
            db.flush()
        result.append(tag)
    return result


def create_or_update_target(
    db: Session,
    raw_value: str,
    *,
    group: Group | None = None,
    description: str = "",
    tags: list[str] | str = "",
    source: str = "ui",
    created_by: str = "",
    approved: bool = True,
) -> tuple[Target, bool]:
    """Возвращает (цель, создана_ли)."""
    s = get_settings()
    validated = validate_in_scope(raw_value, parse_scope(s.allowed_scope), s.max_cidr_hosts)
    tag_names = validate_tags(tags)
    desc = validate_description(description)
    target = db.scalar(select(Target).where(Target.value == validated.value))
    created = target is None
    if target is None:
        target = Target(kind=validated.kind.value, value=validated.value, source=source, created_by=created_by)
        db.add(target)
    target.description = desc or target.description
    if group is not None:
        target.group = group
    target.approved = approved
    if tag_names:
        target.tags = get_or_create_tags(db, tag_names)
    db.flush()
    return target, created


def _iter_yaml_targets(data: Any) -> list[tuple[str, str, dict[str, Any]]]:
    """Разбирает структуру targets.yaml в список (группа, описание_группы, цель)."""
    if not isinstance(data, dict):
        raise ValidationError("targets.yaml: корневой элемент должен быть словарём")
    items: list[tuple[str, str, dict[str, Any]]] = []
    groups = data.get("groups", [])
    if not isinstance(groups, list):
        raise ValidationError("targets.yaml: «groups» должен быть списком")
    for g in groups:
        if not isinstance(g, dict) or "name" not in g:
            raise ValidationError("targets.yaml: у каждой группы должно быть поле «name»")
        for t in g.get("targets", []) or []:
            items.append((str(g["name"]), str(g.get("description", "")), _norm_target(t)))
    for t in data.get("targets", []) or []:
        items.append(("", "", _norm_target(t)))
    return items


def _norm_target(t: Any) -> dict[str, Any]:
    if isinstance(t, str):
        return {"value": t}
    if isinstance(t, dict) and "value" in t:
        return t
    raise ValidationError(f"targets.yaml: некорректная запись цели: {t!r}")


def import_targets_yaml(db: Session, content: str | bytes, created_by: str = "") -> ImportResult:
    result = ImportResult()
    try:
        data = yaml.safe_load(content) or {}
        entries = _iter_yaml_targets(data)
    except (yaml.YAMLError, ValidationError) as exc:
        result.errors.append(f"Ошибка разбора YAML: {exc}")
        return result
    if len(entries) > 5000:
        result.errors.append("Слишком много целей в одном файле (максимум 5000)")
        return result
    for group_name, group_desc, t in entries:
        try:
            group = get_or_create_group(db, group_name, group_desc) if group_name else None
            _, created = create_or_update_target(
                db,
                str(t["value"]),
                group=group,
                description=str(t.get("description", "")),
                tags=t.get("tags", []) or [],
                source="yaml",
                created_by=created_by,
            )
            if created:
                result.created += 1
            else:
                result.updated += 1
        except ValidationError as exc:
            result.errors.append(f"{t.get('value')}: {exc}")
    db.commit()
    return result


def import_targets_file(db: Session, path: Path | None = None, created_by: str = "system") -> ImportResult | None:
    path = path or get_settings().targets_file
    if not path.is_file():
        return None
    return import_targets_yaml(db, path.read_text(encoding="utf-8"), created_by=created_by)
