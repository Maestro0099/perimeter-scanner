"""Формирование и отправка уведомлений о новых находках и изменениях."""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import app_settings
from app.analysis.severity import SEVERITY_LABELS, SEVERITY_RANK, severity_at_least
from app.config import get_settings
from app.db import session_scope
from app.models import Change, Finding, Scan, ScanStatus, scan_targets
from app.notify.email import email_configured, send_email
from app.notify.telegram import NotifyError, send_telegram, telegram_configured
from app.templating import CHANGE_LABELS, PROFILE_LABELS

log = logging.getLogger("notify")

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
NOTIFY_CHANGE_TYPES = {"port_opened", "vuln_new", "subdomain_new", "host_up", "finding_new", "service_changed"}
MAX_ITEMS = 20


@dataclass
class Notification:
    subject: str
    lines: list[tuple[str, str]] = field(default_factory=list)  # (уровень, текст)
    header: str = ""
    link: str = ""

    def as_text(self) -> str:
        out = [self.header, ""]
        out += [f"[{SEVERITY_LABELS.get(sev, sev)}] {text}" for sev, text in self.lines]
        if self.link:
            out += ["", self.link]
        return "\n".join(out)

    def as_telegram(self) -> str:
        out = [f"<b>{html.escape(self.header)}</b>", ""]
        out += [f"{SEV_ICON.get(sev, '•')} {html.escape(text)}" for sev, text in self.lines]
        if self.link:
            out += ["", html.escape(self.link)]
        return "\n".join(out)

    def as_html(self) -> str:
        colors = {"critical": "#e11d48", "high": "#f97316", "medium": "#ca8a04", "low": "#0284c7", "info": "#64748b"}
        rows = "".join(
            f'<tr><td style="padding:4px 8px;color:{colors.get(sev)};font-weight:bold;white-space:nowrap">'
            f"{html.escape(SEVERITY_LABELS.get(sev, sev))}</td><td style=\"padding:4px 8px\">{html.escape(text)}</td></tr>"
            for sev, text in self.lines
        )
        link = f'<p><a href="{html.escape(self.link)}">{html.escape(self.link)}</a></p>' if self.link else ""
        return (
            f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px"><h3>{html.escape(self.header)}</h3>'
            f'<table style="border-collapse:collapse">{rows}</table>{link}</div>'
        )


def new_findings(db: Session, scan: Scan) -> list[Finding]:
    """Находки, отпечатки которых ранее не встречались в сканах тех же целей."""
    target_ids = [t.id for t in scan.targets]
    prev_scan_ids = select(scan_targets.c.scan_id).where(
        scan_targets.c.target_id.in_(target_ids), scan_targets.c.scan_id < scan.id
    )
    seen = set(
        db.scalars(
            select(Finding.fingerprint)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(Finding.scan_id.in_(prev_scan_ids), Scan.status == ScanStatus.DONE.value)
        )
    )
    return [f for f in scan.findings if f.fingerprint not in seen]


def build_notification(db: Session, scan: Scan, min_severity: str) -> Notification | None:
    base = get_settings().public_url.rstrip("/")
    link = f"{base}/scans/{scan.id}" if base else ""
    profile = PROFILE_LABELS.get(scan.profile, scan.profile)
    if scan.status == ScanStatus.FAILED.value:
        return Notification(
            subject=f"[Периметр] Ошибка скана #{scan.id}",
            header=f"Скан #{scan.id} ({profile}) завершился с ошибкой",
            lines=[("high", scan.error[:500] or "неизвестная ошибка")],
            link=link,
        )
    if scan.status != ScanStatus.DONE.value:
        return None
    findings = [f for f in new_findings(db, scan) if severity_at_least(f.severity, min_severity)]
    findings.sort(key=lambda f: -SEVERITY_RANK.get(f.severity, 0))
    changes = [
        c
        for c in db.scalars(select(Change).where(Change.scan_id == scan.id))
        if c.change_type in NOTIFY_CHANGE_TYPES and severity_at_least(c.severity, min_severity)
    ]
    reported = {(c.asset, c.new_value) for c in changes}
    reported_ports = {(c.asset, c.new_value.split(" ")[0]) for c in changes if c.change_type == "port_opened"}
    lines: list[tuple[str, str]] = []
    for c in sorted(changes, key=lambda c: -SEVERITY_RANK.get(c.severity, 0)):
        lines.append((c.severity, f"{CHANGE_LABELS.get(c.change_type, c.change_type)} · {c.asset}: {c.description}"))
    for f in findings:
        if (f.asset, f.cve) in reported:
            continue
        if f.category == "port" and (f.asset, f"{f.port}/{f.protocol}") in reported_ports:
            continue
        where = f"{f.asset}" + (f":{f.port}/{f.protocol}" if f.port else "")
        lines.append((f.severity, f"{where} — {f.title}"))
    if not lines:
        return None
    total = len(lines)
    if total > MAX_ITEMS:
        lines = lines[:MAX_ITEMS] + [("info", f"… и ещё {total - MAX_ITEMS}")]
    counts: dict[str, int] = {}
    for sev, _ in lines:
        counts[sev] = counts.get(sev, 0) + 1
    summary = ", ".join(f"{SEVERITY_LABELS[s].lower()}: {n}" for s, n in sorted(counts.items(), key=lambda x: -SEVERITY_RANK[x[0]]) if s != "info")
    return Notification(
        subject=f"[Периметр] Скан #{scan.id}: новые находки ({total})",
        header=f"Скан #{scan.id} ({profile}): новых находок и изменений — {total}" + (f" ({summary})" if summary else ""),
        lines=lines,
        link=link,
    )


def deliver(n: Notification, telegram: bool, email: bool) -> list[str]:
    errors: list[str] = []
    if telegram and telegram_configured():
        try:
            send_telegram(n.as_telegram())
        except NotifyError as exc:
            errors.append(str(exc))
    if email and email_configured():
        try:
            send_email(n.subject, n.as_text(), n.as_html())
        except NotifyError as exc:
            errors.append(str(exc))
    for e in errors:
        log.warning("Уведомление не отправлено: %s", e)
    return errors


def notify_scan(scan_id: int) -> None:
    with session_scope() as db:
        rs = app_settings.load(db)
        if not (rs.notify_telegram or rs.notify_email):
            return
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        if scan.status == ScanStatus.FAILED.value and not rs.notify_on_failure:
            return
        n = build_notification(db, scan, rs.notify_min_severity)
    if n is not None:
        deliver(n, rs.notify_telegram, rs.notify_email)
