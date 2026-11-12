"""Сравнение двух сканов одной цели.

Снимок (Snapshot) — независимое от БД представление результатов скана по цели.
Функция diff_snapshots чистая и покрыта тестами; построение снимков из БД и
запись изменений — в build_snapshot / compute_scan_changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.knowledge import service_risk
from app.analysis.severity import SEVERITY_RANK
from app.models import Change, DomainResult, Finding, Host, Scan, ScanStatus, scan_targets


@dataclass(frozen=True)
class ServiceInfo:
    service: str = ""
    product: str = ""
    version: str = ""

    @property
    def label(self) -> str:
        return " ".join(p for p in (self.product, self.version) if p) or self.service or "неизвестно"


@dataclass(frozen=True)
class VulnInfo:
    severity: str
    title: str
    cvss: float | None = None


@dataclass(frozen=True)
class FindingInfo:
    asset: str
    asset_type: str
    severity: str
    title: str


@dataclass
class Snapshot:
    # ip -> {"443/tcp": ServiceInfo}
    hosts: dict[str, dict[str, ServiceInfo]] = field(default_factory=dict)
    # (asset, "443/tcp", CVE) -> VulnInfo
    vulns: dict[tuple[str, str, str], VulnInfo] = field(default_factory=dict)
    # домен -> множество поддоменов
    subdomains: dict[str, set[str]] = field(default_factory=dict)
    # отпечаток -> находка (категории dns/mail/web/tls/whois)
    findings: dict[str, FindingInfo] = field(default_factory=dict)


@dataclass(frozen=True)
class ChangeItem:
    asset: str
    asset_type: str
    change_type: str
    severity: str
    description: str
    old_value: str = ""
    new_value: str = ""


def _port_sort_key(key: str) -> tuple[str, int]:
    port, _, proto = key.partition("/")
    return proto, int(port) if port.isdigit() else 0


def diff_snapshots(old: Snapshot | None, new: Snapshot) -> list[ChangeItem]:
    """Возвращает список изменений нового снимка относительно старого.

    Если предыдущего снимка нет (первый скан цели), изменения не формируются —
    первый скан служит базовой линией.
    """
    if old is None:
        return []
    changes: list[ChangeItem] = []

    # --- хосты
    for ip in sorted(set(new.hosts) - set(old.hosts)):
        ports = ", ".join(sorted(new.hosts[ip], key=_port_sort_key)) or "нет открытых портов"
        changes.append(
            ChangeItem(ip, "ip", "host_up", "medium", f"Новый доступный хост, открытые порты: {ports}", "", ports)
        )
    for ip in sorted(set(old.hosts) - set(new.hosts)):
        changes.append(ChangeItem(ip, "ip", "host_down", "info", "Хост больше не отвечает или не обнаружен"))

    # --- порты и версии сервисов
    for ip in sorted(set(new.hosts) & set(old.hosts)):
        old_ports, new_ports = old.hosts[ip], new.hosts[ip]
        for key in sorted(set(new_ports) - set(old_ports), key=_port_sort_key):
            svc = new_ports[key]
            port, _, proto = key.partition("/")
            risk = service_risk(proto, int(port) if port.isdigit() else 0, svc.service)
            sev = risk.severity if risk and SEVERITY_RANK[risk.severity] > SEVERITY_RANK["low"] else "low"
            changes.append(
                ChangeItem(ip, "ip", "port_opened", sev, f"Открыт новый порт {key} ({svc.label})", "", f"{key} {svc.label}")
            )
        for key in sorted(set(old_ports) - set(new_ports), key=_port_sort_key):
            svc = old_ports[key]
            changes.append(ChangeItem(ip, "ip", "port_closed", "info", f"Порт {key} ({svc.label}) закрыт", f"{key} {svc.label}", ""))
        for key in sorted(set(old_ports) & set(new_ports), key=_port_sort_key):
            o, n = old_ports[key], new_ports[key]
            if (o.product, o.version) != (n.product, n.version) and (n.product or n.version):
                changes.append(
                    ChangeItem(
                        ip,
                        "ip",
                        "service_changed",
                        "low",
                        f"Порт {key}: версия сервиса изменилась с «{o.label}» на «{n.label}»",
                        o.label,
                        n.label,
                    )
                )

    # --- уязвимости
    comparable_assets = set(old.hosts) | set(old.subdomains) | {f.asset for f in old.findings.values()}
    for key in sorted(set(new.vulns) - set(old.vulns)):
        asset, port, vid = key
        v = new.vulns[key]
        changes.append(
            ChangeItem(
                asset,
                "ip",
                "vuln_new",
                v.severity,
                f"Новая уязвимость {vid} на {port}" + (f" (CVSS {v.cvss:.1f})" if v.cvss is not None else ""),
                "",
                vid,
            )
        )
    for key in sorted(set(old.vulns) - set(new.vulns)):
        asset, port, vid = key
        if asset in new.hosts:  # хост просканирован, уязвимость больше не обнаруживается
            changes.append(ChangeItem(asset, "ip", "vuln_fixed", "info", f"Уязвимость {vid} на {port} больше не обнаруживается", vid, ""))

    # --- поддомены
    for domain in sorted(new.subdomains):
        if domain not in old.subdomains:
            continue
        for sub in sorted(new.subdomains[domain] - old.subdomains[domain]):
            changes.append(ChangeItem(domain, "domain", "subdomain_new", "low", f"Обнаружен новый поддомен {sub}", "", sub))
        for sub in sorted(old.subdomains[domain] - new.subdomains[domain]):
            changes.append(ChangeItem(domain, "domain", "subdomain_gone", "info", f"Поддомен {sub} больше не обнаруживается", sub, ""))

    # --- прочие находки (DNS, почта, веб, TLS, WHOIS)
    for fp in sorted(set(new.findings) - set(old.findings)):
        f = new.findings[fp]
        if f.asset not in comparable_assets and f.asset_type == "ip":
            continue
        if f.severity == "info":
            continue
        changes.append(ChangeItem(f.asset, f.asset_type, "finding_new", f.severity, f"Новая находка: {f.title}", "", f.title))
    for fp in sorted(set(old.findings) - set(new.findings)):
        f = old.findings[fp]
        if f.severity == "info":
            continue
        changes.append(ChangeItem(f.asset, f.asset_type, "finding_resolved", "info", f"Устранено: {f.title}", f.title, ""))
    return changes


# --------------------------------------------------------------------------- работа с БД

COVERAGE = {"quick": "quick", "full": "full", "aggressive": "full"}
DIFF_CATEGORIES = ("dns", "mail", "web", "tls", "whois")


def build_snapshot(db: Session, scan_id: int, target_id: int) -> Snapshot:
    snap = Snapshot()
    for host in db.scalars(select(Host).where(Host.scan_id == scan_id, Host.target_id == target_id)):
        snap.hosts[host.ip] = {
            f"{p.port}/{p.protocol}": ServiceInfo(p.service, p.product, p.version) for p in host.ports
        }
    for f in db.scalars(select(Finding).where(Finding.scan_id == scan_id, Finding.target_id == target_id)):
        if f.category == "vuln" and f.cve:
            key = (f.asset, f"{f.port}/{f.protocol}" if f.port else "-", f.cve)
            snap.vulns[key] = VulnInfo(f.severity, f.title, f.cvss)
        elif f.category in DIFF_CATEGORIES:
            snap.findings[f.fingerprint] = FindingInfo(f.asset, f.asset_type, f.severity, f.title)
    for d in db.scalars(select(DomainResult).where(DomainResult.scan_id == scan_id, DomainResult.target_id == target_id)):
        snap.subdomains[d.domain] = {s["name"] for s in d.subdomains if isinstance(s, dict) and s.get("name")}
    return snap


def previous_scan_id(db: Session, scan: Scan, target_id: int) -> int | None:
    """Последний завершённый скан этой цели с сопоставимым охватом портов."""
    group = COVERAGE.get(scan.profile, scan.profile)
    profiles = [p for p, g in COVERAGE.items() if g == group]
    return db.scalar(
        select(Scan.id)
        .join(scan_targets, scan_targets.c.scan_id == Scan.id)
        .where(
            scan_targets.c.target_id == target_id,
            Scan.id < scan.id,
            Scan.status == ScanStatus.DONE.value,
            Scan.profile.in_(profiles),
        )
        .order_by(Scan.id.desc())
        .limit(1)
    )


def compute_scan_changes(db: Session, scan: Scan) -> list[ChangeItem]:
    items: list[ChangeItem] = []
    seen: set[tuple[str, str, str]] = set()
    for target in scan.targets:
        prev_id = previous_scan_id(db, scan, target.id)
        if prev_id is None:
            continue
        old = build_snapshot(db, prev_id, target.id)
        new = build_snapshot(db, scan.id, target.id)
        for ch in diff_snapshots(old, new):
            key = (ch.asset, ch.change_type, ch.description)
            if key not in seen:
                seen.add(key)
                items.append(ch)
    for ch in items:
        db.add(
            Change(
                scan_id=scan.id,
                asset=ch.asset,
                asset_type=ch.asset_type,
                change_type=ch.change_type,
                severity=ch.severity,
                description=ch.description,
                old_value=ch.old_value,
                new_value=ch.new_value,
            )
        )
    return items
