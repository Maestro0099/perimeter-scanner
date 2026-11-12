"""Текущее состояние периметра: актуальные результаты по каждой цели."""

from __future__ import annotations

import math
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.diff import COVERAGE
from app.analysis.severity import SEVERITY_ORDER_LIST, SEVERITY_RANK
from app.models import DomainResult, Finding, Host, Scan, ScanStatus, Target, scan_targets

SEVERITY_WEIGHTS = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}


def latest_scan_ids(db: Session) -> dict[int, list[int]]:
    """Для каждой цели — последний завершённый скан в каждой группе охвата (быстрый / полный)."""
    rows = db.execute(
        select(scan_targets.c.target_id, Scan.profile, func.max(Scan.id))
        .join(Scan, Scan.id == scan_targets.c.scan_id)
        .where(Scan.status == ScanStatus.DONE.value)
        .group_by(scan_targets.c.target_id, Scan.profile)
    ).all()
    best: dict[tuple[int, str], int] = {}
    for tid, profile, sid in rows:
        key = (tid, COVERAGE.get(profile, profile))
        best[key] = max(best.get(key, 0), sid)
    result: dict[int, list[int]] = {}
    for (tid, _), sid in best.items():
        result.setdefault(tid, []).append(sid)
    return result


def current_findings(db: Session) -> list[Finding]:
    """Актуальные находки: из последних сканов по каждой цели, без дубликатов (берётся самый свежий)."""
    latest = latest_scan_ids(db)
    if not latest:
        return []
    pairs = {(sid, tid) for tid, sids in latest.items() for sid in sids}
    scan_ids = {sid for sid, _ in pairs}
    rows = db.scalars(select(Finding).where(Finding.scan_id.in_(scan_ids)).order_by(Finding.scan_id.desc()))
    result: dict[str, Finding] = {}
    for f in rows:
        if f.target_id is not None and (f.scan_id, f.target_id) not in pairs:
            continue
        result.setdefault(f.fingerprint, f)
    return sorted(
        result.values(), key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), -(f.cvss or 0), f.asset, f.port or 0)
    )


def latest_hosts(db: Session) -> dict[str, Host]:
    """Последний результат по каждому IP."""
    sub = (
        select(Host.ip, func.max(Host.scan_id).label("sid"))
        .join(Scan, Scan.id == Host.scan_id)
        .where(Scan.status == ScanStatus.DONE.value)
        .group_by(Host.ip)
        .subquery()
    )
    hosts = db.scalars(select(Host).join(sub, (Host.ip == sub.c.ip) & (Host.scan_id == sub.c.sid)))
    return {h.ip: h for h in hosts}


def latest_domain_results(db: Session) -> dict[str, DomainResult]:
    sub = (
        select(DomainResult.domain, func.max(DomainResult.scan_id).label("sid"))
        .join(Scan, Scan.id == DomainResult.scan_id)
        .where(Scan.status == ScanStatus.DONE.value)
        .group_by(DomainResult.domain)
        .subquery()
    )
    rows = db.scalars(
        select(DomainResult).join(sub, (DomainResult.domain == sub.c.domain) & (DomainResult.scan_id == sub.c.sid))
    )
    return {d.domain: d for d in rows}


@dataclass
class RiskScore:
    index: int
    level: str
    label: str
    weight: float


RISK_LEVELS = [
    (10, "low", "Низкий"),
    (30, "medium", "Умеренный"),
    (60, "high", "Высокий"),
    (101, "critical", "Критический"),
]


def risk_score(findings: list[Finding]) -> RiskScore:
    """Индекс риска 0–100: насыщающаяся функция от взвешенной суммы находок."""
    weight = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    index = int(round(100 * (1 - math.exp(-weight / 50.0))))
    if any(f.severity == "critical" for f in findings):
        index = max(index, 60)
    elif any(f.severity == "high" for f in findings):
        index = max(index, 30)
    for limit, level, label in RISK_LEVELS:
        if index < limit:
            return RiskScore(index, level, label, weight)
    return RiskScore(index, "critical", "Критический", weight)


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER_LIST}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def trend(db: Session, limit: int = 30) -> list[dict]:
    """Динамика: число находок по уровням в последних завершённых сканах."""
    scans = list(
        db.scalars(select(Scan).where(Scan.status == ScanStatus.DONE.value).order_by(Scan.id.desc()).limit(limit))
    )[::-1]
    if not scans:
        return []
    rows = db.execute(
        select(Finding.scan_id, Finding.severity, func.count())
        .where(Finding.scan_id.in_([s.id for s in scans]))
        .group_by(Finding.scan_id, Finding.severity)
    ).all()
    by_scan: dict[int, dict[str, int]] = {}
    for sid, sev, cnt in rows:
        by_scan.setdefault(sid, {})[sev] = cnt
    return [
        {
            "scan_id": s.id,
            "date": s.finished_at or s.created_at,
            "profile": s.profile,
            "counts": {sev: by_scan.get(s.id, {}).get(sev, 0) for sev in SEVERITY_ORDER_LIST},
        }
        for s in scans
    ]


def asset_index(db: Session, findings: list[Finding] | None = None) -> list[dict]:
    """Сводка по активам (IP и домены) для таблиц и отчётов."""
    findings = findings if findings is not None else current_findings(db)
    hosts = latest_hosts(db)
    domains = latest_domain_results(db)
    assets: dict[tuple[str, str], dict] = {}
    for ip, h in hosts.items():
        assets[("ip", ip)] = {
            "type": "ip",
            "asset": ip,
            "hostnames": h.hostnames,
            "open_ports": len(h.ports),
            "last_scan": h.scan_id,
            "os": h.os_name,
            "counts": {s: 0 for s in SEVERITY_ORDER_LIST},
        }
    domain_targets = {t.value for t in db.scalars(select(Target).where(Target.kind == "domain"))}
    for name in set(domains) | domain_targets:
        d = domains.get(name)
        assets[("domain", name)] = {
            "type": "domain",
            "asset": name,
            "hostnames": [],
            "open_ports": 0,
            "last_scan": d.scan_id if d else None,
            "subdomains": len(d.subdomains) if d else 0,
            "counts": {s: 0 for s in SEVERITY_ORDER_LIST},
        }
    for f in findings:
        a = assets.get((f.asset_type, f.asset))
        if a is None:
            a = assets[(f.asset_type, f.asset)] = {
                "type": f.asset_type,
                "asset": f.asset,
                "hostnames": [],
                "open_ports": 0,
                "last_scan": f.scan_id,
                "counts": {s: 0 for s in SEVERITY_ORDER_LIST},
            }
        a["counts"][f.severity] += 1
    for a in assets.values():
        sevs = [s for s in SEVERITY_ORDER_LIST if a["counts"][s]]
        a["max_severity"] = sevs[0] if sevs else "info"
        a["risk_weight"] = sum(SEVERITY_WEIGHTS[s] * n for s, n in a["counts"].items())
    return sorted(assets.values(), key=lambda a: (-a["risk_weight"], a["type"], a["asset"]))
