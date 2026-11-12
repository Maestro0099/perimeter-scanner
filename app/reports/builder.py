"""Сборка данных отчётов (общий периметр и отдельный актив)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.state import (
    asset_index,
    count_by_severity,
    current_findings,
    latest_domain_results,
    latest_hosts,
    risk_score,
    trend,
)
from app.models import Change, DomainResult, Finding, Host, Scan, ScanStatus, Target, TlsResult, WebResult, utcnow


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "severity": f.severity,
        "asset": f.asset,
        "asset_type": f.asset_type,
        "category": f.category,
        "port": f.port,
        "protocol": f.protocol,
        "title": f.title,
        "cve": f.cve,
        "cvss": f.cvss,
        "description": f.description,
        "recommendation": f.recommendation,
        "evidence": f.evidence,
        "scan_id": f.scan_id,
    }


def change_dict(c: Change) -> dict[str, Any]:
    return {
        "date": c.created_at,
        "asset": c.asset,
        "asset_type": c.asset_type,
        "change_type": c.change_type,
        "severity": c.severity,
        "description": c.description,
        "scan_id": c.scan_id,
    }


def perimeter_report(db: Session) -> dict[str, Any]:
    findings = current_findings(db)
    hosts = latest_hosts(db)
    counts = count_by_severity(findings)
    risk = risk_score(findings)
    last_scan = db.scalar(select(Scan).where(Scan.status == ScanStatus.DONE.value).order_by(Scan.id.desc()).limit(1))
    changes = list(db.scalars(select(Change).order_by(Change.id.desc()).limit(100)))
    return {
        "kind": "perimeter",
        "title": "Сводный отчёт по внешнему периметру",
        "generated_at": utcnow(),
        "summary": {
            "targets": db.scalar(select(func.count()).select_from(Target)) or 0,
            "hosts": len(hosts),
            "open_ports": sum(len(h.ports) for h in hosts.values()),
            "domains": len(latest_domain_results(db)),
            "findings": len(findings),
            "counts": counts,
            "risk": {"index": risk.index, "level": risk.level, "label": risk.label},
            "last_scan_id": last_scan.id if last_scan else None,
            "last_scan_at": last_scan.finished_at if last_scan else None,
        },
        "top_findings": [finding_dict(f) for f in findings if f.severity != "info"][:15],
        "assets": asset_index(db, findings),
        "findings": [finding_dict(f) for f in findings],
        "changes": [change_dict(c) for c in changes],
        "trend": trend(db),
    }


def ip_report(db: Session, ip: str) -> dict[str, Any] | None:
    host = db.scalar(
        select(Host).join(Scan).where(Host.ip == ip, Scan.status == ScanStatus.DONE.value).order_by(Host.scan_id.desc()).limit(1)
    )
    findings = [f for f in current_findings(db) if f.asset == ip]
    if host is None and not findings:
        return None
    history = list(
        db.execute(
            select(Scan, Host)
            .join(Host, Host.scan_id == Scan.id)
            .where(Host.ip == ip, Scan.status == ScanStatus.DONE.value)
            .order_by(Scan.id.desc())
            .limit(50)
        ).all()
    )
    changes = list(db.scalars(select(Change).where(Change.asset == ip).order_by(Change.id.desc()).limit(200)))
    web = list(db.scalars(select(WebResult).where(WebResult.asset == ip, WebResult.scan_id == (host.scan_id if host else -1))))
    tls = list(db.scalars(select(TlsResult).where(TlsResult.asset == ip, TlsResult.scan_id == (host.scan_id if host else -1))))
    domains = sorted(
        {d.domain for d in latest_domain_results(db).values() if ip in _domain_ips(d)}
    )
    return {
        "kind": "ip",
        "title": f"Отчёт по IP-адресу {ip}",
        "asset": ip,
        "generated_at": utcnow(),
        "host": host,
        "ports": host.ports if host else [],
        "findings": findings,
        "counts": count_by_severity(findings),
        "risk": risk_score(findings),
        "history": [
            {"scan": s, "open_ports": len(h.ports), "ports": ", ".join(f"{p.port}/{p.protocol}" for p in h.ports)}
            for s, h in history
        ],
        "changes": changes,
        "web": web,
        "tls": tls,
        "domains": domains,
    }


def _domain_ips(d: DomainResult) -> set[str]:
    recs = d.records or {}
    ips = set(recs.get("A", []) or []) | set(recs.get("AAAA", []) or [])
    for s in d.subdomains or []:
        if isinstance(s, dict):
            ips |= set(s.get("ips", []) or [])
    return ips


def domain_report(db: Session, domain: str) -> dict[str, Any] | None:
    result = db.scalar(
        select(DomainResult)
        .join(Scan)
        .where(DomainResult.domain == domain, Scan.status == ScanStatus.DONE.value)
        .order_by(DomainResult.scan_id.desc())
        .limit(1)
    )
    target = db.scalar(select(Target).where(Target.value == domain))
    all_current = current_findings(db)
    findings = [f for f in all_current if f.asset == domain]
    if result is None and target is None and not findings:
        return None
    ips = sorted(_domain_ips(result)) if result else []
    host_ips = set((result.records or {}).get("A", []) + (result.records or {}).get("AAAA", [])) if result else set()
    hosts = latest_hosts(db)
    sub_findings = [f for f in all_current if f.asset_type == "domain" and f.asset.endswith("." + domain)]
    history = list(
        db.scalars(
            select(DomainResult)
            .join(Scan)
            .where(DomainResult.domain == domain, Scan.status == ScanStatus.DONE.value)
            .order_by(DomainResult.scan_id.desc())
            .limit(50)
        )
    )
    changes = list(
        db.scalars(
            select(Change)
            .where((Change.asset == domain) | (Change.asset.like(f"%.{domain}")))
            .order_by(Change.id.desc())
            .limit(200)
        )
    )
    scan_id = result.scan_id if result else -1
    web = list(db.scalars(select(WebResult).where(WebResult.scan_id == scan_id).where(
        (WebResult.asset == domain) | (WebResult.asset.like(f"%.{domain}")))))
    tls = list(db.scalars(select(TlsResult).where(TlsResult.scan_id == scan_id).where(
        (TlsResult.asset == domain) | (TlsResult.asset.like(f"%.{domain}")))))
    return {
        "kind": "domain",
        "title": f"Отчёт по домену {domain}",
        "asset": domain,
        "generated_at": utcnow(),
        "target": target,
        "result": result,
        "findings": findings + sub_findings,
        "counts": count_by_severity(findings + sub_findings),
        "risk": risk_score(findings + sub_findings),
        "ips": ips,
        "hosts": [hosts[ip] for ip in sorted(host_ips) if ip in hosts],
        "history": history,
        "changes": changes,
        "web": web,
        "tls": tls,
    }


def serialize(value: Any) -> Any:
    """Приведение отчёта к JSON-совместимому виду."""
    if isinstance(value, datetime):
        return value.isoformat() + "Z"
    if isinstance(value, dict):
        return {k: serialize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [serialize(v) for v in value]
    if isinstance(value, Finding):
        return serialize(finding_dict(value))
    if isinstance(value, Change):
        return serialize(change_dict(value))
    if hasattr(value, "__table__"):
        return {c.name: serialize(getattr(value, c.name)) for c in value.__table__.columns}
    if hasattr(value, "__dataclass_fields__"):
        return {k: serialize(getattr(value, k)) for k in value.__dataclass_fields__}
    return value
