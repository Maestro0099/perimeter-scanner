"""Дашборд."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.analysis.severity import SEVERITY_LABELS, SEVERITY_ORDER_LIST
from app.analysis.state import asset_index, count_by_severity, current_findings, latest_hosts, risk_score, trend
from app.auth import current_user
from app.db import get_db
from app.models import Change, Scan, ScanStatus, Target, User
from app.scanner.engine import active_scans
from app.templating import fmt_dt, render

router = APIRouter()

SEV_COLORS = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#d97706", "low": "#2563eb", "info": "#94a3b8"}


def chart_configs(counts: dict[str, int], trend_rows: list[dict]) -> dict:
    donut_sevs = [s for s in SEVERITY_ORDER_LIST if s != "info"]
    donut = {
        "type": "doughnut",
        "data": {
            "labels": [SEVERITY_LABELS[s] for s in donut_sevs],
            "datasets": [
                {
                    "data": [counts.get(s, 0) for s in donut_sevs],
                    "backgroundColor": [SEV_COLORS[s] for s in donut_sevs],
                    "borderWidth": 0,
                }
            ],
        },
        "options": {"cutout": "68%", "plugins": {"legend": {"position": "bottom", "labels": {"boxWidth": 10, "usePointStyle": True}}}},
    }
    labels = [f"#{t['scan_id']} {fmt_dt(t['date'], '%d.%m')}" for t in trend_rows]
    line = {
        "type": "bar",
        "data": {
            "labels": labels,
            "datasets": [
                {
                    "label": SEVERITY_LABELS[s],
                    "data": [t["counts"][s] for t in trend_rows],
                    "backgroundColor": SEV_COLORS[s],
                    "borderRadius": 2,
                    "maxBarThickness": 28,
                }
                for s in donut_sevs
            ],
        },
        "options": {
            "plugins": {"legend": {"position": "bottom", "labels": {"boxWidth": 10, "usePointStyle": True}}},
            "scales": {"x": {"stacked": True}, "y": {"stacked": True, "beginAtZero": True, "ticks": {"precision": 0}}},
        },
    }
    return {"donut": donut, "trend": line}


@router.get("/")
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    findings = current_findings(db)
    counts = count_by_severity(findings)
    hosts = latest_hosts(db)
    trend_rows = trend(db, 20)
    assets = asset_index(db, findings)
    last_scan = db.scalar(select(Scan).where(Scan.status == ScanStatus.DONE.value).order_by(Scan.id.desc()).limit(1))
    changes = list(db.scalars(select(Change).order_by(Change.id.desc()).limit(15)))
    week_changes = db.scalar(
        select(func.count()).select_from(Change).where(Change.severity.in_(["critical", "high", "medium"]))
    )
    return render(
        request,
        "dashboard.html",
        {
            "counts": counts,
            "risk": risk_score(findings),
            "targets_total": db.scalar(select(func.count()).select_from(Target)) or 0,
            "hosts_total": len(hosts),
            "ports_total": sum(len(h.ports) for h in hosts.values()),
            "top_findings": [f for f in findings if f.severity in ("critical", "high")][:8],
            "top_assets": [a for a in assets if a["risk_weight"] > 0][:6],
            "changes": changes,
            "important_changes": week_changes or 0,
            "last_scan": last_scan,
            "active": active_scans(db),
            "charts": chart_configs(counts, trend_rows),
            "has_trend": bool(trend_rows),
        },
    )
