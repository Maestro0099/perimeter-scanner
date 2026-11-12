"""Сохранение результатов nmap, сравнение сканов в БД и экспорт отчётов."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from app import db as dbmod
from app.models import Change, Scan, ScanStatus, Target, utcnow
from app.scanner.nmap_parser import parse_nmap_xml


@pytest.fixture
def session():
    dbmod.init_engine()
    dbmod.create_all()
    s = dbmod.new_session()
    yield s
    s.close()


def _make_scan(db, targets, profile="full") -> Scan:
    scan = Scan(profile=profile, status=ScanStatus.RUNNING.value, targets=targets, started_by="test", started_at=utcnow())
    db.add(scan)
    db.commit()
    return scan


def _store(scan_id: int, hosts, targets) -> None:
    from app.scanner.engine import ScanJob

    job = ScanJob(scan_id, threading.Event())
    job.store_nmap(hosts, [(t.id, t.kind, t.value) for t in targets])
    job.finalize()
    with dbmod.session_scope() as db:
        scan = db.get(Scan, scan_id)
        scan.status = ScanStatus.DONE.value
        scan.finished_at = utcnow()


def test_two_scans_produce_changes_and_reports(session, fixtures_dir: Path) -> None:
    t1 = Target(kind="ip", value="203.0.113.10")
    t2 = Target(kind="ip", value="203.0.113.11")
    session.add_all([t1, t2])
    session.commit()
    run = parse_nmap_xml((fixtures_dir / "nmap_full.xml").read_bytes())
    hosts = [h for h in run.hosts if h.status == "up"]

    s1 = _make_scan(session, [t1, t2])
    _store(s1.id, hosts, [t1, t2])
    assert session.query(Change).count() == 0  # первый скан — базовая линия

    # второй скан: закрыт FTP, обновлён OpenSSH, исчезли CVE OpenSSH, Redis пропал
    run2 = parse_nmap_xml((fixtures_dir / "nmap_full.xml").read_bytes())
    h1 = run2.hosts[0]
    h1.ports = [p for p in h1.ports if p.port != 21]
    ssh = next(p for p in h1.ports if p.port == 22)
    ssh.service.version = "9.6p1"
    ssh.scripts = []
    h2 = run2.hosts[1]
    h2.ports = [p for p in h2.ports if p.port != 6379]
    s2 = _make_scan(session, [t1, t2])
    _store(s2.id, [h1, h2], [t1, t2])

    session.expire_all()
    rows = session.query(Change).filter_by(scan_id=s2.id).all()
    changes = {(c.asset, c.change_type) for c in rows}
    assert ("203.0.113.10", "port_closed") in changes
    assert ("203.0.113.10", "service_changed") in changes
    assert ("203.0.113.10", "vuln_fixed") in changes
    assert ("203.0.113.11", "port_closed") in changes
    scan2 = session.get(Scan, s2.id)
    assert scan2.summary["changes"] == len(rows)
    assert sum(1 for c in rows if c.change_type == "vuln_fixed") == 3

    # быстрый скан не сравнивается с полным (разный охват портов)
    s3 = _make_scan(session, [t1], profile="quick")
    _store(s3.id, [h1], [t1])
    assert session.query(Change).filter_by(scan_id=s3.id).count() == 0

    from app.analysis.state import current_findings, risk_score
    from app.reports.builder import ip_report, perimeter_report
    from app.reports.exporters import to_csv, to_html, to_json, to_pdf

    findings = current_findings(session)
    assert findings and all(f.scan_id in (s2.id, s3.id) for f in findings)
    risk = risk_score(findings)
    assert risk.level in ("high", "critical")

    rep = perimeter_report(session)
    assert rep["summary"]["hosts"] == 2
    data = json.loads(to_json(rep))
    assert data["summary"]["risk"]["label"]
    csv_text = to_csv(rep).decode("utf-8")
    assert csv_text.startswith("﻿Уровень;Актив")
    html = to_html(rep).decode("utf-8")
    assert "Сводный отчёт по внешнему периметру" in html and "<script" not in html
    pdf = to_pdf(rep)
    assert pdf.startswith(b"%PDF")

    ipr = ip_report(session, "203.0.113.10")
    assert ipr is not None and ipr["ports"]
    assert "203.0.113.10" in to_html(ipr).decode("utf-8")
    assert json.loads(to_json(ipr))["asset"] == "203.0.113.10"


def test_csv_formula_injection_is_neutralised() -> None:
    from app.reports.exporters import _csv_safe

    assert _csv_safe("=HYPERLINK(\"x\")") == "'=HYPERLINK(\"x\")"
    assert _csv_safe("normal") == "normal"
