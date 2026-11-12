"""Расписание и уведомления."""

from __future__ import annotations

import pytest

from app import db as dbmod
from app.models import Change, Finding, Group, Scan, Schedule, Target, utcnow
from app.notify.dispatcher import Notification, build_notification, new_findings
from app.validation import ValidationError


@pytest.fixture
def session(monkeypatch):
    dbmod.init_engine()
    dbmod.create_all()
    from app.scanner import engine

    submitted: list[int] = []
    monkeypatch.setattr(engine.scan_manager, "submit", lambda sid: submitted.append(sid))
    s = dbmod.new_session()
    s.submitted = submitted  # type: ignore[attr-defined]
    yield s
    s.close()


def _finding(scan_id: int, sev: str, title: str, fp: str, **kw) -> Finding:
    return Finding(scan_id=scan_id, asset=kw.pop("asset", "203.0.113.10"), asset_type="ip", category=kw.pop("category", "vuln"),
                   severity=sev, title=title, fingerprint=fp, **kw)


def test_make_trigger_validation() -> None:
    from app.scheduler import make_trigger

    assert make_trigger("0 3 * * *")
    for bad in ("0 25 * * *", "61 * * * *", "* * *", "0 3 * * mon;rm"):
        with pytest.raises(ValidationError):
            make_trigger(bad)


def test_run_schedule_creates_scan(session) -> None:
    from app.scheduler import run_schedule

    g = Group(name="Офис")
    t1 = Target(kind="ip", value="203.0.113.10", group=g)
    t2 = Target(kind="ip", value="203.0.113.11", group=g, approved=False)
    sch = Schedule(group=g, profile="quick", cron="0 3 * * *")
    session.add_all([g, t1, t2, sch])
    session.commit()
    run_schedule(sch.id)
    session.expire_all()
    scans = session.query(Scan).all()
    assert len(scans) == 1
    scan = scans[0]
    assert scan.trigger == "schedule" and scan.group_id == g.id
    assert [t.value for t in scan.targets] == ["203.0.113.10"]  # неутверждённая цель не попала
    assert session.submitted == [scan.id]
    # пока предыдущий скан группы в очереди — новый не создаётся
    run_schedule(sch.id)
    assert session.query(Scan).count() == 1


def test_aggressive_profile_cannot_be_scheduled(session) -> None:
    from app.scanner.engine import ScanRequestError, create_scan

    t = Target(kind="ip", value="203.0.113.10")
    session.add(t)
    session.commit()
    with pytest.raises(ScanRequestError):
        create_scan(session, target_ids=[t.id], profile="aggressive", timing=3, username="x", trigger="schedule")
    with pytest.raises(ScanRequestError):
        create_scan(session, target_ids=[t.id], profile="aggressive", timing=3, username="x", trigger="manual")
    scan = create_scan(session, target_ids=[t.id], profile="aggressive", timing=3, username="x", aggressive_confirmed=True)
    assert scan.profile == "aggressive"


def test_unapproved_or_unknown_targets_rejected(session) -> None:
    from app.scanner.engine import ScanRequestError, create_scan

    t = Target(kind="ip", value="203.0.113.10", approved=False)
    session.add(t)
    session.commit()
    with pytest.raises(ScanRequestError):
        create_scan(session, target_ids=[t.id], profile="quick", timing=3, username="x")
    with pytest.raises(ScanRequestError):
        create_scan(session, target_ids=[9999], profile="quick", timing=3, username="x")


def test_new_findings_and_notification(session, monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_URL", "https://perimeter.corp.local")
    from app.config import get_settings

    get_settings.cache_clear()
    t = Target(kind="ip", value="203.0.113.10")
    session.add(t)
    session.commit()
    s1 = Scan(profile="full", status="done", targets=[t], finished_at=utcnow())
    session.add(s1)
    session.flush()
    session.add(_finding(s1.id, "critical", "CVE-2023-38408 — OpenSSH", "vuln|a|22/tcp|CVE-2023-38408", cve="CVE-2023-38408"))
    s2 = Scan(profile="full", status="done", targets=[t], finished_at=utcnow())
    session.add(s2)
    session.flush()
    session.add_all([
        _finding(s2.id, "critical", "CVE-2023-38408 — OpenSSH", "vuln|a|22/tcp|CVE-2023-38408", cve="CVE-2023-38408"),
        _finding(s2.id, "high", "RDP доступен из интернета — 3389/tcp", "port|a|3389/tcp|open", category="port", port=3389, protocol="tcp"),
        _finding(s2.id, "low", "Отсутствует X-Frame-Options <script>", "web|a|443/tcp|xfo", category="web"),
        Change(scan_id=s2.id, asset="203.0.113.10", change_type="port_opened", severity="high",
               description="Открыт новый порт 3389/tcp (RDP)", new_value="3389/tcp Microsoft Terminal Services"),
    ])
    session.commit()
    scan2 = session.get(Scan, s2.id)
    assert {f.title for f in new_findings(session, scan2)} == {
        "RDP доступен из интернета — 3389/tcp",
        "Отсутствует X-Frame-Options <script>",
    }
    n = build_notification(session, scan2, "high")
    assert n is not None
    # изменение «новый порт» уже сообщает о RDP — находка о том же порте не дублируется
    assert len(n.lines) == 1 and n.lines[0][0] == "high"
    assert n.link == "https://perimeter.corp.local/scans/%d" % s2.id
    n_low = build_notification(session, scan2, "low")
    tg = n_low.as_telegram()
    assert "&lt;script&gt;" in tg and "<script>" not in tg
    assert "<script>" not in n_low.as_html()
    # нет новых значимых находок — уведомления нет
    assert build_notification(session, session.get(Scan, s1.id), "critical") is not None  # первый скан: всё новое
    s3 = Scan(profile="full", status="done", targets=[t], finished_at=utcnow())
    session.add(s3)
    session.flush()
    session.add(_finding(s3.id, "critical", "CVE-2023-38408 — OpenSSH", "vuln|a|22/tcp|CVE-2023-38408", cve="CVE-2023-38408"))
    session.commit()
    assert build_notification(session, session.get(Scan, s3.id), "high") is None


def test_failed_scan_notification(session) -> None:
    s = Scan(profile="quick", status="failed", error="nmap не найден")
    session.add(s)
    session.commit()
    n = build_notification(session, s, "high")
    assert n is not None and "ошибкой" in n.header and "nmap не найден" in n.as_text()


def test_deliver_skips_unconfigured_channels() -> None:
    from app.notify.dispatcher import deliver

    assert deliver(Notification(subject="s", header="h"), telegram=True, email=True) == []


def test_settings_and_schedule_pages(monkeypatch) -> None:
    import re

    from fastapi.testclient import TestClient

    monkeypatch.setenv("ADMIN_PASSWORD", "Test-Password-123")
    from app.config import get_settings

    get_settings.cache_clear()
    dbmod.init_engine()
    from app.main import create_app

    with TestClient(create_app()) as c:
        tok = lambda p: re.search(r'name="csrf_token" value="([^"]+)"', c.get(p).text).group(1)  # noqa: E731
        c.post("/login", data={"username": "admin", "password": "Test-Password-123", "csrf_token": tok("/login")})
        c.post("/groups", data={"name": "Офис", "csrf_token": tok("/targets")})
        r = c.post("/schedules", data={"group_id": 1, "profile": "full", "cron": "0 3 * * *", "csrf_token": tok("/schedules")})
        assert "Расписание создано" in r.text
        r = c.post("/schedules", data={"group_id": 1, "profile": "aggressive", "cron": "0 3 * * *", "csrf_token": tok("/schedules")})
        assert "нельзя запускать по расписанию" in r.text
        r = c.post("/schedules", data={"group_id": 1, "profile": "quick", "cron": "0 99 * * *", "csrf_token": tok("/schedules")})
        assert "Некорректное расписание" in r.text
        r = c.post("/settings", data={"notify_telegram": "on", "notify_min_severity": "medium", "nmap_timing": "4",
                                      "max_parallel_scans": "3", "csrf_token": tok("/settings")})
        assert "Настройки сохранены" in r.text
        from app import app_settings

        rs = app_settings.load()
        assert rs.notify_telegram and not rs.notify_email and rs.nmap_timing == 4 and rs.max_parallel_scans == 3
        r = c.post("/settings", data={"nmap_timing": "9", "max_parallel_scans": "3", "csrf_token": tok("/settings")})
        assert "от 0 до 5" in r.text
        r = c.post("/settings/test", data={"channel": "telegram", "csrf_token": tok("/settings")})
        assert "не настроен" in r.text
