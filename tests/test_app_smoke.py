"""Сквозная проверка: вход, CSRF, роли, цели."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "Test-Password-123")
    from app import db as dbmod
    from app.config import get_settings

    get_settings.cache_clear()
    dbmod.init_engine()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


def _csrf(client: TestClient, path: str = "/login") -> str:
    html = client.get(path).text
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf token not found"
    return m.group(1)


def _login(client: TestClient, username: str = "admin", password: str = "Test-Password-123"):
    token = _csrf(client)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token, "next": "/"},
        follow_redirects=False,
    )


def test_requires_login(client: TestClient) -> None:
    r = client.get("/targets", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


def test_security_headers(client: TestClient) -> None:
    r = client.get("/login")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_login_and_csrf(client: TestClient) -> None:
    # без CSRF-токена — отказ
    r = client.post("/login", data={"username": "admin", "password": "x"})
    assert r.status_code == 403
    r = _login(client, password="wrong-password")
    assert r.status_code == 401
    r = _login(client)
    assert r.status_code == 303
    assert "ps_session" in r.cookies or "ps_session" in client.cookies
    assert client.get("/targets").status_code == 200


def test_login_rate_limit(client: TestClient) -> None:
    for _ in range(5):
        assert _login(client, password="wrong-password").status_code == 401
    assert _login(client).status_code == 429


def test_add_target_and_reject_injection(client: TestClient) -> None:
    _login(client)
    token = _csrf(client, "/targets")
    r = client.post(
        "/targets",
        data={"values": "203.0.113.10\nexample.com\n-sS\n1.2.3.4;id", "tags": "web", "csrf_token": token},
        follow_redirects=True,
    )
    assert r.status_code == 200
    assert "203.0.113.10" in r.text and "example.com" in r.text
    assert "Добавлено/обновлено целей: 2" in r.text


def test_viewer_cannot_modify(client: TestClient) -> None:
    _login(client)
    token = _csrf(client, "/users")
    r = client.post(
        "/users",
        data={"username": "viewer1", "password": "Viewer-Password-1", "role": "viewer", "csrf_token": token},
    )
    assert r.status_code == 200
    client.post("/logout", data={"csrf_token": token})
    client.cookies.clear()
    assert _login(client, "viewer1", "Viewer-Password-1").status_code == 303
    token = _csrf(client, "/targets")
    r = client.post("/targets", data={"values": "203.0.113.11", "csrf_token": token})
    assert r.status_code == 403


def test_pages_render_with_check_results(client: TestClient) -> None:
    from app import db as dbmod
    from app.models import DomainResult, Finding, Scan, Target, TlsResult, WebResult, utcnow

    with dbmod.session_scope() as db:
        t = Target(kind="domain", value="example.com")
        db.add(t)
        db.flush()
        scan = Scan(profile="full", status="done", targets=[t], started_by="admin", finished_at=utcnow(), progress=100)
        db.add(scan)
        db.flush()
        db.add(DomainResult(
            scan_id=scan.id, target_id=t.id, domain="example.com",
            records={"A": ["203.0.113.10"], "MX": ["10 mx.example.com"], "TXT": ["v=spf1 -all"]},
            email_security={"spf": {"record": "v=spf1 -all", "issues": []}, "dmarc": {"record": "", "policy": "", "issues": ["DMARC-запись отсутствует"]}, "dkim": {"selectors": {}}},
            zone_transfer={"ns1.example.com": {"allowed": True, "records": 12}},
            whois={"domain": "example.com", "registrar": "Reg", "expires": "2030-01-01", "days_left": 1000},
            subdomains=[{"name": "www.example.com", "ips": ["203.0.113.10"], "sources": ["crt.sh"], "resolves": True}],
        ))
        db.add(WebResult(scan_id=scan.id, asset="example.com", url="https://example.com/", status_code=200, title="Пример",
                         security_headers={"content-security-policy": {"present": False, "value": ""}}, technologies=["nginx"]))
        db.add(TlsResult(scan_id=scan.id, asset="example.com", host="example.com", port=443,
                         certificate={"subject": "example.com", "issuer": "CA", "days_left": 5, "san": ["example.com"], "chain": []},
                         chain_valid=True, protocols={"TLSv1.0": False, "TLSv1.2": True}, ciphers={"RC4": None, "NULL": False}))
        db.add(Finding(scan_id=scan.id, target_id=t.id, asset="example.com", asset_type="domain", category="dns",
                       severity="high", title="Разрешена передача зоны (AXFR)", fingerprint="dns|example.com|-|axfr"))
        sid = scan.id
    _login(client)
    for path in (f"/scans/{sid}", "/assets/domain/example.com", "/assets/domain", "/findings", "/reports", "/",
                 "/assets/domain/example.com/export.html", "/assets/domain/example.com/export.json"):
        r = client.get(path)
        assert r.status_code == 200, path
    page = client.get("/assets/domain/example.com").text
    assert "AXFR разрешён" in page and "www.example.com" in page and "не проверено: RC4" in page

    token = _csrf(client, "/assets/domain/example.com")
    r = client.post("/assets/domain/example.com/promote", data={"name": "www.example.com", "csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/assets/domain/example.com/promote", data={"name": "evil.org", "csrf_token": token})
    assert r.status_code == 400


def test_add_new_addresses_and_scan(client: TestClient, monkeypatch) -> None:
    """Новые адреса вводятся прямо при запуске: попадают в утверждённый список и в скан."""
    from app.scanner import engine

    monkeypatch.setattr(engine.scan_manager, "submit", lambda sid: None)
    _login(client)
    token = _csrf(client, "/scans/new")
    r = client.post("/scans", data={"new_targets": "198.51.100.40\nnew.example.org", "profile": "quick", "csrf_token": token},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/scans/")
    page = client.get("/targets").text
    assert "198.51.100.40" in page and "new.example.org" in page
    # некорректный ввод ничего не добавляет и не запускает
    r = client.post("/scans", data={"new_targets": "198.51.100.41\n--script=exploit", "profile": "quick", "csrf_token": token})
    assert "198.51.100.41" not in client.get("/targets").text


def test_password_change_drops_other_sessions(client: TestClient) -> None:
    from app import db as dbmod
    from app.models import UserSession

    _login(client)
    client.cookies.clear()
    _login(client)
    with dbmod.session_scope() as db:
        assert db.query(UserSession).count() == 2
    token = _csrf(client, "/account")
    r = client.post("/account/password", data={"current_password": "Test-Password-123", "new_password": "New-Password-4567",
                                               "confirm_password": "New-Password-4567", "csrf_token": token})
    assert "Пароль изменён" in r.text
    with dbmod.session_scope() as db:
        assert db.query(UserSession).count() == 1
