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
