"""Активные проверки: Hydra — сборка аргументов, разбор, шлюз авторизации, лимиты."""

from __future__ import annotations

import base64
import http.server
import threading
import time

import pytest

from app import db as dbmod
from app.active.engine import ActiveTestError, create_hydra_test
from app.active.hydra_runner import (
    HydraError,
    HydraOptions,
    build_hydra_args,
    hydra_available,
    parse_hydra_json,
    validate_module_option,
)
from app.models import ActiveTest, ScanStatus, Target


@pytest.fixture
def session(monkeypatch):
    dbmod.init_engine()
    dbmod.create_all()
    from app.active import engine

    submitted: list[int] = []
    monkeypatch.setattr(engine.active_test_manager, "submit", lambda tid: submitted.append(tid))
    s = dbmod.new_session()
    s.submitted = submitted  # type: ignore[attr-defined]
    yield s
    s.close()


# --------------------------------------------------------------------------- сборка аргументов


def _opts(**kw):
    base = dict(service="ssh", host="203.0.113.10", port=22, tasks=4, login_file="/w/l.txt", password_file="/w/p.txt")
    base.update(kw)
    return HydraOptions(**base)


def test_build_args_basic() -> None:
    args = build_hydra_args(_opts(output_file="/w/o.json"))
    assert args[-2:] == ["203.0.113.10", "ssh"]
    assert "-L" in args and "-P" in args
    assert args[args.index("-t") + 1] == "4"
    assert args[args.index("-s") + 1] == "22"
    assert "-f" in args
    assert args[args.index("-o") + 1] == "/w/o.json" and "json" in args


def test_build_args_combo_mode() -> None:
    args = build_hydra_args(_opts(combo_file="/w/c.txt", password_file=None))
    assert "-C" in args and "-L" not in args and "-P" not in args
    assert args[args.index("-C") + 1] == "/w/c.txt"


def test_build_args_rejects_unknown_service() -> None:
    with pytest.raises(HydraError):
        build_hydra_args(_opts(service="exploit"))
    with pytest.raises(HydraError):
        build_hydra_args(_opts(service="ssh; rm -rf /"))


def test_build_args_rejects_bad_port_and_dash_host() -> None:
    with pytest.raises(HydraError):
        build_hydra_args(_opts(port=0))
    with pytest.raises(HydraError):
        build_hydra_args(_opts(port=70000))
    with pytest.raises(HydraError):
        build_hydra_args(_opts(host="-sL"))


def test_build_args_tasks_capped() -> None:
    args = build_hydra_args(_opts(tasks=9999))
    assert args[args.index("-t") + 1] == "64"


def test_form_service_requires_and_validates_module_option() -> None:
    with pytest.raises(HydraError):
        build_hydra_args(_opts(service="http-post-form", port=80))
    args = build_hydra_args(_opts(service="http-post-form", port=80, module_option="/login:u=^USER^&p=^PASS^:F=bad"))
    assert args[-1] == "/login:u=^USER^&p=^PASS^:F=bad"
    # перевод строки и управляющие символы запрещены
    with pytest.raises(HydraError):
        validate_module_option("/login\n:x")
    # module option к сервису без формы — ошибка
    with pytest.raises(HydraError):
        build_hydra_args(_opts(service="ssh", module_option="/x"))


def test_parse_hydra_json(tmp_path) -> None:
    good = tmp_path / "ok.json"
    good.write_text(
        '{ "results": [ {"port":22,"service":"ssh","host":"203.0.113.10","login":"admin","password":"admin123"} ],'
        ' "errormessages": [ "note", ] }',
        encoding="utf-8",
    )
    found, errors = parse_hydra_json(str(good))  # висящая запятая должна быть обработана
    assert found == [{"login": "admin", "password": "admin123", "port": 22, "service": "ssh"}]
    assert errors == ["note"]
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    assert parse_hydra_json(str(empty)) == ([], [])
    assert parse_hydra_json(str(tmp_path / "missing.json")) == ([], [])


# --------------------------------------------------------------------------- шлюз авторизации и лимиты


def _target(session, value="203.0.113.10", kind="ip", approved=True) -> Target:
    t = Target(kind=kind, value=value, approved=approved)
    session.add(t)
    session.commit()
    return t


def _create(session, target, **over):
    kw = dict(
        target_id=target.id, service="ssh", port=None, login_list="users-common", password_list="pass-weak",
        combo_list="", module_option="", tasks=4, stop_on_first=True,
        authorization="заявка PENTEST-1", confirm=True, confirm_text="ПОДТВЕРЖДАЮ", username="admin", ip="127.0.0.1",
    )
    kw.update(over)
    return create_hydra_test(session, **kw)


def test_authorization_gate(session) -> None:
    t = _target(session)
    with pytest.raises(ActiveTestError, match="основание"):
        _create(session, t, authorization="")
    with pytest.raises(ActiveTestError, match="согласован"):
        _create(session, t, confirm=False)
    with pytest.raises(ActiveTestError, match="ПОДТВЕРЖДАЮ"):
        _create(session, t, confirm_text="да")


def test_target_must_be_approved_and_not_cidr(session) -> None:
    with pytest.raises(ActiveTestError, match="не утверждена"):
        _create(session, _target(session, "203.0.113.11", approved=False))
    with pytest.raises(ActiveTestError, match="подсет"):
        _create(session, _target(session, "203.0.113.0/28", kind="cidr"))


def test_attempt_cap(session, monkeypatch) -> None:
    monkeypatch.setenv("HYDRA_MAX_ATTEMPTS", "10")
    from app.config import get_settings

    get_settings.cache_clear()
    t = _target(session)
    with pytest.raises(ActiveTestError, match="комбинаци"):
        _create(session, t)  # словари дают заведомо больше 10
    get_settings.cache_clear()


def test_successful_create_records_audit_and_queues(session) -> None:
    from app.models import AuditLog

    t = _target(session)
    test = _create(session, t, service="ftp")
    assert test.kind == "hydra" and test.service == "ftp" and test.port == 21
    assert test.status == ScanStatus.QUEUED.value
    assert test.params["attempts"] > 0 and test.authorization == "заявка PENTEST-1"
    assert session.submitted == [test.id]
    row = session.query(AuditLog).filter_by(action="active_test_start").one()
    assert "PENTEST-1" in row.details and "FTP" in row.details


def test_scope_restriction(session, monkeypatch) -> None:
    monkeypatch.setenv("ALLOWED_SCOPE", "203.0.113.0/24")
    from app.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(ActiveTestError):
        _create(session, _target(session, "198.51.100.5"))
    get_settings.cache_clear()


# --------------------------------------------------------------------------- сквозной прогон настоящей Hydra


class _BasicAuthHandler(http.server.BaseHTTPRequestHandler):
    CREDS = "Basic " + base64.b64encode(b"admin:admin123").decode()

    def do_GET(self) -> None:  # noqa: N802
        if self.headers.get("Authorization") == self.CREDS:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="x"')
            self.end_headers()

    def log_message(self, *a) -> None:
        pass


@pytest.fixture
def basic_auth_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _BasicAuthHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.mark.skipif(not hydra_available(), reason="hydra не установлена")
def test_hydra_end_to_end_finds_weak_credentials(session, basic_auth_server, monkeypatch, tmp_path) -> None:
    """Реальный запуск Hydra против локального HTTP Basic-сервиса: admin:admin123 должен найтись."""
    from app.active.engine import HydraJob

    # маленькие словари, включающие верную пару
    wl = tmp_path / "wl"
    wl.mkdir()
    (wl / "u.txt").write_text("root\nadmin\n", encoding="utf-8")
    (wl / "p.txt").write_text("wrong\nadmin123\n", encoding="utf-8")
    from app.active import engine

    monkeypatch.setitem(engine.WORDLISTS, "u", engine.Wordlist("u", "u", "u.txt", "login"))
    monkeypatch.setitem(engine.WORDLISTS, "p", engine.Wordlist("p", "p", "p.txt", "password"))
    monkeypatch.setattr(engine, "WORDLIST_DIR", wl)
    for w in ("u", "p"):
        object.__setattr__(engine.WORDLISTS[w], "filename", f"{w}.txt")

    test = ActiveTest(
        kind="hydra", status=ScanStatus.QUEUED.value, asset="127.0.0.1", port=basic_auth_server,
        protocol="tcp", service="http-get", started_by="admin",
        params={"mode": "lists", "login_list": "u", "password_list": "p", "tasks": 4, "stop_on_first": True, "module_option": "", "attempts": 4},
    )
    session.add(test)
    session.commit()
    HydraJob(test.id, threading.Event()).run()

    session.expire_all()
    done = session.get(ActiveTest, test.id)
    assert done.status == ScanStatus.DONE.value, done.error
    assert done.severity == "critical"
    found = done.result["found"]
    assert any(c["login"] == "admin" and c["password"] == "admin123" for c in found)
