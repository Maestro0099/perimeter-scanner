"""Metasploit: RPC-клиент, валидация модулей/опций, движок проверки и эксплуатации (с заглушкой RPC)."""

from __future__ import annotations

import threading

import msgpack
import pytest

from app import db as dbmod
from app.active.engine import ActiveTestError
from app.active.msf_client import MsfAuthError, MsfError, MsfRpcClient, _to_native
from app.active.msf_engine import CHECK_CODES, MsfJob, create_msf_test, normalize_module, parse_options
from app.models import ActiveTest, ActiveTestKind, ScanStatus, Target


@pytest.fixture
def session(monkeypatch):
    dbmod.init_engine()
    dbmod.create_all()
    from app.active import engine

    monkeypatch.setattr(engine.active_test_manager, "submit", lambda tid: None)
    monkeypatch.setenv("MSF_ENABLED", "true")
    monkeypatch.setenv("MSF_RPC_PASSWORD", "rpc-secret")
    from app.config import get_settings

    get_settings.cache_clear()
    s = dbmod.new_session()
    yield s
    s.close()
    get_settings.cache_clear()


# --------------------------------------------------------------------------- RPC-клиент


class _FakeResp:
    def __init__(self, payload) -> None:
        self.status_code = 200
        self.content = msgpack.packb(payload, use_bin_type=True)


class _FakeHttp:
    def __init__(self, responses) -> None:
        self._responses = list(responses)
        self.sent: list = []

    def post(self, url, content, headers):
        self.sent.append(msgpack.unpackb(content, raw=False))
        return _FakeResp(self._responses.pop(0))

    def close(self) -> None:
        pass


def _client(monkeypatch, responses) -> MsfRpcClient:
    c = MsfRpcClient("msf", 55553, "rpc-secret")
    monkeypatch.setattr(c, "_client", _FakeHttp(responses))
    return c


def test_to_native_decodes_bytes() -> None:
    assert _to_native({b"k": [b"a", 1]}) == {"k": ["a", 1]}


def test_client_requires_password() -> None:
    with pytest.raises(MsfError):
        MsfRpcClient("h", 1, "")


def test_client_login_and_call(monkeypatch) -> None:
    c = _client(monkeypatch, [{"result": "success", "token": "TKN"}, {"version": "6.4.44"}])
    c.login()
    assert c._token == "TKN"
    assert c.version() == {"version": "6.4.44"}
    # второй запрос отправлен с токеном
    assert c._client.sent[1][:2] == ["core.version", "TKN"]


def test_client_login_failure(monkeypatch) -> None:
    c = _client(monkeypatch, [{"result": "failure"}])
    with pytest.raises(MsfAuthError):
        c.login()


def test_client_rpc_error(monkeypatch) -> None:
    c = _client(monkeypatch, [{"result": "success", "token": "T"}, {"error": True, "error_message": "bad module"}])
    c.login()
    with pytest.raises(MsfError, match="bad module"):
        c.call("module.info", "exploit", "x")


# --------------------------------------------------------------------------- валидация


def test_normalize_module() -> None:
    assert normalize_module("exploit", "windows/smb/ms17_010_eternalblue") == ("exploit", "windows/smb/ms17_010_eternalblue")
    assert normalize_module("exploit", "exploit/windows/smb/ms17_010_eternalblue")[1] == "windows/smb/ms17_010_eternalblue"
    assert normalize_module("auxiliary", "scanner/smb/smb_ms17_010")[0] == "auxiliary"
    for bad in [("bad", "x/y"), ("exploit", ""), ("exploit", "../etc/passwd"), ("exploit", "a b"), ("exploit", "win;id")]:
        with pytest.raises(ActiveTestError):
            normalize_module(*bad)


def test_parse_options() -> None:
    assert parse_options("SSL=true\nTARGETURI=/\n# коммент\n") == {"SSL": "true", "TARGETURI": "/"}
    assert parse_options("") == {}
    with pytest.raises(ActiveTestError, match="RHOSTS"):
        parse_options("RHOSTS=1.2.3.4")
    with pytest.raises(ActiveTestError, match="RPORT"):
        parse_options("RPORT=80")
    for bad in ["noeq", "1KEY=1", "K EY=1", "K=" + "x" * 600]:
        with pytest.raises(ActiveTestError):
            parse_options(bad)


def _target(session, value="203.0.113.10", approved=True, kind="ip") -> Target:
    t = Target(kind=kind, value=value, approved=approved)
    session.add(t)
    session.commit()
    return t


def _mk(session, target, **over):
    kw = dict(
        kind=ActiveTestKind.MSF_CHECK.value, target_id=target.id, module_type="exploit",
        module_name="windows/smb/ms17_010_eternalblue", port=445, options_text="", payload="",
        authorization="заявка-7", confirm=True, confirm_text="ПОДТВЕРЖДАЮ", username="admin", ip="127.0.0.1",
    )
    kw.update(over)
    return create_msf_test(session, **kw)


def test_create_check_gate_and_validation(session) -> None:
    t = _target(session)
    with pytest.raises(ActiveTestError, match="ПОДТВЕРЖДАЮ"):
        _mk(session, t, confirm_text="нет")
    with pytest.raises(ActiveTestError, match="основание"):
        _mk(session, t, authorization="")
    with pytest.raises(ActiveTestError, match="не утверждена"):
        _mk(session, _target(session, "203.0.113.99", approved=False))
    with pytest.raises(ActiveTestError, match="подсет"):
        _mk(session, _target(session, "203.0.113.0/28", kind="cidr"))
    # успешное создание
    test = _mk(session, t)
    assert test.kind == "msf_check" and test.service == "exploit/windows/smb/ms17_010_eternalblue"
    assert test.status == ScanStatus.QUEUED.value


def test_exploit_requires_exploit_module(session) -> None:
    t = _target(session)
    with pytest.raises(ActiveTestError, match="exploit"):
        _mk(session, t, kind=ActiveTestKind.MSF_EXPLOIT.value, module_type="auxiliary", module_name="scanner/x/y")
    with pytest.raises(ActiveTestError, match="payload"):
        _mk(session, t, kind=ActiveTestKind.MSF_EXPLOIT.value, payload="bad payload name")


def test_disabled_when_no_password(session, monkeypatch) -> None:
    monkeypatch.setenv("MSF_RPC_PASSWORD", "")
    from app.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(ActiveTestError, match="пароль"):
        _mk(session, _target(session))


# --------------------------------------------------------------------------- движок (с заглушкой RPC)


class _FakeClient:
    def __init__(self, **behavior) -> None:
        self.b = behavior
        self.calls: list = []
        self._executed = False

    def login(self):
        self.calls.append("login")

    def version(self):
        return {"version": "6.4.44"}

    def module_check(self, mt, name, opts):
        self.calls.append(("check", mt, name, dict(opts)))
        return self.b.get("check", {"code": "vulnerable", "message": "The target is vulnerable."})

    def module_results(self, uuid):
        return self.b.get("results", {})

    def module_execute(self, mt, name, opts):
        self.calls.append(("execute", mt, name, dict(opts)))
        self._executed = True
        return self.b.get("execute", {"job_id": 3, "uuid": "u1"})

    def session_list(self):
        return self.b.get("sessions", {}) if self._executed else {}

    def jobs(self):
        return self.b.get("jobs", {})

    def close(self):
        self.calls.append("close")


def _run_with_fake(session, monkeypatch, test, fake) -> ActiveTest:
    from app.active import msf_engine

    monkeypatch.setattr(msf_engine, "client_from_settings", lambda: fake)
    MsfJob(test.id, threading.Event()).run()
    session.expire_all()
    return session.get(ActiveTest, test.id)


def test_check_vulnerable_sets_rhosts_and_severity(session, monkeypatch) -> None:
    t = _target(session)
    test = _mk(session, t, port=445, options_text="SMBDirect=true")
    fake = _FakeClient(check={"code": "vulnerable", "message": "vuln"})
    done = _run_with_fake(session, monkeypatch, test, fake)
    assert done.status == ScanStatus.DONE.value
    assert done.severity == "high" and done.result["code"] == "vulnerable"
    # RHOSTS подставлен из цели, RPORT из порта, доп.опция передана
    _, mt, name, opts = next(c for c in fake.calls if isinstance(c, tuple) and c[0] == "check")
    assert opts["RHOSTS"] == "203.0.113.10" and opts["RPORT"] == 445 and opts["SMBDirect"] == "true"


def test_check_safe_is_info(session, monkeypatch) -> None:
    t = _target(session)
    test = _mk(session, t)
    done = _run_with_fake(session, monkeypatch, test, _FakeClient(check={"code": "safe", "message": "ok"}))
    assert done.severity == "info" and done.result["code"] == "safe"


def test_check_async_via_results(session, monkeypatch) -> None:
    t = _target(session)
    test = _mk(session, t)
    fake = _FakeClient(check={"uuid": "abc"}, results={"status": "completed", "result": {"code": "appears", "message": "x"}})
    done = _run_with_fake(session, monkeypatch, test, fake)
    assert done.severity == "high" and done.result["code"] == "appears"


def test_exploit_success_records_session_and_audit(session, monkeypatch) -> None:
    from app.models import AuditLog

    t = _target(session)
    test = _mk(session, t, kind=ActiveTestKind.MSF_EXPLOIT.value, module_name="windows/smb/ms17_010_eternalblue",
               payload="windows/x64/meterpreter/reverse_tcp", options_text="LHOST=203.0.113.5")
    fake = _FakeClient(
        execute={"job_id": 5, "uuid": "u9"},
        sessions={"1": {"type": "meterpreter", "tunnel_peer": "203.0.113.10:445", "via_exploit": "exploit/windows/smb/ms17_010_eternalblue"}},
    )
    done = _run_with_fake(session, monkeypatch, test, fake)
    assert done.status == ScanStatus.DONE.value
    assert done.severity == "critical" and done.result["success"] is True
    assert done.result["sessions"][0]["id"] == "1"
    _, mt, name, opts = next(c for c in fake.calls if isinstance(c, tuple) and c[0] == "execute")
    assert opts["PAYLOAD"] == "windows/x64/meterpreter/reverse_tcp" and opts["LHOST"] == "203.0.113.5"
    assert session.query(AuditLog).filter_by(action="active_test_finding").count() == 1


def test_exploit_without_session_is_info(session, monkeypatch) -> None:
    t = _target(session)
    test = _mk(session, t, kind=ActiveTestKind.MSF_EXPLOIT.value)
    fake = _FakeClient(execute={"job_id": 7, "uuid": "u"}, sessions={}, jobs={})  # задача исчезла, сессии нет
    done = _run_with_fake(session, monkeypatch, test, fake)
    assert done.severity == "info" and done.result["success"] is False


def test_rpc_failure_fails_test(session, monkeypatch) -> None:
    t = _target(session)
    test = _mk(session, t)

    class _Boom(_FakeClient):
        def module_check(self, *a):
            raise MsfError("Metasploit RPC недоступен: ConnectError")

    done = _run_with_fake(session, monkeypatch, test, _Boom())
    assert done.status == ScanStatus.FAILED.value and "недоступен" in done.error


def test_check_codes_cover_common_states() -> None:
    assert CHECK_CODES["vulnerable"][0] == "high" and CHECK_CODES["safe"][0] == "info"
