"""Metasploit: проверка эксплуатируемости (module.check) и эксплуатация (module.execute).

Запуск только вручную администратором, по одной утверждённой цели, с подтверждением.
RHOSTS/RPORT подставляются из выбранной цели — переопределить адрес нельзя.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.active.engine import ActiveTestError, _check_authorization, active_test_manager, validate_active_target
from app.active.msf_client import MsfAuthError, MsfError, MsfRpcClient, client_from_settings, msf_configured
from app.audit import audit
from app.config import get_settings
from app.db import session_scope
from app.models import ActiveTest, ActiveTestKind, ScanStatus, utcnow

log = logging.getLogger("msf")

MODULE_TYPES = ("exploit", "auxiliary")
_MODULE_RE = re.compile(r"^[a-z0-9][a-z0-9_]*(?:/[a-z0-9][a-z0-9_.-]*)+$")
_OPT_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_OPT_VAL_RE = re.compile(r"^[^\x00-\x08\x0a-\x1f\x7f]{0,512}$")
# Адрес цели задаётся только этими опциями — из формы их принимать нельзя.
_RESERVED_OPTS = {"RHOSTS", "RHOST", "RPORT"}

# Код результата module.check → (уровень, человекочитаемо)
# Подсказки распространённых модулей с поддержкой проверки (ввод не ограничен ими).
MSF_CHECK_SUGGESTIONS: list[dict[str, str]] = [
    {"type": "exploit", "name": "windows/smb/ms17_010_eternalblue", "desc": "EternalBlue (SMBv1, MS17-010)"},
    {"type": "auxiliary", "name": "scanner/smb/smb_ms17_010", "desc": "Проверка MS17-010"},
    {"type": "exploit", "name": "multi/http/apache_normalize_path_rce", "desc": "Apache 2.4.49/2.4.50 path traversal RCE"},
    {"type": "exploit", "name": "linux/http/apache_log4shell_header_injection", "desc": "Log4Shell (CVE-2021-44228)"},
    {"type": "auxiliary", "name": "scanner/http/log4shell_scanner", "desc": "Проверка Log4Shell"},
    {"type": "exploit", "name": "multi/http/struts2_content_type_ognl", "desc": "Apache Struts2 (CVE-2017-5638)"},
    {"type": "exploit", "name": "linux/http/confluence_widget_connector", "desc": "Confluence OGNL RCE"},
    {"type": "exploit", "name": "multi/http/gitlab_exif_rce", "desc": "GitLab ExifTool RCE"},
    {"type": "auxiliary", "name": "scanner/ssh/ssh_enumusers", "desc": "Перечисление пользователей SSH"},
    {"type": "auxiliary", "name": "scanner/rdp/cve_2019_0708_bluekeep", "desc": "Проверка BlueKeep (CVE-2019-0708)"},
    {"type": "exploit", "name": "windows/rdp/cve_2019_0708_bluekeep_rce", "desc": "BlueKeep RCE"},
    {"type": "auxiliary", "name": "scanner/http/tomcat_mgr_login", "desc": "Подбор Tomcat Manager"},
]

CHECK_CODES: dict[str, tuple[str, str]] = {
    "vulnerable": ("high", "Уязвим — проверка подтвердила эксплуатируемость"),
    "appears": ("high", "Вероятно уязвим — цель отвечает как уязвимая"),
    "detected": ("medium", "Обнаружен уязвимый сервис (эксплуатация не подтверждена)"),
    "safe": ("info", "Не уязвим"),
    "unsupported": ("info", "Модуль не поддерживает проверку"),
    "unknown": ("info", "Не удалось определить"),
    "nosession": ("info", "Проверка требует активной сессии"),
}


def normalize_module(module_type: str, name: str) -> tuple[str, str]:
    if module_type not in MODULE_TYPES:
        raise ActiveTestError("Некорректный тип модуля")
    name = name.strip().lower()
    # допускаем ввод как с префиксом (exploit/...), так и без него
    if name.startswith(module_type + "/"):
        name = name[len(module_type) + 1 :]
    if not name or ".." in name or not _MODULE_RE.match(name):
        raise ActiveTestError("Некорректное имя модуля")
    return module_type, name


def parse_options(text: str) -> dict[str, str]:
    """Разбирает дополнительные опции модуля из строк «KEY=значение»."""
    opts: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ActiveTestError(f"Опция должна быть в виде KEY=значение: {line!r}")
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not _OPT_KEY_RE.match(key):
            raise ActiveTestError(f"Недопустимое имя опции: {key!r}")
        if not _OPT_VAL_RE.match(value):
            raise ActiveTestError(f"Недопустимое значение опции {key}")
        if key.upper() in _RESERVED_OPTS:
            raise ActiveTestError(f"Опцию {key} задавать нельзя — адрес берётся из выбранной цели")
        opts[key] = value
        if len(opts) > 40:
            raise ActiveTestError("Слишком много опций")
    return opts


def create_msf_test(
    db: Session,
    *,
    kind: str,
    target_id: int,
    module_type: str,
    module_name: str,
    port: int | None,
    options_text: str,
    payload: str,
    authorization: str,
    confirm: bool,
    confirm_text: str,
    username: str,
    ip: str = "",
) -> ActiveTest:
    s = get_settings()
    if not s.active_tests_enabled or not s.msf_enabled:
        raise ActiveTestError("Metasploit отключён в настройках")
    if kind not in (ActiveTestKind.MSF_CHECK.value, ActiveTestKind.MSF_EXPLOIT.value):
        raise ActiveTestError("Некорректный тип проверки")
    if not msf_configured():
        raise ActiveTestError("Не задан пароль RPC Metasploit (MSF_RPC_PASSWORD)")
    authorization = _check_authorization(authorization, confirm, confirm_text)
    module_type, module_name = normalize_module(module_type, module_name)
    extra = parse_options(options_text)
    payload = (payload or "").strip().lower()

    if kind == ActiveTestKind.MSF_EXPLOIT.value:
        if module_type != "exploit":
            raise ActiveTestError("Для эксплуатации нужен модуль типа exploit")
        if payload and (".." in payload or not _MODULE_RE.match(payload.lstrip("/"))):
            raise ActiveTestError("Некорректное имя нагрузки (payload)")

    target, validated = validate_active_target(db, target_id)
    port = int(port) if port else None
    if port is not None and not 1 <= port <= 65535:
        raise ActiveTestError("Некорректный порт")

    params = {
        "module_type": module_type,
        "module": module_name,
        "options": extra,
        "payload": payload,
    }
    test = ActiveTest(
        kind=kind,
        status=ScanStatus.QUEUED.value,
        target_id=target.id,
        asset=validated.value,
        port=port,
        protocol="tcp",
        service=f"{module_type}/{module_name}",
        params=params,
        authorization=authorization,
        started_by=username,
        ip=ip,
    )
    db.add(test)
    db.commit()
    verb = "эксплуатация" if kind == ActiveTestKind.MSF_EXPLOIT.value else "проверка"
    audit(
        db,
        "active_test_start",
        f"Metasploit ({verb}) #{test.id}: {module_type}/{module_name} → {validated.value}"
        + (f":{port}" if port else "")
        + f"; основание: {authorization}",
        username=username,
        ip=ip,
    )
    active_test_manager.submit(test.id)
    return test


# --------------------------------------------------------------------------- выполнение


@dataclass
class _Outcome:
    severity: str
    result: dict


class MsfJob:
    def __init__(self, test_id: int, cancel: threading.Event) -> None:
        self.test_id = test_id
        self.cancel = cancel
        self.s = get_settings()
        self._last = 0.0

    def progress(self, stage: str, pct: float) -> None:
        now = time.monotonic()
        if now - self._last < 1.5 and pct < 99:
            return
        self._last = now
        with session_scope() as db:
            db.execute(
                update(ActiveTest).where(ActiveTest.id == self.test_id).values(stage=stage[:160], progress=round(min(pct, 99.0), 1))
            )

    def run(self) -> None:
        from app.active.engine import _finish

        with session_scope() as db:
            test = db.get(ActiveTest, self.test_id)
            if test is None or test.status != ScanStatus.QUEUED.value:
                return
            test.status = ScanStatus.RUNNING.value
            test.started_at = utcnow()
            test.stage = "Подключение к Metasploit"
            kind, asset, port, params = test.kind, test.asset, test.port, dict(test.params)
        try:
            outcome = self._execute(kind, asset, port, params)
        except (MsfAuthError, MsfError, ActiveTestError) as exc:
            log.warning("MSF #%s: %s", self.test_id, exc)
            _finish(self.test_id, ScanStatus.FAILED, str(exc))
            return
        self._store(outcome)
        _finish(self.test_id, ScanStatus.DONE)
        log.info("MSF #%s завершена: %s", self.test_id, outcome.result.get("code") or outcome.result.get("status"))

    def _build_options(self, asset: str, port: int | None, params: dict) -> dict:
        opts: dict[str, object] = {"RHOSTS": asset}
        if port:
            opts["RPORT"] = port
        opts.update(params.get("options", {}))
        if params.get("payload"):
            opts["PAYLOAD"] = params["payload"]
        return opts

    def _execute(self, kind: str, asset: str, port: int | None, params: dict) -> _Outcome:
        mt, name = params["module_type"], params["module"]
        opts = self._build_options(asset, port, params)
        self.progress("Подключение к Metasploit", 5)
        client = client_from_settings()
        try:
            client.login()
            ver = client.version().get("version", "")
            with session_scope() as db:
                db.execute(update(ActiveTest).where(ActiveTest.id == self.test_id).values(command=f"msf {ver}: {mt}/{name} RHOSTS={asset}" + (f" RPORT={port}" if port else "")))
            if kind == ActiveTestKind.MSF_CHECK.value:
                return self._run_check(client, mt, name, opts)
            return self._run_exploit(client, name, opts)
        finally:
            client.close()

    # ---- проверка эксплуатируемости
    def _run_check(self, client: MsfRpcClient, mt: str, name: str, opts: dict) -> _Outcome:
        self.progress("Запуск проверки", 20)
        res = client.module_check(mt, name, opts)
        code, message, details = self._await_result(client, res, "check")
        sev, human = CHECK_CODES.get(code, ("info", code or "нет данных"))
        return _Outcome(sev, {"mode": "check", "code": code, "status": human, "message": message, "details": details})

    # ---- эксплуатация
    def _run_exploit(self, client: MsfRpcClient, name: str, opts: dict) -> _Outcome:
        self.progress("Запуск эксплойта", 20)
        before = set(self._session_ids(client))
        res = client.module_execute("exploit", name, opts)
        job_id = str(res.get("job_id")) if res.get("job_id") is not None else ""
        uuid = res.get("uuid", "")
        # ждём появления сессии или завершения задачи
        opened: list[dict] = []
        deadline = time.monotonic() + min(self.s.msf_timeout_minutes * 60, 300)
        while time.monotonic() < deadline:
            if self.cancel.is_set():
                break
            self.progress("Ожидание результата эксплойта", 60)
            sessions = client.session_list()
            new_ids = set(map(str, sessions.keys())) - before
            if new_ids:
                opened = [{"id": sid, **_session_summary(sessions.get(sid, {}))} for sid in sorted(new_ids)]
                break
            jobs = client.jobs()
            if job_id and job_id not in {str(k) for k in jobs.keys()}:
                break  # задача завершилась без сессии
            time.sleep(3)
        success = bool(opened)
        sev = "critical" if success else "info"
        status = "Эксплуатация успешна — открыта сессия" if success else "Сессия не получена (эксплуатация не удалась)"
        return _Outcome(sev, {"mode": "exploit", "success": success, "status": status, "sessions": opened, "uuid": uuid, "job_id": job_id})

    def _await_result(self, client: MsfRpcClient, res: dict, mode: str) -> tuple[str, str, dict]:
        # module.check может вернуть результат сразу или по uuid через module.results
        if res.get("code"):
            return str(res["code"]), str(res.get("message", "")), res
        uuid = res.get("uuid", "")
        if not uuid:
            return "unknown", str(res.get("error_message") or res.get("message") or ""), res
        deadline = time.monotonic() + min(self.s.msf_timeout_minutes * 60, 300)
        last: dict = {}
        while time.monotonic() < deadline:
            if self.cancel.is_set():
                return "unknown", "Отменено", last
            last = client.module_results(uuid)
            status = str(last.get("status", ""))
            self.progress("Проверка выполняется", 50)
            if status in ("completed", "complete"):
                result = last.get("result") or {}
                if isinstance(result, dict):
                    return str(result.get("code", "unknown")), str(result.get("message", "")), result
                return "unknown", str(result), last
            if status in ("errored", "error", "failed"):
                return "unknown", str(last.get("error") or last.get("result") or "ошибка"), last
            time.sleep(2)
        return "unknown", "Превышено время ожидания результата", last

    def _session_ids(self, client: MsfRpcClient) -> list[str]:
        try:
            return [str(k) for k in client.session_list().keys()]
        except MsfError:
            return []

    def _store(self, outcome: _Outcome) -> None:
        with session_scope() as db:
            test = db.get(ActiveTest, self.test_id)
            assert test is not None
            test.severity = outcome.severity
            test.result = outcome.result
            if outcome.severity in ("critical", "high"):
                audit(
                    db,
                    "active_test_finding",
                    f"Metasploit #{test.id}: {outcome.result.get('status')} — {test.service} на {test.asset}",
                    username=test.started_by,
                    ip=test.ip,
                )


def _session_summary(sess: dict) -> dict:
    return {
        "type": sess.get("type", ""),
        "info": sess.get("info", ""),
        "tunnel_peer": sess.get("tunnel_peer", ""),
        "via_exploit": sess.get("via_exploit", ""),
    }


__all__ = ["create_msf_test", "MsfJob", "normalize_module", "parse_options", "CHECK_CODES", "MSF_CHECK_SUGGESTIONS"]
