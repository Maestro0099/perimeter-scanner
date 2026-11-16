"""Оркестрация активных проверок (пока — Hydra).

Запуск только вручную администратором, по одной утверждённой цели, с обязательным
указанием основания. Повторная валидация цели и лимитов выполняется перед стартом.
"""

from __future__ import annotations

import logging
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.active.hydra_runner import (
    SERVICES,
    HydraCancelled,
    HydraError,
    HydraOptions,
    HydraResult,
    HydraTimeout,
    build_hydra_args,
    run_hydra,
    validate_module_option,
)
from app.audit import audit
from app.config import BASE_DIR, get_settings
from app.db import session_scope
from app.models import ActiveTest, ActiveTestKind, ScanStatus, Target, utcnow
from app.validation import ValidationError, parse_scope, validate_in_scope, validate_timing  # noqa: F401

log = logging.getLogger("active")

WORDLIST_DIR = BASE_DIR / "data" / "wordlists"


class ActiveTestError(ValueError):
    """Ошибка запроса активной проверки (сообщение для пользователя)."""


# --------------------------------------------------------------------------- словари


@dataclass(frozen=True)
class Wordlist:
    key: str
    label: str
    filename: str
    kind: str  # "login" | "password" | "combo"

    @property
    def path(self) -> Path:
        return WORDLIST_DIR / self.filename

    def entries(self) -> list[str]:
        if not self.path.is_file():
            return []
        out: list[str] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
        return out

    @property
    def count(self) -> int:
        return len(self.entries())


WORDLISTS: dict[str, Wordlist] = {
    "users-common": Wordlist("users-common", "Распространённые логины", "usernames-common.txt", "login"),
    "pass-weak": Wordlist("pass-weak", "Слабые и дефолтные пароли", "passwords-weak.txt", "password"),
    "default-creds": Wordlist("default-creds", "Пары логин:пароль по умолчанию", "default-creds.txt", "combo"),
}


def wordlists_by_kind(kind: str) -> list[Wordlist]:
    return [w for w in WORDLISTS.values() if w.kind == kind]


# --------------------------------------------------------------------------- создание проверки


def _check_authorization(authorization: str, confirm: bool, confirm_text: str) -> str:
    authorization = (authorization or "").strip()
    if len(authorization) < 3:
        raise ActiveTestError("Укажите основание проверки (разрешение, номер заявки)")
    if len(authorization) > 1000:
        raise ActiveTestError("Слишком длинное основание")
    if not confirm:
        raise ActiveTestError("Подтвердите, что проверка согласована с владельцами систем")
    if confirm_text.strip().upper() != "ПОДТВЕРЖДАЮ":
        raise ActiveTestError("Для запуска введите слово «ПОДТВЕРЖДАЮ»")
    return authorization


def validate_active_target(db: Session, target_id: int):  # noqa: ANN201
    """Проверяет цель активной проверки: существует, утверждена, в области, не подсеть.
    Возвращает (Target, ValidatedTarget)."""
    s = get_settings()
    target = db.get(Target, target_id)
    if target is None:
        raise ActiveTestError("Цель не найдена")
    if not target.approved:
        raise ActiveTestError(f"Цель {target.value} не утверждена для проверки")
    try:
        validated = validate_in_scope(target.value, parse_scope(s.allowed_scope), s.max_cidr_hosts)
    except ValidationError as exc:
        raise ActiveTestError(str(exc)) from exc
    if validated.kind.value == "cidr":
        raise ActiveTestError("Активные проверки выполняются по одному адресу или домену, не по подсети")
    return target, validated


def create_hydra_test(
    db: Session,
    *,
    target_id: int,
    service: str,
    port: int | None,
    login_list: str,
    password_list: str,
    combo_list: str,
    module_option: str,
    tasks: int,
    stop_on_first: bool,
    authorization: str,
    confirm: bool,
    confirm_text: str,
    username: str,
    ip: str = "",
) -> ActiveTest:
    s = get_settings()
    if not (s.active_tests_enabled and s.hydra_enabled):
        raise ActiveTestError("Подбор учётных данных отключён в настройках")
    svc = SERVICES.get(service)
    if svc is None:
        raise ActiveTestError("Выбран неподдерживаемый сервис")
    authorization = _check_authorization(authorization, confirm, confirm_text)

    target, validated = validate_active_target(db, target_id)

    port = int(port) if port else svc.default_port
    if not 1 <= port <= 65535:
        raise ActiveTestError("Некорректный порт")
    tasks = max(1, min(int(tasks or s.hydra_default_tasks), s.hydra_max_tasks))

    # Выбор словарей и проверка лимита числа попыток
    params: dict = {"mode": "", "login_list": "", "password_list": "", "combo_list": "", "attempts": 0}
    if combo_list:
        combo = WORDLISTS.get(combo_list)
        if combo is None or combo.kind != "combo":
            raise ActiveTestError("Некорректный список пар логин:пароль")
        attempts = combo.count
        params.update(mode="combo", combo_list=combo.key)
    else:
        logins = WORDLISTS.get(login_list)
        passwords = WORDLISTS.get(password_list)
        if logins is None or logins.kind != "login":
            raise ActiveTestError("Выберите список логинов")
        if passwords is None or passwords.kind != "password":
            raise ActiveTestError("Выберите список паролей")
        attempts = logins.count * passwords.count
        params.update(mode="lists", login_list=logins.key, password_list=passwords.key)
    if attempts == 0:
        raise ActiveTestError("Выбранные словари пусты")
    if attempts > s.hydra_max_attempts:
        raise ActiveTestError(
            f"Слишком много комбинаций ({attempts}); лимит — {s.hydra_max_attempts}. "
            "Это защищает от блокировки учётных записей. Выберите меньшие словари."
        )

    if svc.needs_module_option:
        try:
            module_option = validate_module_option(module_option)
        except HydraError as exc:
            raise ActiveTestError(str(exc)) from exc
    else:
        module_option = ""
    params.update(tasks=tasks, stop_on_first=bool(stop_on_first), module_option=module_option, attempts=attempts)

    test = ActiveTest(
        kind=ActiveTestKind.HYDRA.value,
        status=ScanStatus.QUEUED.value,
        target_id=target.id,
        asset=validated.value,
        port=port,
        protocol=svc.protocol,
        service=svc.key,
        params=params,
        authorization=authorization,
        started_by=username,
        ip=ip,
    )
    db.add(test)
    db.commit()
    audit(
        db,
        "active_test_start",
        f"Hydra #{test.id}: {svc.label} {validated.value}:{port}, комбинаций: {attempts}; основание: {authorization}",
        username=username,
        ip=ip,
    )
    active_test_manager.submit(test.id)
    return test


# --------------------------------------------------------------------------- менеджер очереди


class ActiveTestManager:
    def __init__(self) -> None:
        self._executor: ThreadPoolExecutor | None = None
        self._cancel: dict[int, threading.Event] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._executor is not None:
            return
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="active")
        with session_scope() as db:
            db.execute(
                update(ActiveTest)
                .where(ActiveTest.status == ScanStatus.RUNNING.value)
                .values(status=ScanStatus.FAILED.value, error="Прервано перезапуском приложения", finished_at=utcnow())
            )
            queued = list(db.scalars(select(ActiveTest.id).where(ActiveTest.status == ScanStatus.QUEUED.value)))
        for tid in queued:
            self.submit(tid)

    def shutdown(self) -> None:
        with self._lock:
            for ev in self._cancel.values():
                ev.set()
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

    def submit(self, test_id: int) -> None:
        if self._executor is None:
            self.start()
        assert self._executor is not None
        with self._lock:
            self._cancel[test_id] = threading.Event()
        self._executor.submit(self._run_safe, test_id)

    def cancel(self, test_id: int) -> bool:
        with self._lock:
            ev = self._cancel.get(test_id)
        if ev is not None:
            ev.set()
        with session_scope() as db:
            test = db.get(ActiveTest, test_id)
            if test and test.status == ScanStatus.QUEUED.value:
                test.status = ScanStatus.CANCELLED.value
                test.finished_at = utcnow()
                test.stage = "Отменён"
                return True
        return ev is not None

    def _job_for(self, test_id: int):  # noqa: ANN202
        with session_scope() as db:
            test = db.get(ActiveTest, test_id)
            kind = test.kind if test else ""
        if kind == ActiveTestKind.HYDRA.value:
            return HydraJob
        if kind in (ActiveTestKind.MSF_CHECK.value, ActiveTestKind.MSF_EXPLOIT.value):
            from app.active.msf_engine import MsfJob

            return MsfJob
        return None

    def _run_safe(self, test_id: int) -> None:
        with self._lock:
            cancel = self._cancel.setdefault(test_id, threading.Event())
        job_cls = self._job_for(test_id)
        if job_cls is None:
            _finish(test_id, ScanStatus.FAILED, "Неизвестный тип проверки")
            return
        try:
            job_cls(test_id, cancel).run()
        except Exception:  # noqa: BLE001
            log.exception("Необработанная ошибка активной проверки #%s", test_id)
            _finish(test_id, ScanStatus.FAILED, "Внутренняя ошибка, подробности в журнале приложения")
        finally:
            with self._lock:
                self._cancel.pop(test_id, None)


active_test_manager = ActiveTestManager()


def _finish(test_id: int, status: ScanStatus, error: str = "") -> None:
    with session_scope() as db:
        test = db.get(ActiveTest, test_id)
        if test is None:
            return
        test.status = status.value
        test.error = error[:4000]
        test.finished_at = utcnow()
        test.stage = {"done": "Завершена", "cancelled": "Отменена", "failed": "Ошибка"}.get(status.value, test.stage)
        if status == ScanStatus.DONE:
            test.progress = 100.0


# --------------------------------------------------------------------------- выполнение


class HydraJob:
    def __init__(self, test_id: int, cancel: threading.Event) -> None:
        self.test_id = test_id
        self.cancel = cancel
        self.s = get_settings()
        self.workdir = self.s.data_dir / "active" / str(test_id)
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
        with session_scope() as db:
            test = db.get(ActiveTest, self.test_id)
            if test is None or test.status != ScanStatus.QUEUED.value:
                return
            test.status = ScanStatus.RUNNING.value
            test.started_at = utcnow()
            test.stage = "Подготовка"
            service, host, port = test.service, test.asset, test.port
            params = dict(test.params)
        self.workdir.mkdir(parents=True, exist_ok=True)
        try:
            result = self._execute(service, host, int(port or 0), params)
        except HydraCancelled:
            _finish(self.test_id, ScanStatus.CANCELLED, "Отменено пользователем")
            return
        except (HydraTimeout, HydraError, ActiveTestError, ValidationError) as exc:
            log.warning("Hydra #%s: %s", self.test_id, exc)
            _finish(self.test_id, ScanStatus.FAILED, str(exc))
            return
        self._store(result)
        _finish(self.test_id, ScanStatus.DONE)
        log.info("Hydra #%s завершена, найдено пар: %s", self.test_id, len(result.found))

    def _execute(self, service: str, host: str, port: int, params: dict) -> HydraResult:
        login_file = self.workdir / "logins.txt"
        pass_file = self.workdir / "passwords.txt"
        combo_file = self.workdir / "combo.txt"
        out_file = self.workdir / "result.json"
        out_file.unlink(missing_ok=True)

        opts_kwargs: dict = {}
        if params.get("mode") == "combo":
            combo = WORDLISTS[params["combo_list"]]
            combo_file.write_text("\n".join(combo.entries()) + "\n", encoding="utf-8")
            opts_kwargs["combo_file"] = str(combo_file)
            # для совместимости интерфейса build_hydra_args
            opts_kwargs["login_file"] = str(combo_file)
        else:
            WORDLISTS[params["login_list"]]  # noqa: B018 валидность уже проверена
            login_file.write_text("\n".join(WORDLISTS[params["login_list"]].entries()) + "\n", encoding="utf-8")
            pass_file.write_text("\n".join(WORDLISTS[params["password_list"]].entries()) + "\n", encoding="utf-8")
            opts_kwargs["login_file"] = str(login_file)
            opts_kwargs["password_file"] = str(pass_file)

        opts = HydraOptions(
            service=service,
            host=host,
            port=port,
            tasks=int(params.get("tasks", self.s.hydra_default_tasks)),
            module_option=params.get("module_option", ""),
            stop_on_first=bool(params.get("stop_on_first", True)),
            output_file=str(out_file),
            **opts_kwargs,
        )
        args = build_hydra_args(opts)
        with session_scope() as db:
            db.execute(
                update(ActiveTest).where(ActiveTest.id == self.test_id).values(
                    command=shlex.join([self.s.hydra_path, *args]), stage="Запуск Hydra"
                )
            )
        return run_hydra(
            self.s.hydra_path,
            args,
            timeout_s=self.s.hydra_timeout_minutes * 60,
            output_file=str(out_file),
            on_progress=self.progress,
            cancel_event=self.cancel,
        )

    def _store(self, result: HydraResult) -> None:
        found = result.found
        severity = "critical" if found else "info"
        with session_scope() as db:
            test = db.get(ActiveTest, self.test_id)
            assert test is not None
            test.severity = severity
            test.result = {
                "found": found,
                "found_count": len(found),
                "errors": result.errors,
                "returncode": result.returncode,
                "duration": round(result.duration, 1),
            }
            if found:
                creds = ", ".join(f"{c['login']}:{c['password']}" for c in found[:10])
                audit(
                    db,
                    "active_test_finding",
                    f"Hydra #{test.id}: обнаружены слабые учётные данные на {test.asset}:{test.port} — {creds}",
                    username=test.started_by,
                    ip=test.ip,
                )


def active_tests(db: Session) -> list[ActiveTest]:
    return list(
        db.scalars(
            select(ActiveTest)
            .where(ActiveTest.status.in_([ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]))
            .order_by(ActiveTest.created_at)
        )
    )


__all__ = [
    "create_hydra_test", "active_test_manager", "ActiveTestError", "WORDLISTS",
    "wordlists_by_kind", "active_tests", "validate_active_target", "_check_authorization",
]
