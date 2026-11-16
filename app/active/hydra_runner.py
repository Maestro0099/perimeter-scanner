"""Запуск Hydra для подбора учётных данных.

Hydra вызывается списком аргументов через subprocess (без shell). Имя цели
передаётся отдельным позиционным аргументом и предварительно проверяется как
IP/домен из утверждённого списка, поэтому не может быть истолковано как опция.
Сервис выбирается только из белого списка SERVICES.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

log = logging.getLogger("hydra")


class HydraError(RuntimeError):
    pass


class HydraCancelled(HydraError):
    pass


class HydraTimeout(HydraError):
    pass


@dataclass(frozen=True)
class HydraService:
    key: str  # имя сервиса hydra
    label: str
    default_port: int
    protocol: str = "tcp"
    needs_module_option: bool = False
    note: str = ""


# Белый список сервисов. Только те, что требуют host/port/login/password
# (плюс http-*-form, где нужна строка параметров формы). Категории опасной
# нагрузки Hydra не поддерживает — это чистый подбор учётных данных.
SERVICES: dict[str, HydraService] = {
    "ssh": HydraService("ssh", "SSH", 22),
    "ftp": HydraService("ftp", "FTP", 21),
    "ftps": HydraService("ftps", "FTPS", 990),
    "telnet": HydraService("telnet", "Telnet", 23),
    "smtp": HydraService("smtp", "SMTP (AUTH)", 25),
    "pop3": HydraService("pop3", "POP3", 110),
    "pop3s": HydraService("pop3s", "POP3S", 995),
    "imap": HydraService("imap", "IMAP", 143),
    "imaps": HydraService("imaps", "IMAPS", 993),
    "mysql": HydraService("mysql", "MySQL / MariaDB", 3306),
    "postgres": HydraService("postgres", "PostgreSQL", 5432),
    "mssql": HydraService("mssql", "Microsoft SQL Server", 1433),
    "vnc": HydraService("vnc", "VNC", 5900),
    "rdp": HydraService("rdp", "RDP", 3389),
    "smb": HydraService("smb", "SMB", 445),
    "ldap2": HydraService("ldap2", "LDAP (v2)", 389),
    "ldap3": HydraService("ldap3", "LDAP (v3)", 389),
    "snmp": HydraService("snmp", "SNMP", 161, protocol="udp"),
    "http-get": HydraService("http-get", "HTTP Basic (GET)", 80, note="Базовая HTTP-аутентификация"),
    "https-get": HydraService("https-get", "HTTPS Basic (GET)", 443, note="Базовая HTTP-аутентификация"),
    "http-post-form": HydraService(
        "http-post-form", "HTTP форма входа (POST)", 80, needs_module_option=True,
        note='Нужна строка формы hydra: "/path:user=^USER^&pass=^PASS^:F=текст-ошибки"',
    ),
    "https-post-form": HydraService(
        "https-post-form", "HTTPS форма входа (POST)", 443, needs_module_option=True,
        note='Нужна строка формы hydra: "/path:user=^USER^&pass=^PASS^:F=текст-ошибки"',
    ),
}

# Для http[s]-*-form module option задаёт логику формы; остальные символы, кроме
# очевидно опасных управляющих, допустимы. Shell не используется, поэтому угрозы
# внедрения команды нет; ограничиваем длину и запрещаем переводы строк.
_MODULE_OPTION_RE = re.compile(r"^[^\x00-\x08\x0a-\x1f\x7f]{1,512}$")

_FOUND_RE = re.compile(r"login:\s*(?P<login>.*?)\s+password:\s*(?P<password>.*?)\s*$")
_PROGRESS_RE = re.compile(r"(?P<done>\d+) of (?P<total>\d+) target")


def hydra_available(path: str = "hydra") -> bool:
    return shutil.which(path) is not None


def validate_module_option(value: str) -> str:
    value = value.strip()
    if not _MODULE_OPTION_RE.match(value):
        raise HydraError("Недопустимая строка параметров формы")
    return value


@dataclass
class HydraOptions:
    service: str
    host: str
    port: int
    tasks: int
    login_file: str
    password_file: str | None = None
    combo_file: str | None = None  # файл login:password (режим -C)
    module_option: str = ""
    stop_on_first: bool = True
    output_file: str = ""


def build_hydra_args(opts: HydraOptions) -> list[str]:
    svc = SERVICES.get(opts.service)
    if svc is None:
        raise HydraError(f"Сервис {opts.service!r} не поддерживается")
    if not 1 <= opts.port <= 65535:
        raise HydraError("Некорректный порт")
    tasks = max(1, min(int(opts.tasks), 64))
    if opts.host.startswith("-"):
        raise HydraError("Некорректный адрес цели")

    args: list[str] = []
    if opts.combo_file:
        args += ["-C", opts.combo_file]
    else:
        args += ["-L", opts.login_file]
        if not opts.password_file:
            raise HydraError("Не задан список паролей")
        args += ["-P", opts.password_file]

    args += ["-t", str(tasks), "-s", str(opts.port), "-u", "-w", "5", "-W", "1"]
    if opts.stop_on_first:
        args.append("-f")  # остановиться на первой найденной паре (меньше нагрузка)
    if opts.output_file:
        args += ["-o", opts.output_file, "-b", "json"]
    args += [opts.host, svc.key]

    if svc.needs_module_option:
        if not opts.module_option:
            raise HydraError(f"Для сервиса {svc.label} нужна строка параметров формы")
        args.append(validate_module_option(opts.module_option))
    elif opts.module_option:
        raise HydraError("Строка параметров не применима к этому сервису")
    return args


@dataclass
class HydraResult:
    returncode: int
    found: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stdout_tail: str = ""
    duration: float = 0.0


def parse_hydra_json(path: str) -> tuple[list[dict[str, str]], list[str]]:
    try:
        raw = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return [], []
    if not raw.strip():
        return [], []
    # Hydra иногда оставляет висящую запятую в errormessages — подчистим.
    cleaned = re.sub(r",(\s*[}\]])", r"\1", raw)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return [], ["Не удалось разобрать JSON-вывод Hydra"]
    found = [
        {"login": str(r.get("login", "")), "password": str(r.get("password", "")),
         "port": r.get("port"), "service": str(r.get("service", ""))}
        for r in data.get("results", []) if isinstance(r, dict)
    ]
    errors = [str(e) for e in data.get("errormessages", []) if str(e).strip()]
    return found, errors


def run_hydra(
    hydra_path: str,
    args: list[str],
    *,
    timeout_s: float,
    output_file: str,
    on_progress: Callable[[str, float], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> HydraResult:
    exe = shutil.which(hydra_path)
    if not exe:
        raise HydraError(f"hydra не найдена ({hydra_path}). Установите пакет hydra.")
    cmd = [exe, *args]
    log.info("Запуск hydra: %s", " ".join(cmd))
    started = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 — список аргументов, shell=False
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        start_new_session=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")},
    )
    tail: list[str] = []
    live_found: list[dict[str, str]] = []

    def _reader() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            tail.append(line)
            if len(tail) > 400:
                del tail[:200]
            m = _FOUND_RE.search(line)
            if m and "host:" in line:
                live_found.append({"login": m.group("login"), "password": m.group("password")})
            if on_progress:
                pm = _PROGRESS_RE.search(line)
                if pm and int(pm.group("total")):
                    pct = 100.0 * int(pm.group("done")) / int(pm.group("total"))
                    try:
                        on_progress("Подбор учётных данных", min(pct, 99.0))
                    except Exception:  # noqa: BLE001
                        pass

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()
    try:
        while True:
            try:
                proc.wait(timeout=1.0)
                break
            except subprocess.TimeoutExpired:
                pass
            if cancel_event is not None and cancel_event.is_set():
                _terminate(proc)
                raise HydraCancelled("Проверка отменена")
            if time.monotonic() - started > timeout_s:
                _terminate(proc)
                raise HydraTimeout(f"Превышено время проверки ({int(timeout_s // 60)} мин)")
    finally:
        reader.join(timeout=5)

    found, errors = parse_hydra_json(output_file)
    if not found and live_found:
        found = live_found
    return HydraResult(
        returncode=proc.returncode,
        found=found,
        errors=errors,
        stdout_tail="".join(tail[-40:]),
        duration=time.monotonic() - started,
    )


def _terminate(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
