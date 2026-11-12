"""Запуск nmap через subprocess (список аргументов, без shell) с таймаутом,
отменой и отслеживанием прогресса по выводу --stats-every."""

from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

log = logging.getLogger("nmap")

_PERCENT_RE = re.compile(r"^(?P<phase>[\w .\-]+?) Timing: About (?P<pct>[\d.]+)% done")
_NSE_RE = re.compile(r"^NSE Timing: About (?P<pct>[\d.]+)% done")

# Доля общего прогресса, отводимая каждой фазе nmap: (начало, конец) в процентах.
PHASES: list[tuple[str, tuple[float, float]]] = [
    ("Ping Scan", (0, 5)),
    ("Parallel DNS", (0, 5)),
    ("SYN Stealth Scan", (5, 45)),
    ("Connect Scan", (5, 45)),
    ("UDP Scan", (45, 60)),
    ("Service scan", (60, 75)),
    ("OS detection", (75, 78)),
    ("NSE", (78, 99)),
]

PHASE_LABELS = {
    "Ping Scan": "Обнаружение хостов",
    "Parallel DNS": "Разрешение имён",
    "SYN Stealth Scan": "Сканирование портов TCP",
    "Connect Scan": "Сканирование портов TCP",
    "UDP Scan": "Сканирование портов UDP",
    "Service scan": "Определение сервисов",
    "OS detection": "Определение ОС",
    "NSE": "Скрипты NSE",
}


class NmapError(RuntimeError):
    pass


class NmapCancelled(NmapError):
    pass


class NmapTimeout(NmapError):
    pass


@dataclass
class NmapProcessResult:
    returncode: int
    stdout_tail: str
    stderr: str
    duration: float


def parse_progress_line(line: str) -> tuple[str, float] | None:
    """Возвращает (фаза, общий прогресс 0..100) для строки статистики nmap."""
    line = line.strip()
    m = _NSE_RE.match(line) or _PERCENT_RE.match(line)
    if not m:
        return None
    phase = m.groupdict().get("phase") or "NSE"
    pct = float(m.group("pct"))
    for name, (start, end) in PHASES:
        if phase.startswith(name):
            return name, start + (end - start) * min(pct, 100.0) / 100.0
    return phase, -1.0


def nmap_available(path: str = "nmap") -> bool:
    return shutil.which(path) is not None


def run_nmap(
    nmap_path: str,
    args: list[str],
    *,
    timeout_s: float,
    on_progress: Callable[[str, float], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> NmapProcessResult:
    exe = shutil.which(nmap_path)
    if not exe:
        raise NmapError(f"nmap не найден ({nmap_path}). Установите пакет nmap.")
    cmd = [exe, *args]
    log.info("Запуск nmap: %s", " ".join(cmd))
    started = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 — список аргументов, shell=False
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        start_new_session=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "HOME": os.environ.get("HOME", "/tmp")},
    )
    tail: list[str] = []
    stderr_chunks: list[str] = []
    best = 0.0

    def _read_stdout() -> None:
        nonlocal best
        assert proc.stdout is not None
        for line in proc.stdout:
            tail.append(line)
            if len(tail) > 200:
                del tail[:100]
            parsed = parse_progress_line(line)
            if parsed and on_progress:
                phase, pct = parsed
                if pct > best:
                    best = pct
                try:
                    on_progress(PHASE_LABELS.get(phase, phase), best)
                except Exception:  # noqa: BLE001
                    log.exception("Ошибка обработчика прогресса")

    def _read_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            if sum(len(c) for c in stderr_chunks) < 20000:
                stderr_chunks.append(line)

    readers = [threading.Thread(target=_read_stdout, daemon=True), threading.Thread(target=_read_stderr, daemon=True)]
    for t in readers:
        t.start()

    try:
        while True:
            try:
                proc.wait(timeout=1.0)
                break
            except subprocess.TimeoutExpired:
                pass
            if cancel_event is not None and cancel_event.is_set():
                _terminate(proc)
                raise NmapCancelled("Сканирование отменено")
            if time.monotonic() - started > timeout_s:
                _terminate(proc)
                raise NmapTimeout(f"Превышено время сканирования ({int(timeout_s // 60)} мин)")
    finally:
        for t in readers:
            t.join(timeout=5)

    return NmapProcessResult(
        returncode=proc.returncode,
        stdout_tail="".join(tail[-50:]),
        stderr="".join(stderr_chunks),
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
        proc.wait(timeout=5)
