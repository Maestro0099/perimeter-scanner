"""Оркестрация сканирований: очередь, ограничение параллельности, этапы, сохранение."""

from __future__ import annotations

import ipaddress
import logging
import shlex
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.analysis.findings import FindingData, findings_from_host
from app.audit import audit
from app.config import get_settings
from app.db import new_session, session_scope
from app.models import Finding, Host, Port, Scan, ScanStatus, Target, TargetKind, utcnow
from app.scanner.nmap_parser import HostResult, NmapParseError, NmapRun, parse_nmap_xml
from app.scanner.nmap_profiles import PROFILES, NmapOptions, build_discovery_args, build_nmap_args, uses_two_phase
from app.scanner.nmap_runner import NmapCancelled, NmapError, NmapTimeout, run_nmap
from app.validation import ValidationError, parse_scope, validate_in_scope, validate_timing

log = logging.getLogger("scanner")


class ScanRequestError(ValueError):
    pass


# --------------------------------------------------------------------------- создание скана


def create_scan(
    db: Session,
    *,
    target_ids: list[int],
    profile: str,
    timing: int | None,
    username: str,
    ip: str = "",
    trigger: str = "manual",
    group_id: int | None = None,
    aggressive_confirmed: bool = False,
) -> Scan:
    prof = PROFILES.get(profile)
    if prof is None:
        raise ScanRequestError("Неизвестный профиль сканирования")
    if prof.manual_only and trigger != "manual":
        raise ScanRequestError(f"Профиль «{prof.title}» можно запускать только вручную")
    if prof.manual_only and not aggressive_confirmed:
        raise ScanRequestError(f"Для профиля «{prof.title}» требуется явное подтверждение")
    try:
        from app import app_settings

        timing_v = validate_timing(timing if timing is not None else app_settings.load(db).nmap_timing)
    except ValidationError as exc:
        raise ScanRequestError(str(exc)) from exc
    if not target_ids:
        raise ScanRequestError("Не выбрано ни одной цели")
    targets = list(db.scalars(select(Target).where(Target.id.in_(target_ids))))
    if len(targets) != len(set(target_ids)):
        raise ScanRequestError("Часть целей не найдена в утверждённом списке")
    not_approved = [t.value for t in targets if not t.approved]
    if not_approved:
        raise ScanRequestError("Цели не утверждены для сканирования: " + ", ".join(not_approved))

    scan = Scan(
        profile=profile,
        timing=timing_v,
        trigger=trigger,
        started_by=username,
        group_id=group_id,
        status=ScanStatus.QUEUED.value,
        targets=targets,
    )
    db.add(scan)
    db.commit()
    audit(
        db,
        "scan_start",
        f"Скан #{scan.id}, профиль «{prof.title}», -T{timing_v}, источник: "
        f"{'расписание' if trigger == 'schedule' else 'вручную'}; цели: " + ", ".join(t.value for t in targets),
        username=username,
        ip=ip,
    )
    scan_manager.submit(scan.id)
    return scan


# --------------------------------------------------------------------------- менеджер очереди


class ScanManager:
    """Очередь сканов. Число одновременно выполняющихся сканов ограничено настройкой
    max_parallel_scans (меняется в интерфейсе без перезапуска)."""

    POOL_SIZE = 16

    def __init__(self) -> None:
        self._executor: ThreadPoolExecutor | None = None
        self._cancel: dict[int, threading.Event] = {}
        self._lock = threading.Lock()
        self._slots = threading.Condition()
        self._running = 0

    def _limit(self) -> int:
        from app import app_settings

        try:
            return app_settings.load().max_parallel_scans
        except Exception:  # noqa: BLE001
            return get_settings().max_parallel_scans

    def _acquire(self, cancel: threading.Event) -> bool:
        with self._slots:
            while self._running >= self._limit():
                if cancel.is_set():
                    return False
                self._slots.wait(timeout=2.0)
            self._running += 1
            return True

    def _release(self) -> None:
        with self._slots:
            self._running -= 1
            self._slots.notify_all()

    def start(self) -> None:
        if self._executor is not None:
            return
        self._executor = ThreadPoolExecutor(max_workers=self.POOL_SIZE, thread_name_prefix="scan")
        with session_scope() as db:
            # сканы, прерванные перезапуском приложения
            db.execute(
                update(Scan)
                .where(Scan.status == ScanStatus.RUNNING.value)
                .values(status=ScanStatus.FAILED.value, error="Прервано перезапуском приложения", finished_at=utcnow())
            )
            queued = list(db.scalars(select(Scan.id).where(Scan.status == ScanStatus.QUEUED.value)))
        for scan_id in queued:
            self.submit(scan_id)

    def shutdown(self) -> None:
        with self._lock:
            for ev in self._cancel.values():
                ev.set()
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

    def submit(self, scan_id: int) -> None:
        if self._executor is None:
            self.start()
        assert self._executor is not None
        with self._lock:
            self._cancel[scan_id] = threading.Event()
        self._executor.submit(self._run_safe, scan_id)

    def cancel(self, scan_id: int) -> bool:
        with self._lock:
            ev = self._cancel.get(scan_id)
        if ev is not None:
            ev.set()
        with session_scope() as db:
            scan = db.get(Scan, scan_id)
            if scan and scan.status == ScanStatus.QUEUED.value:
                scan.status = ScanStatus.CANCELLED.value
                scan.finished_at = utcnow()
                scan.stage = "Отменён"
                return True
        return ev is not None

    def _run_safe(self, scan_id: int) -> None:
        with self._lock:
            cancel = self._cancel.setdefault(scan_id, threading.Event())
        if not self._acquire(cancel):
            with self._lock:
                self._cancel.pop(scan_id, None)
            return
        try:
            ScanJob(scan_id, cancel).run()
        except Exception:  # noqa: BLE001
            log.exception("Необработанная ошибка в скане #%s", scan_id)
            _finish(scan_id, ScanStatus.FAILED, "Внутренняя ошибка, подробности в журнале приложения")
        finally:
            self._release()
            with self._lock:
                self._cancel.pop(scan_id, None)
            try:
                from app.notify.dispatcher import notify_scan

                notify_scan(scan_id)
            except Exception:  # noqa: BLE001
                log.exception("Ошибка отправки уведомлений по скану #%s", scan_id)


scan_manager = ScanManager()


def _finish(scan_id: int, status: ScanStatus, error: str = "") -> None:
    with session_scope() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = status.value
        scan.error = error[:4000]
        scan.finished_at = utcnow()
        if status == ScanStatus.DONE:
            scan.progress = 100.0
            scan.stage = "Завершён"
        elif status == ScanStatus.CANCELLED:
            scan.stage = "Отменён"
        else:
            scan.stage = "Ошибка"


# --------------------------------------------------------------------------- выполнение


class ScanJob:
    """Один скан: nmap → проверки → сравнение → уведомления."""

    def __init__(self, scan_id: int, cancel: threading.Event) -> None:
        self.scan_id = scan_id
        self.cancel = cancel
        self.settings = get_settings()
        self._last_progress_write = 0.0
        self._commands: list[str] = []
        self._started = time.monotonic()
        self.workdir = self.settings.scans_dir / str(scan_id)

    # ---- прогресс
    def progress(self, stage: str, pct: float, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_progress_write < 2.0:
            return
        self._last_progress_write = now
        with session_scope() as db:
            db.execute(
                update(Scan).where(Scan.id == self.scan_id).values(stage=stage[:120], progress=round(min(pct, 99.0), 1))
            )

    def scaled(self, start: float, end: float) -> Callable[[str, float], None]:
        return lambda stage, pct: self.progress(stage, start + (end - start) * pct / 100.0)

    def check_cancel(self) -> None:
        if self.cancel.is_set():
            raise NmapCancelled("Сканирование отменено")

    # ---- основной сценарий
    def run(self) -> None:
        with session_scope() as db:
            scan = db.get(Scan, self.scan_id)
            if scan is None or scan.status != ScanStatus.QUEUED.value:
                return
            scan.status = ScanStatus.RUNNING.value
            scan.started_at = utcnow()
            scan.stage = "Подготовка"
            targets = self._validated_targets(db, scan)
            profile = scan.profile
            timing = scan.timing

        self.workdir.mkdir(parents=True, exist_ok=True)
        try:
            if not targets:
                raise ScanRequestError("Нет утверждённых целей для сканирования")
            hosts = self.run_nmap(targets, profile, timing, 0, 70)
            self.check_cancel()
            self.store_nmap(hosts, targets)
            self.progress("Проверки доменов, веба и TLS", 70, force=True)
            self.run_checks(targets, profile)
            self.check_cancel()
            self.progress("Сравнение с предыдущим сканом", 97, force=True)
            self.finalize()
        except NmapCancelled:
            _finish(self.scan_id, ScanStatus.CANCELLED, "Отменено пользователем")
            return
        except (NmapTimeout, NmapError, NmapParseError, ScanRequestError, ValidationError) as exc:
            log.warning("Скан #%s завершился с ошибкой: %s", self.scan_id, exc)
            _finish(self.scan_id, ScanStatus.FAILED, str(exc))
            return
        _finish(self.scan_id, ScanStatus.DONE)
        log.info("Скан #%s завершён", self.scan_id)

    def run_checks(self, targets: list[tuple[int, str, str]], profile: str) -> None:
        from app.checks.runner import ChecksRunner

        runner = ChecksRunner(self.scan_id, profile, self.cancel, self.scaled(70, 96))
        findings = runner.run(targets)
        with session_scope() as db:
            save_findings(db, self.scan_id, findings, domain_target_map(self.scan_id, targets, findings))

    def finalize(self) -> None:
        """Сравнение с предыдущими сканами и сводка."""
        from app.analysis.diff import compute_scan_changes

        with session_scope() as db:
            scan = db.get(Scan, self.scan_id)
            assert scan is not None
            changes = compute_scan_changes(db, scan)
            db.flush()
            counts: dict[str, int] = {}
            for f in scan.findings:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            scan.summary = {
                "hosts": len(scan.hosts),
                "open_ports": sum(len(h.ports) for h in scan.hosts),
                "findings": counts,
                "changes": len(changes),
            }
        self.changes_count = len(changes)

    def _validated_targets(self, db: Session, scan: Scan) -> list[tuple[int, str, str]]:
        """Повторная проверка целей непосредственно перед запуском."""
        scope = parse_scope(self.settings.allowed_scope)
        result: list[tuple[int, str, str]] = []
        for t in scan.targets:
            if not t.approved:
                continue
            try:
                v = validate_in_scope(t.value, scope, self.settings.max_cidr_hosts)
            except ValidationError as exc:
                log.warning("Цель %s пропущена: %s", t.value, exc)
                continue
            result.append((t.id, v.kind.value, v.value))
        return result

    # ---- nmap
    def _options(self, profile: str, timing: int, targets_file: Path, xml_out: Path, tcp_ports: str | None = None) -> NmapOptions:
        st = self.settings
        return NmapOptions(
            profile=profile,
            timing=timing,
            privileged=st.nmap_privileged,
            targets_file=targets_file,
            xml_out=xml_out,
            host_timeout_min=st.host_timeout_minutes,
            script_timeout_min=st.script_timeout_minutes,
            skip_host_discovery=st.nmap_skip_host_discovery,
            min_rate=st.nmap_min_rate,
            max_retries=st.nmap_max_retries,
            min_hostgroup=st.nmap_min_hostgroup,
            tcp_ports=tcp_ports,
        )

    def _exec(self, args: list[str], xml_out: Path, label: str, p0: float, p1: float) -> NmapRun:
        self._commands.append(shlex.join([self.settings.nmap_path, *args]))
        with session_scope() as db:
            db.execute(
                update(Scan).where(Scan.id == self.scan_id).values(nmap_command="\n".join(self._commands), stage=label)
            )
        remaining = self.settings.scan_timeout_minutes * 60 - (time.monotonic() - self._started)
        if remaining <= 0:
            raise NmapTimeout(f"Превышено время сканирования ({self.settings.scan_timeout_minutes} мин)")
        scale = self.scaled(p0, p1)
        result = run_nmap(
            self.settings.nmap_path,
            args,
            timeout_s=remaining,
            on_progress=lambda stage, pct: scale(f"{label}: {stage}", pct),
            cancel_event=self.cancel,
        )
        if not xml_out.exists():
            raise NmapError(f"nmap завершился с кодом {result.returncode}: {result.stderr.strip()[:1000]}")
        run = parse_nmap_xml(xml_out.read_bytes())
        if result.returncode != 0 and not run.hosts:
            raise NmapError(f"nmap завершился с кодом {result.returncode}: {result.stderr.strip()[:1000]}")
        if run.error:
            log.warning("nmap: %s", run.error)
        return run

    def run_nmap(self, targets: list[tuple[int, str, str]], profile: str, timing: int, p0: float, p1: float) -> list[HostResult]:
        """Быстрый профиль — один запуск. Полный/агрессивный — две фазы:
        1) быстрый поиск открытых TCP-портов по всем 65535 портам;
        2) глубокий анализ (версии, ОС, скрипты, UDP) только по найденным хостам и портам."""
        targets_file = self.workdir / "targets.txt"
        xml_out = self.workdir / "nmap.xml"
        targets_file.write_text("\n".join(v for _, _, v in targets) + "\n", encoding="utf-8")

        if not (self.settings.nmap_two_phase and uses_two_phase(profile)):
            run = self._exec(build_nmap_args(self._options(profile, timing, targets_file, xml_out)), xml_out, "nmap", p0, p1)
            return [h for h in run.hosts if h.status == "up"]

        mid = p0 + (p1 - p0) * 0.45
        disc_xml = self.workdir / "discovery.xml"
        disc = self._exec(
            build_discovery_args(self._options(profile, timing, targets_file, disc_xml)), disc_xml, "Фаза 1 — поиск портов", p0, mid
        )
        self.check_cancel()
        deep_targets, tcp_ports = plan_deep_scan(targets, disc.hosts, udp_all_hosts=self.settings.nmap_udp_all_hosts)
        has_udp = self.settings.nmap_privileged and PROFILES[profile].udp_top > 0
        if not deep_targets or (not tcp_ports and not has_udp):
            log.info("Скан #%s: открытых TCP-портов не найдено, глубокая фаза пропущена", self.scan_id)
            return []
        deep_file = self.workdir / "targets-deep.txt"
        deep_file.write_text("\n".join(deep_targets) + "\n", encoding="utf-8")
        run = self._exec(
            build_nmap_args(self._options(profile, timing, deep_file, xml_out, tcp_ports=tcp_ports)),
            xml_out,
            "Фаза 2 — сервисы, ОС, скрипты",
            mid,
            p1,
        )
        return [h for h in run.hosts if h.status == "up"]

    def store_nmap(self, hosts: list[HostResult], targets: list[tuple[int, str, str]]) -> None:
        with session_scope() as db:
            seen: set[str] = set()
            findings: list[FindingData] = []
            explicit = {v for _, kind, v in targets if kind == TargetKind.IP.value}
            domains = {v for _, kind, v in targets if kind == TargetKind.DOMAIN.value}
            for h in hosts:
                if h.ip in seen:
                    continue
                # При -Pn nmap считает «живым» каждый адрес подсети. Хосты без открытых портов
                # сохраняем, только если адрес или домен указан в целях явно.
                if not h.open_ports and h.ip not in explicit and not (domains & set(h.user_hostnames)):
                    continue
                seen.add(h.ip)
                os_match = h.best_os
                host = Host(
                    scan_id=self.scan_id,
                    target_id=match_target(h, targets),
                    ip=h.ip,
                    hostnames=h.hostnames,
                    status=h.status,
                    os_name=os_match.name if os_match else "",
                    os_accuracy=os_match.accuracy if os_match else 0,
                    host_scripts=[s.to_dict() for s in h.host_scripts],
                    extra=h.extra,
                )
                for p in h.ports:
                    if p.state != "open":
                        continue
                    host.ports.append(
                        Port(
                            protocol=p.protocol,
                            port=p.port,
                            state=p.state,
                            reason=p.reason[:32],
                            service=p.service.name,
                            product=p.service.product[:255],
                            version=p.service.version[:128],
                            extrainfo=p.service.extrainfo[:255],
                            tunnel=p.service.tunnel,
                            cpe=p.service.cpe,
                            scripts=[s.to_dict() for s in p.scripts],
                        )
                    )
                db.add(host)
                findings.extend(findings_from_host(h))
            save_findings(db, self.scan_id, findings, targets_by_asset(targets, hosts))


def plan_deep_scan(
    targets: list[tuple[int, str, str]], discovered: list[HostResult], *, udp_all_hosts: bool = False
) -> tuple[list[str], str]:
    """По результатам фазы 1 определяет, что сканировать глубоко.

    Возвращает (список целей, список TCP-портов через запятую). Явно указанные IP и домены
    включаются всегда; из подсетей — только адреса, на которых найдены открытые порты
    (либо подсеть целиком, если включён режим udp_all_hosts).
    """
    alive = {h.ip: h for h in discovered if h.open_ports}
    ports = sorted({p.port for h in alive.values() for p in h.open_ports if p.protocol == "tcp"})
    result: list[str] = []
    for _, kind, value in targets:
        if kind in (TargetKind.IP.value, TargetKind.DOMAIN.value) or udp_all_hosts:
            if value not in result:
                result.append(value)
    if not udp_all_hosts:
        nets = [ipaddress.ip_network(v, strict=False) for _, k, v in targets if k == TargetKind.CIDR.value]
        for ip in sorted(alive, key=lambda x: ipaddress.ip_address(x)):
            addr = ipaddress.ip_address(ip)
            if ip not in result and any(addr.version == n.version and addr in n for n in nets):
                result.append(ip)
    return result, ",".join(str(p) for p in ports)


def save_findings(db: Session, scan_id: int, findings: list[FindingData], target_map: dict[str, int | None]) -> None:
    seen: set[str] = set()
    for f in findings:
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        db.add(
            Finding(
                scan_id=scan_id,
                target_id=target_map.get(f.asset),
                asset=f.asset,
                asset_type=f.asset_type,
                category=f.category,
                severity=f.severity,
                title=f.title[:255],
                description=f.description,
                recommendation=f.recommendation,
                port=f.port,
                protocol=f.protocol,
                cve=f.cve,
                cvss=f.cvss,
                evidence=f.evidence,
                fingerprint=f.fingerprint,
            )
        )


def match_target(host: HostResult, targets: list[tuple[int, str, str]]) -> int | None:
    try:
        ip = ipaddress.ip_address(host.ip)
    except ValueError:
        return None
    for tid, kind, value in targets:
        if kind == TargetKind.IP.value and value == host.ip:
            return tid
    for tid, kind, value in targets:
        if kind == TargetKind.CIDR.value and ip in ipaddress.ip_network(value, strict=False):
            return tid
    for tid, kind, value in targets:
        if kind == TargetKind.DOMAIN.value and value in host.user_hostnames:
            return tid
    return None


def targets_by_asset(targets: list[tuple[int, str, str]], hosts: list[HostResult]) -> dict[str, int | None]:
    m: dict[str, int | None] = {value: tid for tid, kind, value in targets if kind != TargetKind.CIDR.value}
    for h in hosts:
        m.setdefault(h.ip, match_target(h, targets))
    return m


def domain_target_map(scan_id: int, targets: list[tuple[int, str, str]], findings: list[FindingData]) -> dict[str, int | None]:
    """Сопоставление активов проверок (IP, домены, поддомены) с целями скана."""
    from app.validation import is_subdomain_of

    result: dict[str, int | None] = {}
    domains = sorted(((tid, v) for tid, k, v in targets if k == TargetKind.DOMAIN.value), key=lambda x: -len(x[1]))
    with session_scope() as db:
        ip_map = {h.ip: h.target_id for h in db.scalars(select(Host).where(Host.scan_id == scan_id, Host.ip.in_({f.asset for f in findings})))}
    for f in findings:
        if f.asset in result:
            continue
        if f.asset_type == "domain":
            result[f.asset] = next((tid for tid, v in domains if is_subdomain_of(f.asset, v)), None)
        else:
            result[f.asset] = ip_map.get(f.asset)
    return result


def scan_xml_path(scan_id: int) -> Path:
    return get_settings().scans_dir / str(scan_id) / "nmap.xml"


def active_scans(db: Session) -> list[Scan]:
    return list(
        db.scalars(
            select(Scan)
            .where(Scan.status.in_([ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]))
            .order_by(Scan.created_at)
        )
    )


__all__ = ["create_scan", "scan_manager", "ScanRequestError", "active_scans", "new_session"]
