"""Профили сканирования nmap и построение списка аргументов.

Аргументы формируются ТОЛЬКО из констант этого модуля и проверенных значений
(скорость -T, пути к временным файлам). Цели передаются через файл -iL, а не
в командной строке, поэтому значение цели не может быть истолковано как опция.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.validation import ValidationError, validate_timing

# Категории, которые не используются никогда, ни в одном профиле.
FORBIDDEN_CATEGORIES = ("brute", "dos", "exploit")
# Дополнительно исключаем широковещательные скрипты (они работают в локальной
# сети сканера, а не по целям) и скрипты, отправляющие данные внешним сервисам
# (кроме vulners, который нужен для сопоставления с CVE).
EXCLUDED_ALWAYS = (*FORBIDDEN_CATEGORIES, "broadcast", "external")


@dataclass(frozen=True)
class Profile:
    key: str
    title: str
    description: str
    categories: tuple[str, ...]
    exclude: tuple[str, ...]
    all_tcp: bool
    udp_top: int
    tcp_top: int
    os_detect: bool
    manual_only: bool = False
    warning: str = ""
    extra_scripts: tuple[str, ...] = ()

    def script_expression(self) -> str:
        if not self.categories:
            return ""
        cats = " or ".join(self.categories)
        excl = " or ".join(self.exclude)
        expr = f"({cats}) and not ({excl})"
        if self.extra_scripts:
            expr = f"({expr}) or " + " or ".join(self.extra_scripts)
        return expr


PROFILES: dict[str, Profile] = {
    "quick": Profile(
        key="quick",
        title="Быстрый",
        description="Топ-1000 портов TCP, определение сервисов и версий (-sV).",
        categories=(),
        exclude=EXCLUDED_ALWAYS,
        all_tcp=False,
        udp_top=0,
        tcp_top=1000,
        os_detect=False,
    ),
    "full": Profile(
        key="full",
        title="Полный",
        description=(
            "Все порты TCP (-p-), топ-100 UDP, -sV, -O, скрипты default, safe, discovery, version, vuln "
            "и vulners (сопоставление с CVE и CVSS), перечисление шифров TLS."
        ),
        categories=("default", "safe", "discovery", "version", "vuln"),
        exclude=(*EXCLUDED_ALWAYS, "intrusive"),
        all_tcp=True,
        udp_top=100,
        tcp_top=0,
        os_detect=True,
        # ssl-enum-ciphers входит в discovery, но помечен intrusive (много TLS-рукопожатий);
        # включаем явно — это основной источник данных о шифрах и протоколах.
        extra_scripts=("vulners", "ssl-enum-ciphers"),
    ),
    "aggressive": Profile(
        key="aggressive",
        title="Агрессивный",
        description="Как «Полный», плюс категории auth и intrusive. Только ручной запуск с подтверждением.",
        categories=("default", "safe", "discovery", "version", "vuln", "auth", "intrusive"),
        exclude=EXCLUDED_ALWAYS,
        all_tcp=True,
        udp_top=100,
        tcp_top=0,
        os_detect=True,
        manual_only=True,
        warning=(
            "Агрессивный профиль запускает скрипты категорий auth и intrusive. Они могут создавать "
            "заметную нагрузку, вызывать срабатывание СЗИ, блокировки учётных записей и сбои "
            "нестабильных сервисов. Запускайте только по согласованию с владельцами систем и в "
            "согласованное окно."
        ),
        extra_scripts=("vulners", "ssl-enum-ciphers"),
    ),
}

SCHEDULABLE_PROFILES = tuple(k for k, p in PROFILES.items() if not p.manual_only)

# Запасной список топ-100 UDP-портов (если не найден файл nmap-services).
_FALLBACK_UDP_TOP100 = (
    "7,9,17,19,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,427,443,445,497,500,514-515,518,520,593,"
    "623,626,631,996-999,1022-1023,1025-1030,1433-1434,1645-1646,1701,1718-1719,1812-1813,1900,2000,2048-2049,"
    "2222-2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,20031,30718,31337,32768-32769,"
    "32771,32815,33281,49152-49154,49156,49181-49182,49185-49186,49188,49190-49194,49200-49201,65024"
)

NMAP_SERVICES_PATHS = (
    Path("/usr/share/nmap/nmap-services"),
    Path("/usr/local/share/nmap/nmap-services"),
)


def top_ports(protocol: str, count: int) -> str:
    """Список самых частых портов из nmap-services (как это делает --top-ports)."""
    for path in NMAP_SERVICES_PATHS:
        if not path.is_file():
            continue
        entries: list[tuple[float, int]] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3 or "/" not in parts[1]:
                continue
            port_s, proto = parts[1].split("/", 1)
            if proto != protocol:
                continue
            try:
                entries.append((float(parts[2]), int(port_s)))
            except ValueError:
                continue
        if entries:
            entries.sort(key=lambda e: (-e[0], e[1]))
            return ",".join(str(p) for _, p in sorted(entries[:count], key=lambda e: e[1]))
    if protocol == "udp":
        expanded: list[str] = []
        for part in _FALLBACK_UDP_TOP100.split(","):
            lo, _, hi = part.partition("-")
            expanded.extend(str(p) for p in range(int(lo), int(hi or lo) + 1))
        return ",".join(expanded)
    raise ValidationError("Не найден файл nmap-services")


@dataclass(frozen=True)
class NmapOptions:
    profile: str
    timing: int
    privileged: bool
    targets_file: Path
    xml_out: Path
    host_timeout_min: int = 60
    script_timeout_min: int = 5
    skip_host_discovery: bool = True
    # производительность
    min_rate: int = 0
    max_retries: int = 2
    min_hostgroup: int = 64
    # список TCP-портов для глубокой фазы (результат фазы обнаружения); None — по профилю
    tcp_ports: str | None = None


def _perf_args(opts: NmapOptions, syn: bool) -> list[str]:
    args = [f"-T{validate_timing(opts.timing)}", "--max-retries", str(int(opts.max_retries))]
    if opts.min_rate > 0:
        args += ["--min-rate", str(int(opts.min_rate))]
    if opts.min_hostgroup > 1:
        args += ["--min-hostgroup", str(int(opts.min_hostgroup))]
    if syn:
        # не ждать при ограничении RST на стороне цели: закрытые порты нам не важны
        args.append("--defeat-rst-ratelimit")
    return args


def _output_args(opts: NmapOptions) -> list[str]:
    return [
        "--resolve-all",
        "--host-timeout",
        f"{int(opts.host_timeout_min)}m",
        "--stats-every",
        "5s",
        "--noninteractive",
        "-oX",
        str(opts.xml_out),
        "-iL",
        str(opts.targets_file),
    ]


def uses_two_phase(profile: str) -> bool:
    prof = PROFILES.get(profile)
    return bool(prof and prof.all_tcp)


def build_discovery_args(opts: NmapOptions) -> list[str]:
    """Фаза 1: максимально быстрый поиск открытых TCP-портов (все 65535) без анализа сервисов."""
    if PROFILES.get(opts.profile) is None:
        raise ValidationError(f"Неизвестный профиль: {opts.profile!r}")
    args = ["--privileged", "-sS"] if opts.privileged else ["--unprivileged", "-sT"]
    args += ["-p", "1-65535", "--open", "-n"]
    if opts.skip_host_discovery:
        args.append("-Pn")
    args += _perf_args(opts, syn=opts.privileged)
    args += _output_args(opts)
    return args


def _valid_port_list(value: str) -> bool:
    return bool(value) and all(part.isdigit() and 0 < int(part) < 65536 for part in value.split(","))


def build_nmap_args(opts: NmapOptions) -> list[str]:
    """Основной (или глубокий) запуск: сервисы, версии, ОС, скрипты NSE."""
    profile = PROFILES.get(opts.profile)
    if profile is None:
        raise ValidationError(f"Неизвестный профиль: {opts.profile!r}")
    if opts.tcp_ports is not None and opts.tcp_ports != "" and not _valid_port_list(opts.tcp_ports):
        raise ValidationError("Некорректный список портов")
    udp = bool(opts.privileged and profile.udp_top)
    deep = profile.all_tcp

    args: list[str] = []
    if opts.privileged:
        args += ["--privileged"]
        if opts.tcp_ports != "":
            args.append("-sS")
        if udp:
            args.append("-sU")
    else:
        args += ["--unprivileged", "-sT"]

    if deep:
        parts: list[str] = []
        if opts.tcp_ports is None:
            parts.append("T:1-65535")
        elif opts.tcp_ports:
            parts.append("T:" + opts.tcp_ports)
        if udp:
            parts.append("U:" + top_ports("udp", profile.udp_top))
        if not parts:
            raise ValidationError("Нет портов для сканирования")
        args += ["-p", ",".join(parts)]
    else:
        args += ["--top-ports", str(profile.tcp_top)]

    # Глубокая фаза работает только по найденным портам, поэтому можно позволить
    # максимальную интенсивность определения версий.
    args += ["-sV", "--version-all"] if deep else ["-sV", "--version-intensity", "7"]
    if profile.os_detect and opts.privileged:
        args += ["-O", "--osscan-guess", "--traceroute"]

    expr = profile.script_expression()
    if expr:
        args += [
            "--script",
            expr,
            "--script-timeout",
            f"{int(opts.script_timeout_min)}m",
            "--script-args",
            "vulners.mincvss=0.1",
        ]

    if opts.skip_host_discovery:
        args.append("-Pn")
    args += _perf_args(opts, syn=opts.privileged and opts.tcp_ports != "")
    args += _output_args(opts)
    _assert_safe(args)
    return args


def _assert_safe(args: list[str]) -> None:
    """Последняя линия обороны: запрещённые категории не должны попасть в аргументы."""
    for i, a in enumerate(args):
        if a == "--script":
            expr = args[i + 1]
            positive = expr.split(" and not ")[0]
            for cat in FORBIDDEN_CATEGORIES:
                if cat in positive.replace("(", " ").replace(")", " ").split():
                    raise ValidationError(f"Категория скриптов «{cat}» запрещена")
                if cat not in expr:
                    raise ValidationError(f"Категория «{cat}» должна быть явно исключена")
