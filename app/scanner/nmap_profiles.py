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
            "и vulners (сопоставление с CVE и CVSS)."
        ),
        categories=("default", "safe", "discovery", "version", "vuln"),
        exclude=(*EXCLUDED_ALWAYS, "intrusive"),
        all_tcp=True,
        udp_top=100,
        tcp_top=0,
        os_detect=True,
        extra_scripts=("vulners",),
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
        extra_scripts=("vulners",),
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


def build_nmap_args(opts: NmapOptions) -> list[str]:
    """Возвращает список аргументов nmap (без имени исполняемого файла)."""
    profile = PROFILES.get(opts.profile)
    if profile is None:
        raise ValidationError(f"Неизвестный профиль: {opts.profile!r}")
    timing = validate_timing(opts.timing)

    args: list[str] = []
    if opts.privileged:
        args += ["--privileged", "-sS"]
        if profile.udp_top:
            args.append("-sU")
    else:
        args += ["--unprivileged", "-sT"]

    if profile.all_tcp:
        ports = "T:1-65535"
        if opts.privileged and profile.udp_top:
            ports += ",U:" + top_ports("udp", profile.udp_top)
        args += ["-p", ports]
    else:
        args += ["--top-ports", str(profile.tcp_top)]

    args += ["-sV", "--version-intensity", "7"]
    if profile.os_detect and opts.privileged:
        args += ["-O", "--osscan-limit"]

    expr = profile.script_expression()
    if expr:
        args += ["--script", expr, "--script-timeout", f"{int(opts.script_timeout_min)}m"]

    if opts.skip_host_discovery:
        args.append("-Pn")
    args += [
        f"-T{timing}",
        "--resolve-all",
        "--max-retries",
        "3",
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
