"""Разбор XML-вывода nmap (-oX).

Используется defusedxml, чтобы исключить XXE и «XML-бомбы». Результат —
набор неизменяемых dataclass-объектов, не зависящих от базы данных: их удобно
тестировать и сравнивать.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException


class NmapParseError(ValueError):
    pass


@dataclass
class ScriptResult:
    id: str
    output: str
    data: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "output": self.output, "data": self.data}


@dataclass
class Service:
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    ostype: str = ""
    method: str = ""
    conf: int = 0
    cpe: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return " ".join(p for p in (self.product, self.version) if p)


@dataclass
class VulnRef:
    """Уязвимость, найденная скриптом NSE (vulners или скрипты категории vuln)."""

    id: str
    source: str
    cvss: float | None = None
    type: str = "cve"
    is_exploit: bool = False
    title: str = ""
    state: str = ""
    description: str = ""
    cpe: str = ""

    @property
    def is_cve(self) -> bool:
        return self.id.upper().startswith("CVE-")


@dataclass
class PortResult:
    protocol: str
    port: int
    state: str
    reason: str = ""
    service: Service = field(default_factory=Service)
    scripts: list[ScriptResult] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def key(self) -> str:
        return f"{self.port}/{self.protocol}"

    def script(self, script_id: str) -> ScriptResult | None:
        return next((s for s in self.scripts if s.id == script_id), None)


@dataclass
class OsMatch:
    name: str
    accuracy: int


@dataclass
class HostResult:
    ip: str
    addr_type: str = "ipv4"
    status: str = "up"
    hostnames: list[str] = field(default_factory=list)
    user_hostnames: list[str] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)
    os_matches: list[OsMatch] = field(default_factory=list)
    host_scripts: list[ScriptResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.is_open]

    @property
    def best_os(self) -> OsMatch | None:
        return max(self.os_matches, key=lambda m: m.accuracy) if self.os_matches else None


@dataclass
class NmapRun:
    args: str = ""
    version: str = ""
    start: int = 0
    hosts: list[HostResult] = field(default_factory=list)
    exit_status: str = ""
    error: str = ""
    elapsed: float = 0.0
    complete: bool = True


# --------------------------------------------------------------------------- разбор


def _parse_script_node(node: Element) -> Any:
    """Преобразует вложенные <table>/<elem> в dict/list."""
    children = list(node)
    if not children:
        return None
    keyed = all(c.get("key") is not None for c in children)
    if keyed:
        result: dict[str, Any] = {}
        for c in children:
            key = c.get("key", "")
            value = (c.text or "") if c.tag == "elem" else _parse_script_node(c)
            if key in result:  # повторяющиеся ключи — собираем в список
                prev = result[key]
                result[key] = prev + [value] if isinstance(prev, list) else [prev, value]
            else:
                result[key] = value
        return result
    items: list[Any] = []
    for c in children:
        value = (c.text or "") if c.tag == "elem" else _parse_script_node(c)
        if c.get("key") is not None:
            value = {c.get("key"): value}
        items.append(value)
    return items


def _parse_script(node: Element) -> ScriptResult:
    return ScriptResult(id=node.get("id", ""), output=node.get("output", ""), data=_parse_script_node(node))


def _parse_port(node: Element) -> PortResult:
    state_el = node.find("state")
    svc_el = node.find("service")
    service = Service()
    if svc_el is not None:
        service = Service(
            name=svc_el.get("name", ""),
            product=svc_el.get("product", ""),
            version=svc_el.get("version", ""),
            extrainfo=svc_el.get("extrainfo", ""),
            tunnel=svc_el.get("tunnel", ""),
            ostype=svc_el.get("ostype", ""),
            method=svc_el.get("method", ""),
            conf=_int(svc_el.get("conf")),
            cpe=[c.text or "" for c in svc_el.findall("cpe") if c.text],
        )
    return PortResult(
        protocol=node.get("protocol", "tcp"),
        port=_int(node.get("portid")),
        state=state_el.get("state", "unknown") if state_el is not None else "unknown",
        reason=state_el.get("reason", "") if state_el is not None else "",
        service=service,
        scripts=[_parse_script(s) for s in node.findall("script")],
    )


def _parse_host(node: Element) -> HostResult | None:
    ip = ""
    addr_type = "ipv4"
    for a in node.findall("address"):
        if a.get("addrtype") in ("ipv4", "ipv6"):
            ip = a.get("addr", "")
            addr_type = a.get("addrtype", "ipv4")
            break
    if not ip:
        return None
    status_el = node.find("status")
    hostnames: list[str] = []
    user_hostnames: list[str] = []
    for h in node.findall("hostnames/hostname"):
        name = (h.get("name") or "").lower()
        if not name:
            continue
        if name not in hostnames:
            hostnames.append(name)
        if h.get("type") == "user" and name not in user_hostnames:
            user_hostnames.append(name)
    return HostResult(
        ip=ip,
        addr_type=addr_type,
        status=status_el.get("state", "unknown") if status_el is not None else "unknown",
        hostnames=hostnames,
        user_hostnames=user_hostnames,
        ports=[_parse_port(p) for p in node.findall("ports/port")],
        os_matches=[
            OsMatch(name=m.get("name", ""), accuracy=_int(m.get("accuracy"))) for m in node.findall("os/osmatch")
        ],
        host_scripts=[_parse_script(s) for s in node.findall("hostscript/script")],
    )


def _int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _repair_truncated(text: str) -> str | None:
    """Если nmap был прерван, XML обрывается. Отрезаем до последнего полного хоста."""
    idx = text.rfind("</host>")
    head = text.find("<nmaprun")
    if head == -1:
        return None
    if idx == -1:
        end = text.find(">", head)
        return text[: end + 1] + "</nmaprun>" if end != -1 else None
    return text[: idx + len("</host>")] + "</nmaprun>"


def parse_nmap_xml(data: str | bytes) -> NmapRun:
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    if not text.strip():
        raise NmapParseError("Пустой вывод nmap")
    complete = True
    try:
        root = SafeET.fromstring(text)
    except DefusedXmlException as exc:
        raise NmapParseError(f"Небезопасный XML: {exc}") from exc
    except SafeET.ParseError:
        repaired = _repair_truncated(text)
        if repaired is None:
            raise NmapParseError("Некорректный XML nmap") from None
        try:
            root = SafeET.fromstring(repaired)
        except SafeET.ParseError as exc:
            raise NmapParseError(f"Некорректный XML nmap: {exc}") from exc
        complete = False
    if root.tag != "nmaprun":
        raise NmapParseError("Это не вывод nmap (ожидался корневой элемент <nmaprun>)")

    run = NmapRun(
        args=root.get("args", ""),
        version=root.get("version", ""),
        start=_int(root.get("start")),
        complete=complete,
    )
    for h in root.findall("host"):
        host = _parse_host(h)
        if host is not None:
            run.hosts.append(host)
    finished = root.find("runstats/finished")
    if finished is not None:
        run.exit_status = finished.get("exit", "")
        run.error = finished.get("errormsg", "")
        try:
            run.elapsed = float(finished.get("elapsed", "0"))
        except ValueError:
            run.elapsed = 0.0
    else:
        run.complete = False
    return run


# --------------------------------------------------------------------------- уязвимости

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_VULN_STATES = ("VULNERABLE", "LIKELY VULNERABLE", "VULNERABLE (Exploitable)", "VULNERABLE (DoS)")


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _vulners_refs(script: ScriptResult) -> list[VulnRef]:
    refs: list[VulnRef] = []
    data = script.data
    if not isinstance(data, dict):
        return refs
    for cpe, entries in data.items():
        if isinstance(entries, dict):
            entries = [entries]
        if not isinstance(entries, list):
            continue
        for e in entries:
            if not isinstance(e, dict) or "id" not in e:
                continue
            refs.append(
                VulnRef(
                    id=str(e.get("id", "")),
                    source="vulners",
                    cvss=_to_float(e.get("cvss")),
                    type=str(e.get("type", "")),
                    is_exploit=str(e.get("is_exploit", "false")).lower() == "true",
                    cpe=str(cpe),
                )
            )
    return refs


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(_flatten_text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(_flatten_text(v) for v in value.values())
    return str(value)


def _nse_vuln_refs(script: ScriptResult) -> list[VulnRef]:
    """Скрипты, использующие библиотеку vulns.lua: таблица с ключами title/state/ids/scores."""
    refs: list[VulnRef] = []
    data = script.data
    tables: list[tuple[str, dict[str, Any]]] = []
    if isinstance(data, dict):
        if "state" in data and "title" in data:
            tables.append((script.id, data))
        else:
            tables.extend((k, v) for k, v in data.items() if isinstance(v, dict) and "state" in v)
    for key, t in tables:
        state = str(t.get("state", "")).strip()
        if not any(state.upper().startswith(s) for s in ("VULNERABLE", "LIKELY VULNERABLE")):
            continue
        ids_text = _flatten_text(t.get("ids")) + " " + key
        cves = sorted({c.upper() for c in _CVE_RE.findall(ids_text)})
        scores = t.get("scores")
        cvss = None
        if isinstance(scores, dict):
            cvss = _to_float(scores.get("CVSSv3") or scores.get("CVSSv2") or scores.get("CVSS"))
        elif isinstance(scores, list):
            cvss = next((_to_float(_flatten_text(s)) for s in scores if _to_float(_flatten_text(s))), None)
        title = str(t.get("title", key))
        desc = _flatten_text(t.get("description"))[:2000]
        for vid in cves or [f"NSE:{script.id}"]:
            refs.append(
                VulnRef(
                    id=vid,
                    source=script.id,
                    cvss=cvss,
                    type="cve" if vid.startswith("CVE-") else "nse",
                    title=title,
                    state=state,
                    description=desc.strip(),
                )
            )
    if not refs and not tables and "State: VULNERABLE" in script.output:
        # Запасной вариант для скриптов без структурированного вывода
        first = script.output.strip().splitlines()
        title = next((ln.strip() for ln in first[1:3] if ln.strip()), script.id) if first else script.id
        cves = sorted({c.upper() for c in _CVE_RE.findall(script.output)})
        for vid in cves or [f"NSE:{script.id}"]:
            refs.append(
                VulnRef(id=vid, source=script.id, type="cve" if vid.startswith("CVE-") else "nse", title=title, state="VULNERABLE")
            )
    return refs


def extract_vulns(scripts: list[ScriptResult]) -> list[VulnRef]:
    """Собирает уязвимости из вывода скриптов порта или хоста, без дубликатов."""
    seen: dict[str, VulnRef] = {}
    for s in scripts:
        refs = _vulners_refs(s) if s.id == "vulners" else _nse_vuln_refs(s)
        for r in refs:
            existing = seen.get(r.id)
            if existing is None:
                seen[r.id] = r
            else:
                # сохраняем максимальную оценку и признак эксплойта
                if r.cvss is not None and (existing.cvss is None or r.cvss > existing.cvss):
                    existing.cvss = r.cvss
                existing.is_exploit = existing.is_exploit or r.is_exploit
                if not existing.title and r.title:
                    existing.title = r.title
    return list(seen.values())
