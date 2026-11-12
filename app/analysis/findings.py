"""Формирование находок из результатов nmap."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from app.analysis.knowledge import SCRIPT_RULES, cve_recommendation, service_risk
from app.analysis.severity import severity_from_cvss
from app.scanner.nmap_parser import HostResult, PortResult, extract_vulns


@dataclass
class FindingData:
    asset: str
    asset_type: str
    category: str
    severity: str
    title: str
    description: str = ""
    recommendation: str = ""
    port: int | None = None
    protocol: str = ""
    cve: str = ""
    cvss: float | None = None
    evidence: str = ""
    key: str = ""

    @property
    def fingerprint(self) -> str:
        """Стабильный ключ находки для сравнения сканов."""
        loc = f"{self.port}/{self.protocol}" if self.port else "-"
        return f"{self.category}|{self.asset}|{loc}|{self.key or self.cve or self.title}"[:255]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


def _port_findings(ip: str, port: PortResult) -> list[FindingData]:
    out: list[FindingData] = []
    svc = port.service
    svc_desc = svc.name or "неизвестный сервис"
    if svc.label:
        svc_desc += f" ({svc.label})"
    risk = service_risk(port.protocol, port.port, svc.name)
    if risk:
        out.append(
            FindingData(
                asset=ip,
                asset_type="ip",
                category="port",
                severity=risk.severity,
                title=f"{risk.title} — {port.key}",
                description=f"Открыт порт {port.key}: {svc_desc}.",
                recommendation=risk.recommendation,
                port=port.port,
                protocol=port.protocol,
                evidence=svc.label,
                key="open",
            )
        )
    else:
        out.append(
            FindingData(
                asset=ip,
                asset_type="ip",
                category="port",
                severity="info",
                title=f"Открытый порт {port.key} — {svc.name or 'unknown'}",
                description=f"Порт {port.key} доступен из внешней сети: {svc_desc}.",
                recommendation="Убедитесь, что публикация сервиса необходима и согласована; лишние порты закройте.",
                port=port.port,
                protocol=port.protocol,
                evidence=svc.label,
                key="open",
            )
        )

    for vuln in extract_vulns(port.scripts):
        if vuln.source == "vulners" and not vuln.is_cve:
            continue  # ссылки на эксплойты учитываются в признаке is_exploit соответствующих CVE
        sev = severity_from_cvss(vuln.cvss) if vuln.cvss is not None else (
            "high" if vuln.state.upper().startswith("VULNERABLE") else "medium"
        )
        title_ref = vuln.id if vuln.is_cve else (vuln.title or vuln.source)
        product = svc.label or svc.name
        desc = vuln.title or f"Версия {product} подвержена уязвимости {vuln.id}."
        if vuln.description:
            desc += "\n" + vuln.description
        if vuln.is_exploit:
            desc += "\nДля уязвимости существует публичный эксплойт."
        out.append(
            FindingData(
                asset=ip,
                asset_type="ip",
                category="vuln",
                severity=sev,
                title=f"{title_ref} — {product or port.key}",
                description=desc,
                recommendation=cve_recommendation(svc.product, svc.version, vuln.id)
                if vuln.is_cve
                else "Устраните уязвимость согласно рекомендациям производителя; ограничьте доступ к сервису.",
                port=port.port,
                protocol=port.protocol,
                cve=vuln.id if vuln.is_cve else "",
                cvss=vuln.cvss,
                evidence=f"Источник: {vuln.source}" + (f", CPE: {vuln.cpe}" if vuln.cpe else ""),
                key=vuln.id,
            )
        )

    out.extend(_script_rule_findings(ip, port.scripts, port))
    return out


def _script_rule_findings(ip: str, scripts: list, port: PortResult | None) -> list[FindingData]:
    out: list[FindingData] = []
    for script in scripts:
        for sid, needle, sev, title, rec in SCRIPT_RULES:
            if script.id != sid:
                continue
            if needle is not None and needle.lower() not in script.output.lower():
                continue
            if not script.output.strip() or "ERROR" in script.output[:20]:
                continue
            out.append(
                FindingData(
                    asset=ip,
                    asset_type="ip",
                    category="vuln" if sev in ("critical", "high") else "port",
                    severity=sev,
                    title=title + (f" — {port.key}" if port else ""),
                    description=f"Результат скрипта nmap {sid}.",
                    recommendation=rec,
                    port=port.port if port else None,
                    protocol=port.protocol if port else "",
                    evidence=script.output.strip()[:2000],
                    key=f"nse:{sid}",
                )
            )
    return out


def findings_from_host(host: HostResult) -> list[FindingData]:
    out: list[FindingData] = []
    for port in host.open_ports:
        out.extend(_port_findings(host.ip, port))
    out.extend(_script_rule_findings(host.ip, host.host_scripts, None))
    for vuln in extract_vulns(host.host_scripts):
        out.append(
            FindingData(
                asset=host.ip,
                asset_type="ip",
                category="vuln",
                severity=severity_from_cvss(vuln.cvss) if vuln.cvss is not None else "high",
                title=f"{vuln.id if vuln.is_cve else vuln.title or vuln.source}",
                description=(vuln.title + "\n" + vuln.description).strip(),
                recommendation=cve_recommendation("", "", vuln.id) if vuln.is_cve else "Устраните уязвимость согласно рекомендациям производителя.",
                cve=vuln.id if vuln.is_cve else "",
                cvss=vuln.cvss,
                evidence=f"Источник: {vuln.source}",
                key=vuln.id,
            )
        )
    # одинаковые отпечатки внутри одного хоста объединяем, оставляя самый серьёзный
    uniq: dict[str, FindingData] = {}
    from app.analysis.severity import SEVERITY_RANK

    for f in out:
        prev = uniq.get(f.fingerprint)
        if prev is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[prev.severity]:
            uniq[f.fingerprint] = f
    return list(uniq.values())
