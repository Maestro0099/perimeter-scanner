"""DNS-проверки домена: записи, SPF/DKIM/DMARC, zone transfer."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from app.analysis.findings import FindingData

log = logging.getLogger("checks.dns")

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
DKIM_SELECTORS = (
    "default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "s1", "s2", "smtp",
    "mx", "email", "key1", "key2", "mailru", "yandex", "dkim1", "sig1", "everlytickey1", "mandrill", "zoho",
)


def make_resolver(timeout: float) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout * 2
    return r


def query(resolver: dns.resolver.Resolver, name: str, rtype: str) -> list[str]:
    try:
        answer = resolver.resolve(name, rtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        log.debug("DNS %s %s: %s", name, rtype, exc)
        return []
    out: list[str] = []
    for rr in answer:
        if rtype == "TXT":
            out.append(b"".join(rr.strings).decode("utf-8", errors="replace"))
        elif rtype == "MX":
            out.append(f"{rr.preference} {rr.exchange.to_text().rstrip('.')}")
        else:
            out.append(rr.to_text().rstrip("."))
    return out


def resolve_records(domain: str, resolver: dns.resolver.Resolver) -> dict[str, list[str]]:
    return {rtype: query(resolver, domain, rtype) for rtype in RECORD_TYPES}


def resolve_ips(name: str, resolver: dns.resolver.Resolver) -> list[str]:
    return query(resolver, name, "A") + query(resolver, name, "AAAA")


# --------------------------------------------------------------------------- SPF / DMARC / DKIM


def analyze_spf(txt_records: list[str]) -> dict[str, Any]:
    spf = [t for t in txt_records if t.lower().startswith("v=spf1")]
    result: dict[str, Any] = {"record": spf[0] if spf else "", "count": len(spf), "all": "", "lookups": 0, "issues": []}
    if not spf:
        result["issues"].append("SPF-запись отсутствует")
        return result
    if len(spf) > 1:
        result["issues"].append("Несколько SPF-записей — SPF недействителен (permerror)")
    rec = spf[0]
    m = re.search(r"(?:^|\s)([+\-~?]?)all\b", rec, re.IGNORECASE)
    qualifier = (m.group(1) or "+") if m else ""
    result["all"] = qualifier + "all" if m else ""
    if not m and "redirect=" not in rec.lower():
        result["issues"].append("В SPF нет механизма all — политика для остальных отправителей не определена")
    elif qualifier == "+":
        result["issues"].append("SPF разрешает отправку с любых адресов (+all)")
    elif qualifier == "?":
        result["issues"].append("SPF с нейтральной политикой (?all) не защищает от подделки")
    result["lookups"] = len(re.findall(r"\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", rec, re.IGNORECASE))
    if result["lookups"] > 10:
        result["issues"].append("Более 10 DNS-запросов в SPF (permerror)")
    if re.search(r"\bptr\b", rec, re.IGNORECASE):
        result["issues"].append("Используется устаревший механизм ptr")
    return result


def analyze_dmarc(txt_records: list[str]) -> dict[str, Any]:
    recs = [t for t in txt_records if t.lower().startswith("v=dmarc1")]
    result: dict[str, Any] = {"record": recs[0] if recs else "", "policy": "", "pct": 100, "rua": "", "issues": []}
    if not recs:
        result["issues"].append("DMARC-запись отсутствует")
        return result
    tags = dict(
        (k.strip().lower(), v.strip()) for k, _, v in (p.partition("=") for p in recs[0].split(";")) if k.strip()
    )
    result["policy"] = tags.get("p", "").lower()
    result["rua"] = tags.get("rua", "")
    try:
        result["pct"] = int(tags.get("pct", "100"))
    except ValueError:
        result["pct"] = 100
    if result["policy"] not in ("none", "quarantine", "reject"):
        result["issues"].append("Некорректная политика DMARC (тег p)")
    elif result["policy"] == "none":
        result["issues"].append("Политика DMARC p=none — письма с подделанным отправителем не блокируются")
    if result["pct"] < 100:
        result["issues"].append(f"DMARC применяется только к {result['pct']}% писем")
    if not result["rua"]:
        result["issues"].append("Не указан адрес для агрегированных отчётов (rua)")
    return result


def find_dkim(domain: str, resolver: dns.resolver.Resolver) -> dict[str, str]:
    found: dict[str, str] = {}
    for sel in DKIM_SELECTORS:
        recs = query(resolver, f"{sel}._domainkey.{domain}", "TXT")
        for r in recs:
            if "p=" in r or "v=dkim1" in r.lower():
                found[sel] = r[:500]
                break
    return found


# --------------------------------------------------------------------------- zone transfer


def check_zone_transfer(domain: str, nameservers: list[str], resolver: dns.resolver.Resolver, timeout: float) -> dict[str, Any]:
    """Одна попытка AXFR к каждому авторитетному серверу (проверка конфигурации)."""
    results: dict[str, Any] = {}
    for ns in nameservers[:10]:
        ips = query(resolver, ns, "A")
        if not ips:
            results[ns] = {"allowed": False, "error": "не удалось определить адрес"}
            continue
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ips[0], domain, timeout=timeout, lifetime=timeout * 3))
            names = sorted(str(n) for n in zone.nodes.keys())
            results[ns] = {"allowed": True, "records": len(names), "sample": names[:20]}
        except Exception as exc:  # noqa: BLE001 — отказ в передаче зоны ожидаем
            results[ns] = {"allowed": False, "error": type(exc).__name__}
    return results


# --------------------------------------------------------------------------- итог


@dataclass
class DomainCheckResult:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    email: dict[str, Any] = field(default_factory=dict)
    axfr: dict[str, Any] = field(default_factory=dict)
    findings: list[FindingData] = field(default_factory=list)


def _f(domain: str, category: str, severity: str, title: str, desc: str, rec: str, key: str, evidence: str = "") -> FindingData:
    return FindingData(
        asset=domain, asset_type="domain", category=category, severity=severity, title=title,
        description=desc, recommendation=rec, evidence=evidence, key=key,
    )


def check_domain_dns(domain: str, timeout: float) -> DomainCheckResult:
    resolver = make_resolver(timeout)
    res = DomainCheckResult(domain)
    res.records = resolve_records(domain, resolver)
    txt = res.records.get("TXT", [])
    dmarc_txt = query(resolver, f"_dmarc.{domain}", "TXT")
    spf = analyze_spf(txt)
    dmarc = analyze_dmarc(dmarc_txt)
    dkim = find_dkim(domain, resolver) if res.records.get("MX") else {}
    res.email = {"spf": spf, "dmarc": dmarc, "dkim": {"selectors": dkim, "checked": list(DKIM_SELECTORS)}}
    res.axfr = check_zone_transfer(domain, res.records.get("NS", []), resolver, timeout)

    has_mail = bool(res.records.get("MX"))
    if not any(res.records.get(t) for t in ("A", "AAAA", "CNAME", "MX", "NS")):
        res.findings.append(_f(domain, "dns", "info", "Домен не разрешается", "Для домена не найдено DNS-записей.",
                               "Проверьте актуальность домена в списке целей.", "nxdomain"))
        return res

    # Zone transfer
    open_axfr = [ns for ns, r in res.axfr.items() if r.get("allowed")]
    if open_axfr:
        res.findings.append(_f(
            domain, "dns", "high", "Разрешена передача зоны (AXFR)",
            "Серверы отдают полное содержимое DNS-зоны любому клиенту: " + ", ".join(open_axfr),
            "Ограничьте AXFR списком вторичных серверов (allow-transfer) или используйте TSIG.",
            "axfr", evidence="\n".join(f"{ns}: {res.axfr[ns].get('records')} записей" for ns in open_axfr),
        ))

    # SPF
    if not spf["record"]:
        res.findings.append(_f(domain, "mail", "medium" if has_mail else "low", "SPF не настроен",
                               "Отсутствует SPF-запись: злоумышленник может отправлять письма от имени домена.",
                               "Добавьте TXT-запись SPF, например: v=spf1 mx include:<почтовый провайдер> -all. "
                               "Для доменов без почты: v=spf1 -all.", "spf-missing"))
    else:
        sev_map = {"+all": "high", "?all": "medium"}
        for issue in spf["issues"]:
            sev = "medium" if "Несколько" in issue or "10 DNS" in issue else sev_map.get(spf["all"], "low")
            res.findings.append(_f(domain, "mail", sev, f"SPF: {issue}", f"Текущая запись: {spf['record']}",
                                   "Исправьте SPF-запись; рекомендуется завершать её механизмом -all или ~all.",
                                   "spf:" + issue[:40], evidence=spf["record"]))
    # DMARC
    if not dmarc["record"]:
        res.findings.append(_f(domain, "mail", "medium" if has_mail else "low", "DMARC не настроен",
                               "Без DMARC получатели не знают, как обрабатывать письма с поддельным отправителем.",
                               "Добавьте TXT-запись _dmarc, начните с p=none и rua=mailto:..., затем перейдите к quarantine/reject.",
                               "dmarc-missing"))
    else:
        for issue in dmarc["issues"]:
            sev = "medium" if "p=none" in issue else "low"
            res.findings.append(_f(domain, "mail", sev, f"DMARC: {issue}", f"Текущая запись: {dmarc['record']}",
                                   "Ужесточите политику DMARC до p=quarantine или p=reject после анализа отчётов.",
                                   "dmarc:" + issue[:40], evidence=dmarc["record"]))
    # DKIM
    if has_mail and not dkim:
        res.findings.append(_f(domain, "mail", "low", "DKIM: подписи не найдены по распространённым селекторам",
                               "Проверены селекторы: " + ", ".join(DKIM_SELECTORS[:10]) + " и др. Возможно, используется нестандартный селектор.",
                               "Настройте DKIM-подпись исходящей почты и опубликуйте открытый ключ в DNS.", "dkim-missing"))
    if not res.records.get("CAA") and (res.records.get("A") or res.records.get("AAAA")):
        res.findings.append(_f(domain, "dns", "info", "Нет CAA-записи",
                               "CAA ограничивает круг удостоверяющих центров, которые могут выпускать сертификаты для домена.",
                               "Добавьте CAA-запись, например: 0 issue \"letsencrypt.org\".", "caa-missing"))
    return res
