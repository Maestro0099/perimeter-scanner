"""Запуск проверок доменов, веба и TLS в рамках скана и сохранение результатов."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from sqlalchemy import select

from app.analysis.findings import FindingData
from app.checks.dns_checks import check_domain_dns, make_resolver, resolve_ips
from app.checks.subdomains import discover_subdomains
from app.checks.tls_checks import TlsCheckResult, check_tls
from app.checks.web_checks import WebCheckResult, check_web
from app.checks.whois_client import registrable_domain, whois_lookup
from app.config import get_settings
from app.db import session_scope
from app.models import DomainResult, Host, TargetKind, TlsResult, WebResult

log = logging.getLogger("checks")

WEB_PORTS = {80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443}
HTTPS_PORTS = {443, 8443, 9443}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443, 9443}
TLS_SERVICES = {"https", "ssl", "imaps", "pop3s", "smtps", "ldaps", "https-alt"}


@dataclass(frozen=True)
class Endpoint:
    kind: str  # web | tls
    asset: str
    asset_type: str
    host: str
    port: int
    url: str = ""
    sni: str | None = None


def endpoints_from_hosts(hosts: list[Host]) -> list[Endpoint]:
    eps: list[Endpoint] = []
    for h in hosts:
        for p in h.ports:
            if p.protocol != "tcp":
                continue
            svc = (p.service or "").lower()
            is_tls = p.tunnel == "ssl" or svc in TLS_SERVICES or p.port in TLS_PORTS
            is_web = "http" in svc or p.port in WEB_PORTS
            host = f"[{h.ip}]" if ":" in h.ip else h.ip
            if is_web:
                scheme = "https" if (is_tls or p.port in HTTPS_PORTS) else "http"
                default = 443 if scheme == "https" else 80
                url = f"{scheme}://{host}" + ("" if p.port == default else f":{p.port}") + "/"
                eps.append(Endpoint("web", h.ip, "ip", h.ip, p.port, url))
            if is_tls:
                eps.append(Endpoint("tls", h.ip, "ip", h.ip, p.port))
    return eps


def endpoints_for_domain(name: str) -> list[Endpoint]:
    return [
        Endpoint("web", name, "domain", name, 80, f"http://{name}/"),
        Endpoint("web", name, "domain", name, 443, f"https://{name}/"),
        Endpoint("tls", name, "domain", name, 443, sni=name),
    ]


def whois_findings(domain: str, info: dict) -> list[FindingData]:
    days = info.get("days_left")
    if days is None:
        return []
    rec = "Продлите регистрацию домена и включите автопродление у регистратора."
    if days < 0:
        sev, title = "critical", "Срок регистрации домена истёк"
    elif days < 30:
        sev, title = "high", f"Регистрация домена истекает через {days} дн."
    elif days < 60:
        sev, title = "medium", f"Регистрация домена истекает через {days} дн."
    else:
        return []
    return [
        FindingData(
            asset=domain, asset_type="domain", category="whois", severity=sev, title=title,
            description=f"Дата окончания регистрации: {info.get('expires')}. Регистратор: {info.get('registrar') or '—'}.",
            recommendation=rec, key="whois-expiry",
        )
    ]


class ChecksRunner:
    def __init__(
        self,
        scan_id: int,
        profile: str,
        cancel: threading.Event,
        progress: Callable[[str, float], None],
    ) -> None:
        self.scan_id = scan_id
        self.profile = profile
        self.cancel = cancel
        self.progress = progress
        self.s = get_settings()
        self.findings: list[FindingData] = []

    def run(self, targets: list[tuple[int, str, str]]) -> list[FindingData]:
        domains = [(tid, v) for tid, kind, v in targets if kind == TargetKind.DOMAIN.value]
        extra_names: list[str] = []
        whois_cache: dict[str, dict] = {}
        for i, (tid, domain) in enumerate(domains):
            if self.cancel.is_set():
                return self.findings
            self.progress(f"Проверка домена {domain}", 100.0 * i / max(len(domains), 1) * 0.4)
            extra_names += self.check_domain(tid, domain, whois_cache)

        with session_scope() as db:
            hosts = list(db.scalars(select(Host).where(Host.scan_id == self.scan_id)))
            endpoints = endpoints_from_hosts(hosts)
        for _, domain in domains:
            endpoints += endpoints_for_domain(domain)
        if self.s.check_subdomains_web:
            for name in extra_names[: self.s.max_subdomains_web]:
                endpoints += endpoints_for_domain(name)
        self.run_endpoints(list(dict.fromkeys(endpoints)))
        return self.findings

    # ---- домены
    def check_domain(self, target_id: int, domain: str, whois_cache: dict[str, dict]) -> list[str]:
        timeout = self.s.dns_timeout
        dns_res = check_domain_dns(domain, timeout)
        self.findings += dns_res.findings
        reg = registrable_domain(domain)
        if reg not in whois_cache:
            whois_cache[reg] = whois_lookup(reg, timeout=max(timeout, 10))
            if reg == domain:
                self.findings += whois_findings(domain, whois_cache[reg])
        info = whois_cache[reg]
        subs, errors = discover_subdomains(
            domain,
            timeout=timeout,
            use_crtsh=self.s.crtsh_enabled,
            use_bruteforce=self.s.subdomain_bruteforce and self.profile != "quick",
        )
        with session_scope() as db:
            db.add(
                DomainResult(
                    scan_id=self.scan_id,
                    target_id=target_id,
                    domain=domain,
                    records=dns_res.records | ({"_notes": errors} if errors else {}),
                    email_security=dns_res.email,
                    zone_transfer=dns_res.axfr,
                    whois={k: v for k, v in info.items() if k != "raw"} | {"raw": (info.get("raw") or "")[:3000]},
                    subdomains=subs,
                )
            )
        if errors:
            log.info("Поддомены %s: %s", domain, "; ".join(errors))
        return [s["name"] for s in subs if s.get("resolves")]

    # ---- веб и TLS
    def run_endpoints(self, endpoints: list[Endpoint]) -> None:
        if not endpoints:
            return
        resolver = make_resolver(self.s.dns_timeout)
        resolvable: dict[str, bool] = {}

        def ok(ep: Endpoint) -> bool:
            if ep.asset_type == "ip":
                return True
            if ep.host not in resolvable:
                resolvable[ep.host] = bool(resolve_ips(ep.host, resolver))
            return resolvable[ep.host]

        endpoints = [e for e in endpoints if ok(e)]
        total = len(endpoints)
        done = 0
        timeout = self.s.http_timeout
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="check") as ex:
            futures = {}
            for ep in endpoints:
                if ep.kind == "web":
                    futures[ex.submit(check_web, ep.url, asset=ep.asset, asset_type=ep.asset_type, port=ep.port, timeout=timeout)] = ep
                else:
                    futures[ex.submit(check_tls, ep.host, ep.port, asset=ep.asset, asset_type=ep.asset_type, sni=ep.sni, timeout=timeout)] = ep
            for fut in as_completed(futures):
                ep = futures[fut]
                done += 1
                self.progress(f"Проверки веб и TLS ({done}/{total})", 40 + 60.0 * done / total)
                if self.cancel.is_set():
                    for f in futures:
                        f.cancel()
                    return
                try:
                    result = fut.result()
                except Exception:  # noqa: BLE001
                    log.exception("Ошибка проверки %s", ep)
                    continue
                self.store(result, ep)

    def store(self, result: WebCheckResult | TlsCheckResult, ep: Endpoint) -> None:
        if result.error and ep.asset_type == "domain" and ep.asset != ep.host:
            return
        with session_scope() as db:
            if isinstance(result, WebCheckResult):
                if result.error and ep.port == 80 and ep.asset_type == "domain":
                    return  # HTTP на 80 не отвечает — это нормально
                db.add(
                    WebResult(
                        scan_id=self.scan_id, asset=result.asset, url=result.url, final_url=result.final_url[:512],
                        status_code=result.status_code, title=result.title, server=result.server,
                        redirects_to_https=result.redirects_to_https, headers=result.headers,
                        security_headers=result.security_headers, technologies=result.technologies, error=result.error,
                    )
                )
            else:
                db.add(
                    TlsResult(
                        scan_id=self.scan_id, asset=result.asset, host=result.host, port=result.port,
                        certificate=result.certificate, chain_valid=result.chain_valid, chain_error=result.chain_error,
                        protocols=result.protocols, ciphers=result.ciphers, error=result.error,
                    )
                )
        self.findings += result.findings
