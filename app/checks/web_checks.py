"""Проверки веб-сервисов: заголовки безопасности, редирект на HTTPS, баннеры, технологии."""

from __future__ import annotations

import html
import logging
import re
import warnings
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from app.analysis.findings import FindingData
from app.analysis.knowledge import ADMIN_PANEL_TECH
from app.checks.techdetect import detect, discloses_version

log = logging.getLogger("checks.web")

USER_AGENT = "Mozilla/5.0 (compatible; perimeter-scanner/1.0; internal security monitoring)"
MAX_BODY = 512 * 1024
MAX_REDIRECTS = 6
HSTS_MIN_AGE = 15552000  # 180 дней

SECURITY_HEADERS: dict[str, tuple[str, str, str]] = {
    # заголовок: (уровень при отсутствии, название, рекомендация)
    "content-security-policy": (
        "low", "Content-Security-Policy",
        "Добавьте заголовок Content-Security-Policy, ограничивающий источники скриптов, стилей и фреймов.",
    ),
    "x-frame-options": (
        "low", "X-Frame-Options",
        "Добавьте X-Frame-Options: DENY (или SAMEORIGIN) либо директиву CSP frame-ancestors для защиты от clickjacking.",
    ),
    "x-content-type-options": (
        "low", "X-Content-Type-Options", "Добавьте заголовок X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "info", "Referrer-Policy", "Добавьте Referrer-Policy: strict-origin-when-cross-origin (или строже).",
    ),
    "permissions-policy": (
        "info", "Permissions-Policy", "Добавьте Permissions-Policy, отключив неиспользуемые возможности браузера.",
    ),
}


@dataclass
class WebCheckResult:
    asset: str
    asset_type: str
    url: str
    final_url: str = ""
    status_code: int | None = None
    title: str = ""
    server: str = ""
    redirects_to_https: bool | None = None
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, Any] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    error: str = ""
    findings: list[FindingData] = field(default_factory=list)


def _fetch(client: httpx.Client, url: str) -> tuple[httpx.Response, str]:
    with client.stream("GET", url) as resp:
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_bytes():
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_BODY:
                break
        body = b"".join(chunks)[:MAX_BODY]
    charset = resp.charset_encoding or "utf-8"
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    return resp, text


def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:200] if m else ""


def analyze_headers(headers: dict[str, str], is_https: bool) -> dict[str, Any]:
    h = {k.lower(): v for k, v in headers.items()}
    result: dict[str, Any] = {}
    hsts = h.get("strict-transport-security", "")
    if is_https:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.IGNORECASE)
        result["strict-transport-security"] = {
            "present": bool(hsts),
            "value": hsts,
            "max_age": int(m.group(1)) if m else 0,
            "include_subdomains": "includesubdomains" in hsts.lower(),
        }
    csp = h.get("content-security-policy", "")
    for name in SECURITY_HEADERS:
        value = h.get(name, "")
        present = bool(value)
        if name == "x-frame-options" and not present and "frame-ancestors" in csp.lower():
            present = True
            value = "(CSP frame-ancestors)"
        result[name] = {"present": present, "value": value}
    if csp:
        result["content-security-policy"]["weak"] = bool(re.search(r"'unsafe-inline'|'unsafe-eval'|\*(?:\s|;|$)", csp))
    return result


def _cookie_issues(set_cookies: list[str], is_https: bool) -> list[str]:
    issues: list[str] = []
    for c in set_cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = []
        if is_https and "; secure" not in low and not low.endswith("secure"):
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            issues.append(f"{name}: нет {', '.join(missing)}")
    return issues


def _in_scope(target_url: str, original_url: str, asset: str) -> bool:
    """Переходим по редиректам только в пределах исходного хоста или домена организации."""
    from app.checks.whois_client import registrable_domain
    from app.validation import is_subdomain_of, is_valid_domain

    host = (urlsplit(target_url).hostname or "").lower()
    orig = (urlsplit(original_url).hostname or "").lower()
    if host == orig:
        return True
    if is_valid_domain(asset):
        return is_subdomain_of(host, registrable_domain(asset))
    return False


def check_web(url: str, *, asset: str, asset_type: str, port: int, timeout: float) -> WebCheckResult:
    res = WebCheckResult(asset=asset, asset_type=asset_type, url=url)
    start_https = url.startswith("https://")
    transport = httpx.HTTPTransport(retries=0, verify=False)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with httpx.Client(
                transport=transport,
                timeout=httpx.Timeout(timeout),
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"},
                verify=False,
            ) as client:
                current = url
                resp, body = _fetch(client, current)
                while resp.is_redirect and len(res.redirect_chain) < MAX_REDIRECTS:
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    nxt = urljoin(current, location)
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        break
                    if not _in_scope(nxt, url, asset):
                        res.redirect_chain.append(nxt + " (внешний адрес, не запрашивался)")
                        current = nxt
                        res.final_url = nxt
                        res.error = ""
                        res.status_code = resp.status_code
                        break
                    res.redirect_chain.append(nxt)
                    current = nxt
                    resp, body = _fetch(client, current)
    except httpx.HTTPError as exc:
        res.error = f"{type(exc).__name__}: {str(exc)[:200]}"
        return res

    offscope = bool(res.redirect_chain) and res.redirect_chain[-1].endswith("(внешний адрес, не запрашивался)")
    res.final_url = current
    res.status_code = resp.status_code
    if offscope:
        res.title = _title(body)
        res.server = resp.headers.get("server", "")[:255]
        res.headers = {k: v[:500] for k, v in resp.headers.items() if k.lower() != "set-cookie"}
        if not start_https:
            res.redirects_to_https = current.startswith("https://")
        return res
    res.title = _title(body)
    res.headers = {k: v[:500] for k, v in resp.headers.items() if k.lower() != "set-cookie"}
    res.server = resp.headers.get("server", "")[:255]
    final_https = current.startswith("https://")
    if not start_https:
        res.redirects_to_https = final_https and urlsplit(current).hostname == urlsplit(url).hostname
        if not res.redirects_to_https and res.redirect_chain and final_https:
            res.redirects_to_https = True
    set_cookies = resp.headers.get_list("set-cookie")
    res.technologies = detect(dict(resp.headers), set_cookies, body)
    res.security_headers = analyze_headers(dict(resp.headers), final_https)
    res.findings = _web_findings(res, port, start_https, final_https, set_cookies, body)
    return res


def _wf(res: WebCheckResult, port: int, sev: str, title: str, desc: str, rec: str, key: str, evidence: str = "") -> FindingData:
    return FindingData(
        asset=res.asset, asset_type=res.asset_type, category="web", severity=sev, title=title, description=desc,
        recommendation=rec, port=port, protocol="tcp", evidence=evidence or res.url, key=key,
    )


def _web_findings(
    res: WebCheckResult, port: int, start_https: bool, final_https: bool, set_cookies: list[str], body: str
) -> list[FindingData]:
    out: list[FindingData] = []
    if not start_https:
        if res.redirects_to_https:
            return out  # заголовки проверяются на HTTPS-версии
        out.append(_wf(
            res, port, "medium", "Нет перенаправления с HTTP на HTTPS",
            f"{res.url} отвечает по незашифрованному HTTP (код {res.status_code}) без перенаправления на HTTPS.",
            "Настройте постоянное перенаправление (301) всех HTTP-запросов на HTTPS и включите HSTS.", "no-https-redirect",
        ))
    sh = res.security_headers
    hsts = sh.get("strict-transport-security")
    if final_https and hsts is not None:
        if not hsts["present"]:
            out.append(_wf(res, port, "medium", "Отсутствует заголовок HSTS",
                           "Без Strict-Transport-Security браузер может быть принуждён к незашифрованному соединению (SSL stripping).",
                           "Добавьте Strict-Transport-Security: max-age=31536000; includeSubDomains.", "hdr:hsts"))
        elif hsts["max_age"] < HSTS_MIN_AGE:
            out.append(_wf(res, port, "low", "Слишком малый max-age в HSTS", f"Текущее значение: {hsts['value']}",
                           "Установите max-age не менее 15552000 (180 дней), рекомендуется 31536000.", "hdr:hsts-age", hsts["value"]))
    missing = [(n, *SECURITY_HEADERS[n]) for n in SECURITY_HEADERS if not sh.get(n, {}).get("present")]
    for name, sev, label, rec in missing:
        out.append(_wf(res, port, sev, f"Отсутствует заголовок {label}",
                       f"Ответ {res.final_url} не содержит заголовка {label}.", rec, f"hdr:{name}"))
    csp = sh.get("content-security-policy", {})
    if csp.get("present") and csp.get("weak"):
        out.append(_wf(res, port, "info", "CSP содержит небезопасные директивы",
                       "Политика CSP разрешает 'unsafe-inline', 'unsafe-eval' или источник *.",
                       "Уберите 'unsafe-inline'/'unsafe-eval', используйте nonce или hash.", "hdr:csp-weak", csp.get("value", "")))
    # Раскрытие версий ПО
    banners = {k: res.headers.get(k, "") for k in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")}
    disclosed = {k: v for k, v in banners.items() if v and (discloses_version(v) or k != "server")}
    if disclosed:
        out.append(_wf(res, port, "low", "Раскрытие версии серверного ПО в заголовках",
                       "Заголовки ответа сообщают тип и версию ПО, что упрощает подбор эксплойтов.",
                       "Скройте версии: server_tokens off (nginx), ServerTokens Prod (Apache), "
                       "удалите X-Powered-By/X-AspNet-Version.", "banner",
                       "\n".join(f"{k}: {v}" for k, v in disclosed.items())))
    cookie_issues = _cookie_issues(set_cookies, final_https)
    if cookie_issues:
        out.append(_wf(res, port, "low", "Cookie без защитных флагов",
                       "Cookie устанавливаются без флагов Secure / HttpOnly / SameSite.",
                       "Установите для cookie флаги Secure, HttpOnly и SameSite=Lax/Strict.", "cookies",
                       "\n".join(cookie_issues[:10])))
    if re.search(r"<title>\s*Index of /", body, re.IGNORECASE):
        out.append(_wf(res, port, "medium", "Включён листинг каталогов",
                       "Веб-сервер показывает содержимое каталога.", "Отключите autoindex / Options -Indexes.", "dirlist"))
    for tech in res.technologies:
        if tech in ADMIN_PANEL_TECH:
            sev, title = ADMIN_PANEL_TECH[tech]
            out.append(_wf(res, port, sev, title,
                           f"На {res.final_url} обнаружен интерфейс {tech}.",
                           "Административные интерфейсы не должны быть доступны из интернета: "
                           "ограничьте доступ VPN / списком адресов и включите MFA.", f"panel:{tech}"))
    return out
