"""Поиск поддоменов: журналы Certificate Transparency (crt.sh) и перебор по словарю."""

from __future__ import annotations

import logging
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx

from app.checks.dns_checks import make_resolver, resolve_ips
from app.config import BASE_DIR
from app.validation import is_subdomain_of, is_valid_domain

log = logging.getLogger("checks.subdomains")

WORDLIST = BASE_DIR / "data" / "subdomains.txt"
USER_AGENT = "perimeter-scanner/1.0 (internal security monitoring)"


def load_wordlist(path: Path = WORDLIST, limit: int = 5000) -> list[str]:
    if not path.is_file():
        return []
    words: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        w = line.strip().lower()
        if w and not w.startswith("#") and w not in words:
            words.append(w)
    return words[:limit]


def parse_crtsh(data: Any, domain: str) -> set[str]:
    names: set[str] = set()
    if not isinstance(data, list):
        return names
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value", "")).splitlines():
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            if name and name != domain and is_subdomain_of(name, domain) and is_valid_domain(name):
                names.add(name)
    return names


def from_crtsh(domain: str, timeout: float) -> tuple[set[str], str]:
    """Возвращает (имена, ошибка)."""
    try:
        with httpx.Client(timeout=timeout * 3, headers={"User-Agent": USER_AGENT}) as client:
            r = client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
            if r.status_code != 200:
                return set(), f"crt.sh вернул HTTP {r.status_code}"
            return parse_crtsh(r.json(), domain), ""
    except (httpx.HTTPError, ValueError) as exc:
        return set(), f"crt.sh недоступен: {type(exc).__name__}"


def bruteforce(domain: str, words: list[str], timeout: float, workers: int = 20) -> dict[str, list[str]]:
    resolver = make_resolver(timeout)
    # Защита от wildcard DNS: случайное имя не должно разрешаться
    wildcard = set(resolve_ips(f"{secrets.token_hex(8)}.{domain}", resolver))

    def probe(word: str) -> tuple[str, list[str]]:
        name = f"{word}.{domain}"
        return name, resolve_ips(name, resolver)

    found: dict[str, list[str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for name, ips in ex.map(probe, words):
            if ips and not (wildcard and set(ips) <= wildcard):
                found[name] = ips
    return found


def discover_subdomains(
    domain: str, *, timeout: float, use_crtsh: bool, use_bruteforce: bool, max_resolve: int = 500
) -> tuple[list[dict[str, Any]], list[str]]:
    """Возвращает (список {name, ips, sources}, ошибки)."""
    errors: list[str] = []
    sources: dict[str, set[str]] = {}
    ips: dict[str, list[str]] = {}
    if use_crtsh:
        names, err = from_crtsh(domain, timeout)
        if err:
            errors.append(err)
        for n in names:
            sources.setdefault(n, set()).add("crt.sh")
    if use_bruteforce:
        for name, addrs in bruteforce(domain, load_wordlist(), timeout).items():
            sources.setdefault(name, set()).add("словарь")
            ips[name] = addrs
    resolver = make_resolver(timeout)
    to_resolve = [n for n in sorted(sources) if n not in ips][:max_resolve]
    with ThreadPoolExecutor(max_workers=20) as ex:
        for name, addrs in zip(to_resolve, ex.map(lambda n: resolve_ips(n, resolver), to_resolve)):
            ips[name] = addrs
    result = [
        {"name": n, "ips": sorted(ips.get(n, [])), "sources": sorted(sources[n]), "resolves": bool(ips.get(n))}
        for n in sorted(sources)
    ]
    return result, errors
