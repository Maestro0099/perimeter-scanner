"""Минимальный WHOIS-клиент (TCP/43) с определением сервера через IANA."""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone
from typing import Any

IANA = "whois.iana.org"
MAX_RESPONSE = 256 * 1024

_EXPIRY_PATTERNS = [
    r"Registry Expiry Date:\s*(.+)",
    r"Registrar Registration Expiration Date:\s*(.+)",
    r"Expiration Date:\s*(.+)",
    r"Expiry Date:\s*(.+)",
    r"paid-till:\s*(.+)",
    r"expires:\s*(.+)",
    r"Expires On:\s*(.+)",
    r"expire:\s*(.+)",
    r"free-date:\s*(.+)",
]
_CREATED_PATTERNS = [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Registered on:\s*(.+)", r"registered:\s*(.+)"]
_REGISTRAR_PATTERNS = [r"Registrar:\s*(.+)", r"registrar:\s*(.+)"]
_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y.%m.%d", "%d.%m.%Y", "%d-%b-%Y", "%Y/%m/%d",
)


def _query(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii"))
        chunks: list[bytes] = []
        total = 0
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if total > MAX_RESPONSE:
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_date(value: str) -> datetime | None:
    value = value.strip().split(" (")[0].strip()
    for fmt in _DATE_FORMATS:
        try:
            dt = datetime.strptime(value, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return None


def _first(patterns: list[str], text: str) -> str:
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def parse_whois(text: str) -> dict[str, Any]:
    expires_raw = _first(_EXPIRY_PATTERNS, text)
    created_raw = _first(_CREATED_PATTERNS, text)
    expires = parse_date(expires_raw) if expires_raw else None
    created = parse_date(created_raw) if created_raw else None
    days_left = None
    if expires:
        days_left = (expires - datetime.now(timezone.utc)).days
    return {
        "registrar": _first(_REGISTRAR_PATTERNS, text)[:200],
        "created": created.date().isoformat() if created else created_raw[:40],
        "expires": expires.date().isoformat() if expires else expires_raw[:40],
        "days_left": days_left,
    }


def registrable_domain(domain: str) -> str:
    """Упрощённо: последние две метки (или три для зон вида co.uk, com.ru)."""
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac", "msk", "spb"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def whois_lookup(domain: str, timeout: float = 10.0) -> dict[str, Any]:
    domain = registrable_domain(domain)
    tld = domain.rsplit(".", 1)[-1]
    try:
        iana = _query(IANA, tld, timeout)
        m = re.search(r"^whois:\s*(\S+)", iana, re.MULTILINE | re.IGNORECASE)
        server = m.group(1) if m else ""
        if not server:
            return {"domain": domain, "error": "WHOIS-сервер для зоны не найден"}
        text = _query(server, domain, timeout)
        # тонкие реестры (.com/.net) ссылаются на WHOIS регистратора
        ref = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.IGNORECASE)
        if ref and ref.group(1).lower() != server.lower():
            try:
                text2 = _query(ref.group(1), domain, timeout)
                if _first(_EXPIRY_PATTERNS, text2):
                    text = text + "\n" + text2
            except OSError:
                pass
    except OSError as exc:
        return {"domain": domain, "error": f"WHOIS недоступен: {type(exc).__name__}"}
    result = parse_whois(text)
    result.update({"domain": domain, "server": server, "raw": text[:4000]})
    return result
