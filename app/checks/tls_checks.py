"""Проверки TLS: сертификат, цепочка доверия, поддерживаемые протоколы и слабые шифры."""

from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from app.analysis.findings import FindingData

log = logging.getLogger("checks.tls")

PROTOCOLS: list[tuple[str, str]] = [
    ("TLSv1.0", "TLSv1"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.3", "TLSv1_3"),
]
DEPRECATED = {"TLSv1.0", "TLSv1.1"}

# группа шифров: (строка OpenSSL, уровень, описание)
WEAK_CIPHER_GROUPS: dict[str, tuple[str, str, str]] = {
    "NULL": ("eNULL:NULL", "high", "шифры без шифрования (NULL)"),
    "anon": ("aNULL", "high", "анонимный обмен ключами без аутентификации сервера"),
    "EXPORT": ("EXPORT", "high", "экспортные (40/56-битные) шифры"),
    "DES": ("DES:!3DES", "high", "шифр DES"),
    "RC4": ("RC4", "medium", "потоковый шифр RC4"),
    "3DES": ("3DES", "medium", "шифр 3DES (атака SWEET32)"),
    "MD5": ("MD5", "medium", "шифронаборы с MAC на основе MD5"),
    "kRSA": ("kRSA", "low", "обмен ключами RSA без прямой секретности (PFS)"),
}


@dataclass
class TlsCheckResult:
    asset: str
    asset_type: str
    host: str
    port: int
    certificate: dict[str, Any] = field(default_factory=dict)
    chain: list[dict[str, Any]] = field(default_factory=list)
    chain_valid: bool | None = None
    chain_error: str = ""
    protocols: dict[str, Any] = field(default_factory=dict)
    ciphers: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    findings: list[FindingData] = field(default_factory=list)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _base_ctx() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _handshake(ctx: ssl.SSLContext, host: str, port: int, sni: str | None, timeout: float) -> ssl.SSLSocket:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = ctx.wrap_socket(raw, server_hostname=sni)
        sock.settimeout(timeout)
        return sock
    except Exception:
        raw.close()
        raise


def _name(n: x509.Name) -> str:
    try:
        cn = n.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return str(cn[0].value)
    except Exception:  # noqa: BLE001
        pass
    return n.rfc4514_string()


def _key_info(cert: x509.Certificate) -> tuple[str, int]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return type(key).__name__.replace("PublicKey", ""), 256
    return type(key).__name__, 0


def describe_cert(der: bytes) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)]
        names += [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    key_type, key_size = _key_info(cert)
    sig = cert.signature_hash_algorithm
    return {
        "subject": _name(cert.subject),
        "issuer": _name(cert.issuer),
        "san": names[:100],
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": (not_after - datetime.now(timezone.utc)).days,
        "self_signed": cert.issuer == cert.subject,
        "serial": format(cert.serial_number, "x"),
        "signature": sig.name if sig else "",
        "key_type": key_type,
        "key_size": key_size,
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def _chain_from_socket(sock: ssl.SSLSocket) -> list[dict[str, Any]]:
    getter = getattr(sock, "get_unverified_chain", None)
    if getter is None and getattr(sock, "_sslobj", None) is not None:
        getter = getattr(sock._sslobj, "get_unverified_chain", None)  # Python 3.10–3.12
    if getter is None:
        return []
    try:
        items = getter() or []
    except Exception:  # noqa: BLE001
        return []
    chain: list[dict[str, Any]] = []
    for item in items[:10]:
        try:
            der = item if isinstance(item, bytes) else item.public_bytes(ssl._ssl.ENCODING_DER)  # type: ignore[attr-defined]
            info = describe_cert(der)
            chain.append({k: info[k] for k in ("subject", "issuer", "not_after", "days_left", "self_signed", "signature")})
        except Exception:  # noqa: BLE001
            continue
    return chain


def _hostname_matches(name: str, cert: dict[str, Any]) -> bool:
    candidates = [c.lower() for c in cert.get("san") or []] or [str(cert.get("subject", "")).lower()]
    name = name.lower()
    for c in candidates:
        if c == name:
            return True
        if c.startswith("*.") and name.count(".") == c.count(".") and name.endswith(c[1:]):
            return True
    return False


def check_tls(host: str, port: int, *, asset: str, asset_type: str, sni: str | None, timeout: float) -> TlsCheckResult:
    res = TlsCheckResult(asset=asset, asset_type=asset_type, host=host, port=port)
    server_name = sni if sni and not _is_ip(sni) else None

    # 1. Сертификат и согласованные параметры
    try:
        with _handshake(_base_ctx(), host, port, server_name, timeout) as sock:
            der = sock.getpeercert(binary_form=True)
            res.certificate = describe_cert(der) if der else {}
            res.certificate["negotiated_protocol"] = sock.version() or ""
            cipher = sock.cipher()
            res.certificate["negotiated_cipher"] = cipher[0] if cipher else ""
            res.chain = _chain_from_socket(sock)
    except (OSError, ssl.SSLError, ValueError) as exc:
        res.error = f"TLS-соединение не установлено: {type(exc).__name__}: {str(exc)[:200]}"
        return res
    res.certificate["chain"] = res.chain

    # 2. Проверка цепочки доверия и имени
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = server_name is not None
        with _handshake(ctx, host, port, server_name, timeout):
            res.chain_valid = True
    except ssl.SSLCertVerificationError as exc:
        res.chain_valid = False
        res.chain_error = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        res.chain_valid = None
        res.chain_error = f"Проверка не выполнена: {type(exc).__name__}"

    # 3. Поддерживаемые протоколы
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        for label, attr in PROTOCOLS:
            version = getattr(ssl.TLSVersion, attr, None)
            if version is None:
                res.protocols[label] = None
                continue
            try:
                ctx = _base_ctx()
                ctx.minimum_version = version
                ctx.maximum_version = version
                if label in DEPRECATED:
                    ctx.set_ciphers("ALL:@SECLEVEL=0")
            except (ssl.SSLError, ValueError):
                res.protocols[label] = None  # локальная библиотека не умеет проверять
                continue
            try:
                with _handshake(ctx, host, port, server_name, timeout):
                    res.protocols[label] = True
            except ssl.SSLError:
                res.protocols[label] = False
            except OSError:
                res.protocols[label] = None

    # 4. Слабые шифры (TLS 1.2 и ниже)
    max_legacy = next(
        (getattr(ssl.TLSVersion, a) for lbl, a in reversed(PROTOCOLS[:3]) if res.protocols.get(lbl)), None
    )
    for group, (spec, _sev, _desc) in WEAK_CIPHER_GROUPS.items():
        if max_legacy is None:
            res.ciphers[group] = None
            continue
        try:
            ctx = _base_ctx()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
            ctx.maximum_version = max_legacy
            ctx.set_ciphers(spec + ":@SECLEVEL=0")
        except (ssl.SSLError, ValueError):
            res.ciphers[group] = None  # не поддерживается локальной OpenSSL — не проверено
            continue
        try:
            with _handshake(ctx, host, port, server_name, timeout) as sock:
                c = sock.cipher()
                res.ciphers[group] = c[0] if c else True
        except ssl.SSLError:
            res.ciphers[group] = False
        except OSError:
            res.ciphers[group] = None

    res.findings = tls_findings(res, server_name)
    return res


def _tf(res: TlsCheckResult, sev: str, title: str, desc: str, rec: str, key: str, evidence: str = "") -> FindingData:
    return FindingData(
        asset=res.asset, asset_type=res.asset_type, category="tls", severity=sev, title=title, description=desc,
        recommendation=rec, port=res.port, protocol="tcp", evidence=evidence, key=key,
    )


def tls_findings(res: TlsCheckResult, server_name: str | None) -> list[FindingData]:
    out: list[FindingData] = []
    c = res.certificate
    if not c:
        return out
    days = c.get("days_left")
    ev = f"Субъект: {c.get('subject')}\nИздатель: {c.get('issuer')}\nДействителен до: {c.get('not_after')}"
    if days is not None:
        if days < 0:
            out.append(_tf(res, "critical", "Срок действия сертификата истёк",
                           f"Сертификат истёк {abs(days)} дн. назад.", "Немедленно выпустите и установите новый сертификат.", "cert-expired", ev))
        elif days < 14:
            out.append(_tf(res, "high", f"Сертификат истекает через {days} дн.",
                           "Срок действия сертификата заканчивается менее чем через 2 недели.",
                           "Продлите сертификат; настройте автоматическое продление (ACME).", "cert-expiring", ev))
        elif days < 30:
            out.append(_tf(res, "medium", f"Сертификат истекает через {days} дн.",
                           "Срок действия сертификата заканчивается менее чем через 30 дней.",
                           "Запланируйте продление сертификата.", "cert-expiring", ev))
    if c.get("self_signed"):
        out.append(_tf(res, "medium", "Самоподписанный сертификат",
                       "Сертификат не выпущен доверенным удостоверяющим центром; клиенты не могут проверить подлинность сервера.",
                       "Используйте сертификат от доверенного УЦ (например, Let's Encrypt).", "cert-selfsigned", ev))
    elif res.chain_valid is False and not (
        "hostname" in res.chain_error.lower() or "match" in res.chain_error.lower()
    ):
        out.append(_tf(res, "medium", "Цепочка сертификатов не проходит проверку",
                       f"Ошибка проверки: {res.chain_error or 'неизвестна'}. Частая причина — не установлены промежуточные сертификаты.",
                       "Установите полную цепочку (сертификат сервера + промежуточные) на сервере.", "cert-chain", ev))
    if server_name and not _hostname_matches(server_name, c):
        out.append(_tf(res, "medium", "Имя в сертификате не совпадает с доменом",
                       f"Сертификат не содержит имени {server_name}.",
                       "Выпустите сертификат, включающий это имя в Subject Alternative Name.", "cert-hostname", ev))
    if c.get("key_type") == "RSA" and 0 < c.get("key_size", 0) < 2048:
        out.append(_tf(res, "high", f"Слабый ключ RSA ({c['key_size']} бит)", "Длина ключа RSA менее 2048 бит.",
                       "Перевыпустите сертификат с ключом RSA ≥ 2048 бит или ECDSA P-256.", "cert-weak-key", ev))
    if c.get("signature") in ("sha1", "md5"):
        out.append(_tf(res, "medium", f"Устаревший алгоритм подписи ({c['signature'].upper()})",
                       "Сертификат подписан с использованием устаревшей хэш-функции.",
                       "Перевыпустите сертификат с подписью SHA-256 или новее.", "cert-weak-sig", ev))
    old = [p for p in ("TLSv1.0", "TLSv1.1") if res.protocols.get(p)]
    if old:
        out.append(_tf(res, "medium", "Поддерживаются устаревшие протоколы: " + ", ".join(old),
                       "TLS 1.0 и 1.1 признаны небезопасными (RFC 8996).",
                       "Отключите TLS 1.0/1.1, оставьте TLS 1.2 и TLS 1.3.", "proto-old"))
    if res.protocols.get("TLSv1.3") is False and res.protocols.get("TLSv1.2"):
        out.append(_tf(res, "info", "TLS 1.3 не поддерживается", "Сервер не поддерживает TLS 1.3.",
                       "Включите TLS 1.3 для повышения безопасности и производительности.", "proto-no13"))
    if res.protocols.get("TLSv1.2") is False and res.protocols.get("TLSv1.3") is False:
        out.append(_tf(res, "high", "Не поддерживаются современные версии TLS",
                       "Сервер не принимает ни TLS 1.2, ни TLS 1.3.", "Включите TLS 1.2 и TLS 1.3.", "proto-none"))
    for group, accepted in res.ciphers.items():
        if accepted:
            _spec, sev, desc = WEAK_CIPHER_GROUPS[group]
            out.append(_tf(res, sev, f"Принимаются слабые шифры: {group}", f"Сервер согласовывает {desc}.",
                           "Отключите слабые шифронаборы; используйте AEAD-шифры (AES-GCM, ChaCha20-Poly1305) с ECDHE.",
                           f"cipher:{group}", str(accepted)))
    return out
