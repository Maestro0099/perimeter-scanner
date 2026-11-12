"""Проверки доменов, веба и TLS (без обращения во внешнюю сеть)."""

from __future__ import annotations

import datetime as dt
import http.server
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.checks.dns_checks import analyze_dmarc, analyze_spf
from app.checks.runner import endpoints_from_hosts, whois_findings
from app.checks.subdomains import parse_crtsh
from app.checks.techdetect import detect
from app.checks.tls_checks import check_tls
from app.checks.web_checks import analyze_headers, check_web
from app.checks.whois_client import parse_whois, registrable_domain
from app.models import Host, Port


# --------------------------------------------------------------------------- DNS / почта


def test_spf_analysis() -> None:
    assert "SPF-запись отсутствует" in analyze_spf(["google-site-verification=x"])["issues"]
    good = analyze_spf(["v=spf1 mx include:_spf.example.net -all"])
    assert good["all"] == "-all" and good["issues"] == []
    assert any("+all" in i for i in analyze_spf(["v=spf1 +all"])["issues"])
    assert any("?all" in i for i in analyze_spf(["v=spf1 a ?all"])["issues"])
    assert any("Несколько" in i for i in analyze_spf(["v=spf1 -all", "v=spf1 mx -all"])["issues"])
    assert analyze_spf(["v=spf1 mx all"])["all"] == "+all"


def test_dmarc_analysis() -> None:
    assert analyze_dmarc([])["issues"] == ["DMARC-запись отсутствует"]
    strict = analyze_dmarc(["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])
    assert strict["policy"] == "reject" and strict["issues"] == []
    weak = analyze_dmarc(["v=DMARC1; p=none; pct=50"])
    assert weak["policy"] == "none"
    assert any("p=none" in i for i in weak["issues"])
    assert any("50%" in i for i in weak["issues"])
    assert any("rua" in i for i in weak["issues"])


def test_crtsh_parsing() -> None:
    data = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "mail.example.com"},
        {"name_value": "example.com"},
        {"name_value": "evil-example.com"},
        {"name_value": "x.example.com.attacker.net"},
        {"name_value": "bad name.example.com"},
        "garbage",
    ]
    assert parse_crtsh(data, "example.com") == {"www.example.com", "mail.example.com"}
    assert parse_crtsh({"not": "a list"}, "example.com") == set()


def test_whois_parsing() -> None:
    future = (dt.date.today() + dt.timedelta(days=20)).strftime("%Y.%m.%d")
    ru = f"domain:        EXAMPLE.RU\nregistrar:     RU-CENTER-RU\ncreated:       2001.01.01T00:00:00Z\npaid-till:     {future}\n"
    info = parse_whois(ru)
    assert info["registrar"] == "RU-CENTER-RU"
    assert 18 <= info["days_left"] <= 20
    findings = whois_findings("example.ru", info)
    assert findings and findings[0].severity == "high"
    com = "Registrar: Example Registrar, Inc.\nCreation Date: 1995-08-14T04:00:00Z\nRegistry Expiry Date: 2099-08-13T04:00:00Z\n"
    info = parse_whois(com)
    assert info["expires"] == "2099-08-13" and info["days_left"] > 1000
    assert whois_findings("example.com", info) == []
    assert registrable_domain("a.b.example.com") == "example.com"
    assert registrable_domain("shop.example.co.uk") == "example.co.uk"


# --------------------------------------------------------------------------- веб


def test_techdetect() -> None:
    techs = detect(
        {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"},
        ["BITRIX_SM_GUEST_ID=1; path=/"],
        '<script src="/bitrix/js/main/core.js"></script><script src="/js/jquery-3.6.0.min.js"></script>',
    )
    assert {"nginx", "PHP", "1С-Битрикс", "jQuery"} <= set(techs)


def test_header_analysis() -> None:
    res = analyze_headers({"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"}, is_https=True)
    assert res["x-frame-options"]["present"]  # закрыто директивой frame-ancestors
    assert not res["strict-transport-security"]["present"]
    assert not res["x-content-type-options"]["present"]


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "https://other.example.net/")
            self.end_headers()
            return
        body = b"<html><head><title>Index of /</title></head><body>wp-login.php</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session=abc; Path=/")
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.end_headers()
        self.wfile.write(body)

    def version_string(self) -> str:
        return "Apache/2.4.29 (Ubuntu)"

    def log_message(self, *args) -> None:  # тишина в тестах
        pass


@pytest.fixture
def http_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def test_check_web_plain_http(http_server: int) -> None:
    res = check_web(f"http://127.0.0.1:{http_server}/", asset="203.0.113.10", asset_type="ip", port=http_server, timeout=5)
    assert res.error == ""
    assert res.status_code == 200
    assert res.redirects_to_https is False
    assert "Apache HTTP Server" in res.technologies and "PHP" in res.technologies
    keys = {f.key for f in res.findings}
    assert {"no-https-redirect", "banner", "cookies", "dirlist", "hdr:x-frame-options", "panel:WordPress (админ-панель)"} <= keys
    banner = next(f for f in res.findings if f.key == "banner")
    assert "PHP/5.6.40" in banner.evidence
    assert all(f.category == "web" and f.port == http_server for f in res.findings)


def test_redirect_out_of_scope_is_not_followed(http_server: int) -> None:
    res = check_web(f"http://127.0.0.1:{http_server}/redirect", asset="203.0.113.10", asset_type="ip", port=http_server, timeout=5)
    assert res.redirect_chain and "не запрашивался" in res.redirect_chain[-1]
    assert res.status_code == 301


def test_check_web_connection_refused() -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    res = check_web(f"http://127.0.0.1:{port}/", asset="x", asset_type="ip", port=port, timeout=2)
    assert res.error and not res.findings


# --------------------------------------------------------------------------- TLS


def _self_signed(tmp_path: Path, days: int) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.example.com")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return cert_path, key_path


@pytest.fixture
def tls_server(tmp_path: Path):
    cert, key = _self_signed(tmp_path, days=10)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(20)
    stop = threading.Event()

    def serve() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    s.settimeout(1)
                    try:
                        s.recv(1)
                    except OSError:
                        pass
            except (ssl.SSLError, OSError):
                conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield srv.getsockname()[1]
    stop.set()
    t.join(2)
    srv.close()


def test_check_tls_self_signed_expiring(tls_server: int) -> None:
    res = check_tls("127.0.0.1", tls_server, asset="test.example.com", asset_type="domain", sni="test.example.com", timeout=5)
    assert res.error == ""
    c = res.certificate
    assert c["subject"] == "test.example.com" and c["self_signed"]
    assert 8 <= c["days_left"] <= 10
    assert c["key_type"] == "RSA" and c["key_size"] == 2048
    assert res.chain_valid is False
    assert res.protocols["TLSv1.2"] is True and res.protocols["TLSv1.3"] is True
    assert res.protocols["TLSv1.0"] in (False, None)
    keys = {f.key: f.severity for f in res.findings}
    assert keys.get("cert-expiring") == "high"
    assert keys.get("cert-selfsigned") == "medium"
    assert "proto-old" not in keys
    assert keys.get("cipher:NULL") is None


def test_check_tls_hostname_mismatch(tls_server: int) -> None:
    res = check_tls("127.0.0.1", tls_server, asset="other.example.com", asset_type="domain", sni="other.example.com", timeout=5)
    assert any(f.key == "cert-hostname" for f in res.findings)


def test_endpoints_from_hosts() -> None:
    h = Host(ip="203.0.113.10", hostnames=[])
    h.ports = [
        Port(protocol="tcp", port=80, state="open", service="http", tunnel=""),
        Port(protocol="tcp", port=443, state="open", service="http", tunnel="ssl"),
        Port(protocol="tcp", port=993, state="open", service="imaps", tunnel="ssl"),
        Port(protocol="tcp", port=22, state="open", service="ssh", tunnel=""),
        Port(protocol="udp", port=443, state="open", service="https", tunnel=""),
    ]
    eps = {(e.kind, e.port, e.url) for e in endpoints_from_hosts([h])}
    assert eps == {
        ("web", 80, "http://203.0.113.10/"),
        ("web", 443, "https://203.0.113.10/"),
        ("tls", 443, ""),
        ("tls", 993, ""),
    }
