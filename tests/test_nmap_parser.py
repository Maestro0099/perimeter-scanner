from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.findings import findings_from_host
from app.scanner.nmap_parser import NmapParseError, extract_vulns, parse_nmap_xml
from app.scanner.nmap_profiles import NmapOptions, build_nmap_args
from app.scanner.nmap_runner import parse_progress_line
from app.validation import ValidationError


def load(fixtures_dir: Path, name: str) -> bytes:
    return (fixtures_dir / name).read_bytes()


def test_parse_real_local_scan(fixtures_dir: Path) -> None:
    run = parse_nmap_xml(load(fixtures_dir, "nmap_local.xml"))
    assert run.complete
    assert run.exit_status == "success"
    assert len(run.hosts) == 1
    host = run.hosts[0]
    assert host.ip == "127.0.0.1"
    assert host.status == "up"
    open_ports = host.open_ports
    assert [p.port for p in open_ports] == [8081]
    http = open_ports[0]
    assert http.service.name == "http"
    assert "SimpleHTTPServer" in http.service.product
    title = http.script("http-title")
    assert title is not None and "Test page" in title.output
    closed = [p for p in host.ports if p.state == "closed"]
    assert {p.port for p in closed} == {9, 22}


def test_parse_full_fixture_hosts_and_services(fixtures_dir: Path) -> None:
    run = parse_nmap_xml(load(fixtures_dir, "nmap_full.xml"))
    assert run.version == "7.94"
    assert run.elapsed == pytest.approx(300.12)
    assert [h.ip for h in run.hosts] == ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
    h1, h2, h3 = run.hosts
    assert h3.status == "down"
    assert h1.user_hostnames == ["example.com"]
    assert "www.example.com" in h1.hostnames
    assert h1.best_os is not None and h1.best_os.name == "Linux 5.0 - 5.14" and h1.best_os.accuracy == 95
    keys = [p.key for p in h1.open_ports]
    assert keys == ["21/tcp", "22/tcp", "80/tcp", "443/tcp", "3306/tcp", "161/udp"]
    ssh = next(p for p in h1.ports if p.port == 22)
    assert ssh.service.product == "OpenSSH"
    assert ssh.service.version == "8.9p1 Ubuntu 3ubuntu0.6"
    assert ssh.service.cpe == ["cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:linux:linux_kernel"]
    https = next(p for p in h1.ports if p.port == 443)
    assert https.service.tunnel == "ssl"
    assert h1.host_scripts[0].id == "whois-ip"
    assert [p.port for p in h2.open_ports] == [3389, 6379]


def test_vulners_extraction(fixtures_dir: Path) -> None:
    run = parse_nmap_xml(load(fixtures_dir, "nmap_full.xml"))
    ssh = next(p for p in run.hosts[0].ports if p.port == 22)
    vulns = {v.id: v for v in extract_vulns(ssh.scripts)}
    assert set(vulns) == {"CVE-2023-38408", "CVE-2023-28531", "PACKETSTORM:173661", "CVE-2023-51385"}
    assert vulns["CVE-2023-38408"].cvss == 9.8
    assert vulns["CVE-2023-38408"].cpe == "cpe:/a:openbsd:openssh:8.9p1"
    assert vulns["PACKETSTORM:173661"].is_exploit
    assert not vulns["PACKETSTORM:173661"].is_cve


def test_nse_vuln_library_extraction(fixtures_dir: Path) -> None:
    run = parse_nmap_xml(load(fixtures_dir, "nmap_full.xml"))
    https = next(p for p in run.hosts[0].ports if p.port == 443)
    vulns = extract_vulns(https.scripts)
    # ssl-dh-params имеет состояние NOT VULNERABLE и не должен попасть в результат
    assert [v.id for v in vulns] == ["CVE-2014-0160"]
    assert vulns[0].source == "ssl-heartbleed"
    assert "Heartbleed" in vulns[0].title
    assert "OpenSSL versions" in vulns[0].description


def test_findings_generation(fixtures_dir: Path) -> None:
    run = parse_nmap_xml(load(fixtures_dir, "nmap_full.xml"))
    findings = findings_from_host(run.hosts[0])
    by_title = {f.title: f for f in findings}
    cves = {f.cve: f for f in findings if f.cve}
    assert set(cves) == {"CVE-2023-38408", "CVE-2023-28531", "CVE-2023-51385", "CVE-2014-0160"}
    assert cves["CVE-2023-38408"].severity == "critical"
    assert cves["CVE-2023-51385"].severity == "medium"
    assert cves["CVE-2014-0160"].severity == "high"  # без CVSS, состояние VULNERABLE
    assert "nvd.nist.gov" in cves["CVE-2023-38408"].recommendation
    assert any("анонимный вход" in t.lower() for t in by_title)
    mysql = next(f for f in findings if f.port == 3306 and f.category == "port")
    assert mysql.severity == "high"
    snmp = [f for f in findings if f.port == 161]
    assert {f.severity for f in snmp} >= {"high"}
    https_open = next(f for f in findings if f.port == 443 and f.category == "port")
    assert https_open.severity == "info"
    # отпечатки уникальны
    assert len({f.fingerprint for f in findings}) == len(findings)
    redis = findings_from_host(run.hosts[1])
    assert any(f.severity == "critical" and f.port == 6379 for f in redis)


def test_truncated_xml_is_repaired(fixtures_dir: Path) -> None:
    run = parse_nmap_xml(load(fixtures_dir, "nmap_truncated.xml"))
    assert not run.complete
    assert [h.ip for h in run.hosts] == ["203.0.113.10"]


@pytest.mark.parametrize("data", [b"", b"   ", b"<html></html>", b"not xml at all"])
def test_invalid_xml(data: bytes) -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(data)


def test_xxe_is_blocked(fixtures_dir: Path) -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml(load(fixtures_dir, "nmap_xxe.xml"))


def test_progress_line_parsing() -> None:
    phase, pct = parse_progress_line("SYN Stealth Scan Timing: About 50.00% done; ETC: 22:41 (0:00:27 remaining)")
    assert phase == "SYN Stealth Scan" and pct == pytest.approx(25.0)
    phase, pct = parse_progress_line("NSE Timing: About 100.00% done; ETC: 22:41 (0:00:00 remaining)")
    assert phase == "NSE" and pct == pytest.approx(99.0)
    assert parse_progress_line("Nmap scan report for example.com") is None


def test_build_args_safe(tmp_path: Path) -> None:
    for profile in ("quick", "full", "aggressive"):
        args = build_nmap_args(NmapOptions(profile, 3, True, tmp_path / "t.txt", tmp_path / "o.xml"))
        assert args[-2:] == ["-iL", str(tmp_path / "t.txt")]
        joined = " ".join(args)
        assert "-T3" in args
        if profile != "quick":
            expr = args[args.index("--script") + 1]
            assert "not (brute or dos or exploit" in expr
        if profile == "full":
            assert "intrusive)" in joined and "auth" not in joined
        if profile == "aggressive":
            assert "auth or intrusive" in joined
    quick = build_nmap_args(NmapOptions("quick", 4, False, tmp_path / "t.txt", tmp_path / "o.xml"))
    assert "-sT" in quick and "--top-ports" in quick and "-O" not in quick and "-sU" not in quick
    full = build_nmap_args(NmapOptions("full", 4, True, tmp_path / "t.txt", tmp_path / "o.xml"))
    ports = full[full.index("-p") + 1]
    assert ports.startswith("T:1-65535,U:") and len(ports.split("U:")[1].split(",")) == 100
    with pytest.raises(ValidationError):
        build_nmap_args(NmapOptions("full", 9, True, tmp_path / "t.txt", tmp_path / "o.xml"))
    with pytest.raises(ValidationError):
        build_nmap_args(NmapOptions("bogus", 3, True, tmp_path / "t.txt", tmp_path / "o.xml"))
