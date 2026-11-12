from __future__ import annotations

from app.analysis.diff import FindingInfo, ServiceInfo, Snapshot, VulnInfo, diff_snapshots


def base() -> Snapshot:
    return Snapshot(
        hosts={
            "203.0.113.10": {
                "22/tcp": ServiceInfo("ssh", "OpenSSH", "8.9p1"),
                "443/tcp": ServiceInfo("https", "nginx", "1.18.0"),
                "8080/tcp": ServiceInfo("http-proxy", "", ""),
            },
            "203.0.113.11": {"25/tcp": ServiceInfo("smtp", "Postfix", "")},
        },
        vulns={
            ("203.0.113.10", "22/tcp", "CVE-2023-38408"): VulnInfo("critical", "CVE-2023-38408", 9.8),
        },
        subdomains={"example.com": {"www.example.com", "mail.example.com"}},
        findings={
            "mail|example.com|-|dmarc": FindingInfo("example.com", "domain", "medium", "DMARC не настроен"),
        },
    )


def by_type(changes, t):
    return [c for c in changes if c.change_type == t]


def test_first_scan_is_baseline() -> None:
    assert diff_snapshots(None, base()) == []


def test_identical_snapshots_have_no_changes() -> None:
    assert diff_snapshots(base(), base()) == []


def test_new_and_closed_ports() -> None:
    new = base()
    new.hosts["203.0.113.10"] = dict(new.hosts["203.0.113.10"])
    del new.hosts["203.0.113.10"]["8080/tcp"]
    new.hosts["203.0.113.10"]["3389/tcp"] = ServiceInfo("ms-wbt-server", "Microsoft Terminal Services", "")
    new.hosts["203.0.113.10"]["8443/tcp"] = ServiceInfo("https-alt", "", "")
    changes = diff_snapshots(base(), new)
    opened = by_type(changes, "port_opened")
    assert {c.new_value.split()[0] for c in opened} == {"3389/tcp", "8443/tcp"}
    rdp = next(c for c in opened if c.new_value.startswith("3389"))
    assert rdp.severity == "high"  # RDP из интернета — высокий риск
    other = next(c for c in opened if c.new_value.startswith("8443"))
    assert other.severity == "low"
    closed = by_type(changes, "port_closed")
    assert len(closed) == 1 and closed[0].old_value.startswith("8080/tcp")
    assert closed[0].severity == "info"


def test_service_version_change() -> None:
    new = base()
    new.hosts["203.0.113.10"] = dict(new.hosts["203.0.113.10"])
    new.hosts["203.0.113.10"]["22/tcp"] = ServiceInfo("ssh", "OpenSSH", "9.6p1")
    changes = diff_snapshots(base(), new)
    assert len(changes) == 1
    ch = changes[0]
    assert ch.change_type == "service_changed"
    assert ch.old_value == "OpenSSH 8.9p1" and ch.new_value == "OpenSSH 9.6p1"


def test_version_disappearing_is_not_a_change() -> None:
    """Если nmap не смог определить версию повторно, это не считается изменением."""
    new = base()
    new.hosts["203.0.113.10"] = dict(new.hosts["203.0.113.10"])
    new.hosts["203.0.113.10"]["22/tcp"] = ServiceInfo("ssh", "", "")
    assert by_type(diff_snapshots(base(), new), "service_changed") == []


def test_new_and_fixed_vulns() -> None:
    new = base()
    new.vulns = {("203.0.113.10", "443/tcp", "CVE-2021-23017"): VulnInfo("high", "CVE-2021-23017", 7.7)}
    changes = diff_snapshots(base(), new)
    nv = by_type(changes, "vuln_new")
    assert len(nv) == 1 and nv[0].new_value == "CVE-2021-23017" and nv[0].severity == "high"
    assert "CVSS 7.7" in nv[0].description
    fixed = by_type(changes, "vuln_fixed")
    assert len(fixed) == 1 and fixed[0].old_value == "CVE-2023-38408"


def test_hosts_up_and_down() -> None:
    new = base()
    new.hosts = {k: v for k, v in new.hosts.items() if k != "203.0.113.11"}
    new.hosts["203.0.113.12"] = {"80/tcp": ServiceInfo("http", "nginx", "")}
    changes = diff_snapshots(base(), new)
    up = by_type(changes, "host_up")
    down = by_type(changes, "host_down")
    assert [c.asset for c in up] == ["203.0.113.12"]
    assert [c.asset for c in down] == ["203.0.113.11"]
    # порты нового хоста не дублируются отдельными изменениями
    assert by_type(changes, "port_opened") == []


def test_vuln_on_unscanned_host_is_not_reported_fixed() -> None:
    new = base()
    new.hosts = {"203.0.113.11": new.hosts["203.0.113.11"]}
    new.vulns = {}
    assert by_type(diff_snapshots(base(), new), "vuln_fixed") == []


def test_subdomains() -> None:
    new = base()
    new.subdomains = {"example.com": {"www.example.com", "vpn.example.com"}}
    changes = diff_snapshots(base(), new)
    assert [c.new_value for c in by_type(changes, "subdomain_new")] == ["vpn.example.com"]
    assert [c.old_value for c in by_type(changes, "subdomain_gone")] == ["mail.example.com"]
    assert all(c.asset == "example.com" and c.asset_type == "domain" for c in changes)


def test_subdomains_of_new_domain_are_not_reported() -> None:
    new = base()
    new.subdomains["example.org"] = {"a.example.org"}
    assert by_type(diff_snapshots(base(), new), "subdomain_new") == []


def test_other_findings() -> None:
    new = base()
    new.findings = {
        "tls|example.com|443/tcp|expired": FindingInfo("example.com", "domain", "critical", "Сертификат истёк"),
        "web|example.com|443/tcp|info": FindingInfo("example.com", "domain", "info", "Сервер: nginx"),
    }
    changes = diff_snapshots(base(), new)
    nf = by_type(changes, "finding_new")
    assert [c.new_value for c in nf] == ["Сертификат истёк"]  # info-находки не считаются изменениями
    resolved = by_type(changes, "finding_resolved")
    assert [c.old_value for c in resolved] == ["DMARC не настроен"]
