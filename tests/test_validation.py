from __future__ import annotations

import pytest

from app.models import TargetKind
from app.validation import (
    ValidationError,
    normalize_domain,
    parse_scope,
    validate_cron,
    validate_in_scope,
    validate_password,
    validate_tags,
    validate_target,
    validate_timing,
)


@pytest.mark.parametrize(
    "raw,kind,value",
    [
        ("203.0.113.10", TargetKind.IP, "203.0.113.10"),
        (" 198.51.100.7 ", TargetKind.IP, "198.51.100.7"),
        ("198.51.100.0/28", TargetKind.CIDR, "198.51.100.0/28"),
        ("198.51.100.5/28", TargetKind.CIDR, "198.51.100.0/28"),
        ("203.0.113.9/32", TargetKind.IP, "203.0.113.9"),
        ("2001:db8::1", TargetKind.IP, "2001:db8::1"),
        ("2001:DB8:0::/124", TargetKind.CIDR, "2001:db8::/124"),
        ("Example.COM.", TargetKind.DOMAIN, "example.com"),
        ("mail.example.org", TargetKind.DOMAIN, "mail.example.org"),
        ("пример.рф", TargetKind.DOMAIN, "xn--e1afmkfd.xn--p1ai"),
        ("a-b.example.co.uk", TargetKind.DOMAIN, "a-b.example.co.uk"),
    ],
)
def test_valid_targets(raw: str, kind: TargetKind, value: str) -> None:
    t = validate_target(raw)
    assert t.kind == kind
    assert t.value == value


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "-sS",
        "--script=exploit",
        "-iL/etc/passwd",
        "example.com;rm -rf /",
        "example.com && id",
        "$(id).example.com",
        "`id`.example.com",
        "example.com|nc",
        "example .com",
        "http://example.com",
        "example.com/path",
        "user@example.com",
        "localhost",
        "exa_mple.com",
        "-example.com",
        "example-.com",
        "example.c",
        "256.1.1.1",
        "1.2.3",
        "10.0.0.0/33",
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "169.254.1.1",
        "::1",
        "a" * 64 + ".com",
        "*.example.com",
        "example.com\nfoo.com",
    ],
)
def test_invalid_targets(raw: str) -> None:
    with pytest.raises(ValidationError):
        validate_target(raw)


def test_cidr_size_limit() -> None:
    validate_target("10.0.0.0/20", max_cidr_hosts=4096)
    with pytest.raises(ValidationError):
        validate_target("10.0.0.0/19", max_cidr_hosts=4096)
    with pytest.raises(ValidationError):
        validate_target("0.0.0.0/0")


def test_non_string_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_target(123)  # type: ignore[arg-type]


def test_scope() -> None:
    scope = parse_scope("203.0.113.0/24, example.com")
    assert validate_in_scope("203.0.113.5", scope).value == "203.0.113.5"
    assert validate_in_scope("203.0.113.0/28", scope).kind == TargetKind.CIDR
    assert validate_in_scope("www.example.com", scope).value == "www.example.com"
    assert validate_in_scope("example.com", scope).value == "example.com"
    for bad in ("198.51.100.1", "203.0.112.0/23", "badexample.com", "example.com.evil.org"):
        with pytest.raises(ValidationError):
            validate_in_scope(bad, scope)


def test_empty_scope_allows_all() -> None:
    assert validate_in_scope("198.51.100.1", parse_scope("")).value == "198.51.100.1"


def test_normalize_domain_rejects_garbage() -> None:
    with pytest.raises(ValidationError):
        normalize_domain("exa mple.com")


def test_tags() -> None:
    assert validate_tags("Web, prod  web") == ["web", "prod"]
    assert validate_tags(["dmz"]) == ["dmz"]
    with pytest.raises(ValidationError):
        validate_tags("bad;tag")


def test_password_policy() -> None:
    assert validate_password("Correct-Horse-42")
    for bad in ("short1!", "alllowercaseletters", "ALLUPPER1234567"):
        with pytest.raises(ValidationError):
            validate_password(bad)


def test_cron_and_timing() -> None:
    assert validate_cron(" 0 3 * * 1-5 ") == "0 3 * * 1-5"
    for bad in ("* * * *", "0 3 * * mon;id", "0 3 * * $(id)"):
        with pytest.raises(ValidationError):
            validate_cron(bad)
    assert validate_timing("4") == 4
    for bad in ("6", "-1", "x"):
        with pytest.raises(ValidationError):
            validate_timing(bad)
