"""Строгая валидация целей сканирования и прочих входных данных.

Любое значение, которое потенциально попадает в аргументы nmap, проходит через
эти функции. Значения нормализуются (IP — в каноническую форму, домены — в
нижний регистр и IDNA/punycode), а всё, что похоже на опции командной строки
или содержит посторонние символы, отклоняется.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from app.models import TargetKind

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_NAME_RE = re.compile(r"^[\w .,()+\-«»\"']{1,100}$", re.UNICODE)
_TAG_RE = re.compile(r"^[\w.\-]{1,50}$", re.UNICODE)
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,64}$")
_CRON_FIELD_RE = re.compile(r"^[\d*/,\-]+$")


class ValidationError(ValueError):
    """Ошибка валидации с сообщением для пользователя (на русском)."""


@dataclass(frozen=True)
class ValidatedTarget:
    kind: TargetKind
    value: str


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower().rstrip(".")
    if not value:
        raise ValidationError("Пустое доменное имя")
    if any(c in value for c in "/:@ \t\r\n\\;|&$`'\"<>*?"):
        raise ValidationError(f"Недопустимые символы в доменном имени: {raw!r}")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"Некорректное доменное имя: {raw!r}") from exc
    if len(value) > 253:
        raise ValidationError("Доменное имя длиннее 253 символов")
    labels = value.split(".")
    if len(labels) < 2:
        raise ValidationError("Укажите полное доменное имя (например, example.com)")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValidationError(f"Некорректная часть доменного имени: {label!r}")
    if not _TLD_RE.match(labels[-1]):
        raise ValidationError(f"Некорректная доменная зона: {labels[-1]!r}")
    return value


def is_valid_domain(raw: str) -> bool:
    try:
        normalize_domain(raw)
    except ValidationError:
        return False
    return True


def validate_target(raw: str, max_cidr_hosts: int = 4096) -> ValidatedTarget:
    """Определяет тип цели (IP, CIDR, домен) и возвращает нормализованное значение."""
    if not isinstance(raw, str):
        raise ValidationError("Цель должна быть строкой")
    value = raw.strip()
    if not value:
        raise ValidationError("Пустое значение цели")
    if len(value) > 255:
        raise ValidationError("Слишком длинное значение цели")
    if value.startswith("-"):
        raise ValidationError("Значение цели не может начинаться с «-»")
    if any(c.isspace() for c in value):
        raise ValidationError("Значение цели не должно содержать пробелов")

    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValidationError(f"Некорректная подсеть CIDR: {value!r}") from exc
        if net.num_addresses > max_cidr_hosts:
            raise ValidationError(
                f"Подсеть {net} слишком велика ({net.num_addresses} адресов, максимум {max_cidr_hosts})"
            )
        _reject_special(net.network_address)
        if net.num_addresses == 1:
            return ValidatedTarget(TargetKind.IP, str(net.network_address))
        return ValidatedTarget(TargetKind.CIDR, str(net))

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        _reject_special(ip)
        return ValidatedTarget(TargetKind.IP, str(ip))

    if re.fullmatch(r"[\d.]+", value):
        raise ValidationError(f"Некорректный IP-адрес: {value!r}")
    return ValidatedTarget(TargetKind.DOMAIN, normalize_domain(value))


def _reject_special(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_reserved or ip.is_link_local:
        raise ValidationError(f"Адрес {ip} не может быть целью сканирования (служебный диапазон)")


# --------------------------------------------------------------------------- область (scope)


@dataclass(frozen=True)
class Scope:
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    domains: tuple[str, ...]

    @property
    def is_empty(self) -> bool:
        return not self.networks and not self.domains

    def contains(self, target: ValidatedTarget) -> bool:
        if self.is_empty:
            return True
        if target.kind == TargetKind.DOMAIN:
            return any(target.value == d or target.value.endswith("." + d) for d in self.domains)
        net = ipaddress.ip_network(target.value, strict=False)
        return any(net.version == s.version and net.subnet_of(s) for s in self.networks)  # type: ignore[arg-type]


def parse_scope(raw: str) -> Scope:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    domains: list[str] = []
    for item in (x.strip() for x in raw.split(",")):
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
            continue
        except ValueError:
            pass
        domains.append(normalize_domain(item.lstrip("*.")))
    return Scope(tuple(nets), tuple(domains))


def validate_in_scope(raw: str, scope: Scope, max_cidr_hosts: int = 4096) -> ValidatedTarget:
    target = validate_target(raw, max_cidr_hosts)
    if not scope.contains(target):
        raise ValidationError(f"Цель {target.value} вне разрешённой области (ALLOWED_SCOPE)")
    return target


def is_subdomain_of(name: str, parent: str) -> bool:
    return name == parent or name.endswith("." + parent)


# --------------------------------------------------------------------------- прочие поля


def validate_name(raw: str, field: str = "Название") -> str:
    value = raw.strip()
    if not _NAME_RE.match(value):
        raise ValidationError(f"{field}: допустимы буквы, цифры, пробел и . , ( ) + - (до 100 символов)")
    return value


def validate_tags(raw: str | list[str]) -> list[str]:
    items = raw if isinstance(raw, list) else re.split(r"[,\s]+", raw)
    tags: list[str] = []
    for item in items:
        tag = str(item).strip().lower()
        if not tag:
            continue
        if not _TAG_RE.match(tag):
            raise ValidationError(f"Некорректный тег: {tag!r}")
        if tag not in tags:
            tags.append(tag)
    if len(tags) > 20:
        raise ValidationError("Не более 20 тегов на цель")
    return tags


def validate_description(raw: str, max_len: int = 1000) -> str:
    value = raw.strip()
    if len(value) > max_len:
        raise ValidationError(f"Описание длиннее {max_len} символов")
    return value


def validate_username(raw: str) -> str:
    value = raw.strip()
    if not _USERNAME_RE.match(value):
        raise ValidationError("Логин: 3–64 символа, латиница, цифры, «_», «.», «-»")
    return value


def validate_password(raw: str) -> str:
    if len(raw) < 12:
        raise ValidationError("Пароль должен быть не короче 12 символов")
    if len(raw) > 256:
        raise ValidationError("Слишком длинный пароль")
    classes = sum(
        bool(re.search(p, raw)) for p in (r"[a-zа-я]", r"[A-ZА-Я]", r"\d", r"[^\w\s]|_")
    )
    if classes < 3:
        raise ValidationError("Пароль должен содержать минимум 3 типа символов: строчные, заглавные, цифры, спецсимволы")
    return raw


def validate_cron(raw: str) -> str:
    fields = raw.strip().split()
    if len(fields) != 5:
        raise ValidationError("Расписание: 5 полей cron (минута час день месяц день_недели)")
    for f in fields:
        if not _CRON_FIELD_RE.match(f):
            raise ValidationError(f"Недопустимое поле cron: {f!r}")
    return " ".join(fields)


def validate_timing(value: int | str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Скорость (-T) должна быть числом от 0 до 5") from exc
    if not 0 <= v <= 5:
        raise ValidationError("Скорость (-T) должна быть числом от 0 до 5")
    return v
