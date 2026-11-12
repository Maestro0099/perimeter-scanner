"""Модели данных."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role(str, enum.Enum):
    ADMIN = "admin"
    VIEWER = "viewer"


class TargetKind(str, enum.Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# --------------------------------------------------------------------------- пользователи


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=Role.VIEWER.value)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN.value


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")

    user: Mapped[User] = relationship()


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(64), default="system")
    ip: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)
    details: Mapped[str] = mapped_column(Text, default="")


# --------------------------------------------------------------------------- цели

target_tags = Table(
    "target_tags",
    Base.metadata,
    Column("target_id", ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

scan_targets = Table(
    "scan_targets",
    Base.metadata,
    Column("scan_id", ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True),
    Column("target_id", ForeignKey("targets.id", ondelete="CASCADE"), primary_key=True),
)


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    targets: Mapped[list[Target]] = relationship(back_populates="group")


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(10))
    value: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), nullable=True)
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(20), default="ui")  # ui | yaml | promoted
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64), default="")

    group: Mapped[Group | None] = relationship(back_populates="targets")
    tags: Mapped[list[Tag]] = relationship(secondary=target_tags, lazy="selectin")

    @property
    def tag_names(self) -> list[str]:
        return sorted(t.name for t in self.tags)


# --------------------------------------------------------------------------- сканы


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    profile: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(16), default=ScanStatus.QUEUED.value, index=True)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    stage: Mapped[str] = mapped_column(String(120), default="В очереди")
    trigger: Mapped[str] = mapped_column(String(16), default="manual")  # manual | schedule
    started_by: Mapped[str] = mapped_column(String(64), default="")
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id", ondelete="SET NULL"), nullable=True)
    timing: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")
    nmap_command: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    targets: Mapped[list[Target]] = relationship(secondary=scan_targets, lazy="selectin")
    group: Mapped[Group | None] = relationship()
    hosts: Mapped[list[Host]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    changes: Mapped[list[Change]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    @property
    def is_active(self) -> bool:
        return self.status in (ScanStatus.QUEUED.value, ScanStatus.RUNNING.value)

    @property
    def duration_seconds(self) -> int | None:
        if self.started_at and self.finished_at:
            return int((self.finished_at - self.started_at).total_seconds())
        return None


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    hostnames: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="up")
    os_name: Mapped[str] = mapped_column(String(255), default="")
    os_accuracy: Mapped[int] = mapped_column(Integer, default=0)
    host_scripts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    # дополнительные сведения: варианты ОС, uptime, расстояние, traceroute, типы устройств
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="hosts")
    ports: Mapped[list[Port]] = relationship(
        back_populates="host", cascade="all, delete-orphan", order_by="Port.port", lazy="selectin"
    )


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(String(8))
    port: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(24))
    reason: Mapped[str] = mapped_column(String(32), default="")
    service: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(128), default="")
    extrainfo: Mapped[str] = mapped_column(String(255), default="")
    tunnel: Mapped[str] = mapped_column(String(16), default="")
    cpe: Mapped[list[str]] = mapped_column(JSON, default=list)
    scripts: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)

    host: Mapped[Host] = relationship(back_populates="ports")

    @property
    def service_label(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    asset: Mapped[str] = mapped_column(String(255), index=True)  # IP или домен
    asset_type: Mapped[str] = mapped_column(String(10), default="ip")  # ip | domain
    category: Mapped[str] = mapped_column(String(20), index=True)  # port, vuln, dns, web, tls, whois
    severity: Mapped[str] = mapped_column(String(10), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(8), default="")
    cve: Mapped[str] = mapped_column(String(64), default="")
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    fingerprint: Mapped[str] = mapped_column(String(255), index=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Change(Base):
    __tablename__ = "changes"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    asset: Mapped[str] = mapped_column(String(255), index=True)
    asset_type: Mapped[str] = mapped_column(String(10), default="ip")
    change_type: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(10), default="info")
    description: Mapped[str] = mapped_column(Text)
    old_value: Mapped[str] = mapped_column(Text, default="")
    new_value: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped[Scan] = relationship(back_populates="changes")


class DomainResult(Base):
    __tablename__ = "domain_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[int | None] = mapped_column(ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    records: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    email_security: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    zone_transfer: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    whois: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    subdomains: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)


class WebResult(Base):
    __tablename__ = "web_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset: Mapped[str] = mapped_column(String(255), index=True)
    url: Mapped[str] = mapped_column(String(512))
    final_url: Mapped[str] = mapped_column(String(512), default="")
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    server: Mapped[str] = mapped_column(String(255), default="")
    redirects_to_https: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    security_headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    technologies: Mapped[list[str]] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")


class TlsResult(Base):
    __tablename__ = "tls_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset: Mapped[str] = mapped_column(String(255), index=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    certificate: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    chain_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    chain_error: Mapped[str] = mapped_column(Text, default="")
    protocols: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ciphers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")


# --------------------------------------------------------------------------- расписание и настройки


class Schedule(Base):
    __tablename__ = "schedules"
    __table_args__ = (UniqueConstraint("group_id", "profile", name="uq_schedule_group_profile"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"))
    profile: Mapped[str] = mapped_column(String(20))
    cron: Mapped[str] = mapped_column(String(100))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_run: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    group: Mapped[Group] = relationship()


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
