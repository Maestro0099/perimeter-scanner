"""Настройки приложения. Все секреты берутся только из переменных окружения / .env."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Сервер ---
    app_name: str = "Контроль периметра"
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    secret_key: str = Field(default="", description="Секрет для подписи токенов")
    data_dir: Path = Path("./data")
    database_url: str = ""
    cookie_secure: bool = True
    session_ttl_hours: int = 12
    trusted_proxies: str = "127.0.0.1"

    # --- Первичный администратор (создаётся при первом запуске, если пользователей нет) ---
    admin_username: str = "admin"
    admin_password: str = ""

    # --- Ограничение попыток входа ---
    login_max_attempts: int = 5
    login_window_minutes: int = 15
    login_lockout_minutes: int = 15

    # --- Область сканирования ---
    # Необязательный дополнительный ограничитель: список CIDR и доменных суффиксов
    # через запятую. Если задан, цели вне этой области добавить невозможно.
    allowed_scope: str = ""
    max_cidr_hosts: int = 4096
    targets_file: Path = Path("./targets.yaml")

    # --- nmap ---
    nmap_path: str = "nmap"
    nmap_privileged: bool = True
    nmap_timing: int = 3
    max_parallel_scans: int = 2
    scan_timeout_minutes: int = 360
    host_timeout_minutes: int = 60
    script_timeout_minutes: int = 5

    # --- Проверки доменов / веба ---
    dns_timeout: float = 5.0
    http_timeout: float = 10.0
    crtsh_enabled: bool = True
    subdomain_bruteforce: bool = True
    check_subdomains_web: bool = True
    max_subdomains_web: int = 50

    # --- Уведомления (секреты) ---
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_starttls: bool = True
    smtp_ssl: bool = False
    public_url: str = ""

    # --- Планировщик ---
    scheduler_enabled: bool = True
    timezone: str = "Europe/Moscow"

    @field_validator("nmap_timing")
    @classmethod
    def _timing(cls, v: int) -> int:
        if not 0 <= v <= 5:
            raise ValueError("NMAP_TIMING должен быть от 0 до 5")
        return v

    @field_validator("max_parallel_scans")
    @classmethod
    def _parallel(cls, v: int) -> int:
        return max(1, min(v, 16))

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_dir / 'perimeter.db').as_posix()}"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"

    @property
    def trusted_proxy_list(self) -> list[str]:
        return [p.strip() for p in self.trusted_proxies.split(",") if p.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
