"""Секретный ключ приложения и работа с токенами сессий."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from functools import lru_cache

from app.config import get_settings


@lru_cache
def secret_key() -> bytes:
    """SECRET_KEY из .env, либо сгенерированный и сохранённый в каталоге данных."""
    settings = get_settings()
    if settings.secret_key:
        return settings.secret_key.encode()
    path = settings.data_dir / ".secret_key"
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes().strip()
    key = secrets.token_hex(32).encode()
    path.write_bytes(key)
    path.chmod(0o600)
    return key


def new_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hmac.new(secret_key(), token.encode(), hashlib.sha256).hexdigest()
