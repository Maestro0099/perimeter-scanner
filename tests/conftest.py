from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = ROOT / "tests" / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    """Каждый тест — с отдельным каталогом данных и без .env."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "test-secret")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("SCHEDULER_ENABLED", "false")
    monkeypatch.setenv("TARGETS_FILE", str(tmp_path / "none.yaml"))
    monkeypatch.setenv("ALLOWED_SCOPE", "")
    from app.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
