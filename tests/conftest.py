"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from soc.config import Settings
from soc.alert_reader import AlertReader

DATA_DIR = Path(__file__).parent / "data"


def make_settings(**overrides) -> Settings:
    """Build a test Settings object with sane defaults; override as needed."""
    base = dict(
        alerts_path=DATA_DIR / "sample_alerts.json",
        logs_dir=Path("/tmp/soc-test-logs"),
        state_dir=Path("/tmp/soc-test-state"),
        log_level="DEBUG",
        max_read_bytes=50 * 1024 * 1024,
        ai_api_key="",
        ai_base_url="https://routellm.abacus.ai/v1",
        ai_model="gpt-4o-mini",
        ai_timeout=60.0,
        ai_max_retries=3,
        ai_temperature=0.2,
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def sample_alerts_path() -> Path:
    return DATA_DIR / "sample_alerts.json"


@pytest.fixture
def reader(tmp_path: Path, sample_alerts_path: Path) -> AlertReader:
    cfg = make_settings(
        alerts_path=sample_alerts_path,
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
    )
    return AlertReader(cfg)
