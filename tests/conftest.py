"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from soc.config import Settings
from soc.alert_reader import AlertReader

DATA_DIR = Path(__file__).parent / "data"


@pytest.fixture
def sample_alerts_path() -> Path:
    return DATA_DIR / "sample_alerts.json"


@pytest.fixture
def reader(tmp_path: Path, sample_alerts_path: Path) -> AlertReader:
    cfg = Settings(
        alerts_path=sample_alerts_path,
        logs_dir=tmp_path / "logs",
        state_dir=tmp_path / "state",
        log_level="DEBUG",
        max_read_bytes=50 * 1024 * 1024,
    )
    return AlertReader(cfg)
