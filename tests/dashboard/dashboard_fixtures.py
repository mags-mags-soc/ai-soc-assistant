"""Shared fixtures for the dashboard test suite.

Deliberately *not* named ``conftest.py``: the backend suite imports its own
``conftest`` module by name, and a second file with that name shadows it on
``sys.path``. Test modules import these fixtures explicitly instead.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.data.sample import SampleAlertDataSource  # noqa: E402
from soc.models import Alert  # noqa: E402

_REFERENCE_TIME = datetime(2026, 7, 31, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def reference_time() -> datetime:
    """Fixed anchor so timestamp assertions stay deterministic."""
    return _REFERENCE_TIME


@pytest.fixture()
def sample_source(reference_time: datetime) -> SampleAlertDataSource:
    """A sample source anchored to a fixed point in time."""
    return SampleAlertDataSource(reference_time=reference_time)


@pytest.fixture()
def sample_alerts(sample_source: SampleAlertDataSource) -> list[Alert]:
    """All alerts produced by the sample source."""
    return sample_source.fetch_alerts(limit=100)
