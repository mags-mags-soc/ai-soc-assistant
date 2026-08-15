"""Tests for the sample alert data source."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from dashboard_fixtures import reference_time, sample_alerts, sample_source  # noqa: F401

from dashboard.data.base import AlertDataSource, DataSourceError
from dashboard.data.factory import available_sources, build_data_source
from dashboard.data.sample import SampleAlertDataSource
from dashboard.settings import DashboardSettings
from soc.models import Alert
from soc.severity import Severity


def test_source_satisfies_protocol(sample_source: SampleAlertDataSource) -> None:
    assert isinstance(sample_source, AlertDataSource)
    assert sample_source.is_live is False
    assert sample_source.name


def test_alerts_are_backend_domain_objects(sample_alerts: list[Alert]) -> None:
    assert sample_alerts
    assert all(isinstance(alert, Alert) for alert in sample_alerts)
    assert all(isinstance(alert.severity, Severity) for alert in sample_alerts)


def test_severity_is_derived_from_rule_level(sample_alerts: list[Alert]) -> None:
    critical = [a for a in sample_alerts if a.severity is Severity.CRITICAL]
    assert critical, "sample data must contain at least one critical alert"
    assert all(alert.rule.level >= 13 for alert in critical)


def test_timestamps_are_anchored_to_reference_time(
    sample_alerts: list[Alert], reference_time: datetime
) -> None:
    assert all(alert.timestamp <= reference_time for alert in sample_alerts)
    oldest = min(alert.timestamp for alert in sample_alerts)
    assert reference_time - oldest < timedelta(hours=6)


def test_limit_is_respected(sample_source: SampleAlertDataSource) -> None:
    assert len(sample_source.fetch_alerts(limit=3)) == 3


def test_invalid_limit_raises(sample_source: SampleAlertDataSource) -> None:
    with pytest.raises(DataSourceError):
        sample_source.fetch_alerts(limit=0)


def test_output_is_deterministic(sample_source: SampleAlertDataSource) -> None:
    first = [alert.id for alert in sample_source.fetch_alerts(limit=100)]
    second = [alert.id for alert in sample_source.fetch_alerts(limit=100)]
    assert first == second


def test_mitre_mapping_is_populated(sample_alerts: list[Alert]) -> None:
    from dashboard.metrics import mitre_ids

    mapped = [alert for alert in sample_alerts if mitre_ids(alert)]
    assert len(mapped) >= 5


def test_factory_builds_registered_source() -> None:
    settings = DashboardSettings(source="sample")
    assert isinstance(build_data_source(settings), SampleAlertDataSource)
    assert "sample" in available_sources()


def test_factory_rejects_unknown_source() -> None:
    settings = DashboardSettings(source="does-not-exist")
    with pytest.raises(DataSourceError):
        build_data_source(settings)


def test_fetch_group_returns_the_alert_itself(
    sample_source: SampleAlertDataSource, sample_alerts: list[Alert]
) -> None:
    """Sample alerts are not deduplicated: a group is the alert on its own."""
    target = sample_alerts[2]
    assert [alert.id for alert in sample_source.fetch_group(target.id)] == [target.id]


def test_fetch_group_unknown_id_is_empty(sample_source: SampleAlertDataSource) -> None:
    assert sample_source.fetch_group("does-not-exist") == []
