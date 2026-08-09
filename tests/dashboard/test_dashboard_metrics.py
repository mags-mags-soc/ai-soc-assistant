"""Tests for the dashboard metric aggregations."""

from __future__ import annotations

import pytest

from dashboard_fixtures import reference_time, sample_alerts, sample_source  # noqa: F401

from dashboard.metrics import compute_metrics, mitre_ids, sort_alerts, top_techniques
from soc.models import Alert
from soc.severity import Severity


def test_empty_input_produces_zeroed_metrics() -> None:
    metrics = compute_metrics([])
    assert metrics.total_alerts == 0
    assert metrics.unique_agents == 0
    assert metrics.unique_rules == 0
    assert metrics.mitre_technique_count == 0
    assert metrics.latest_alert_at is None
    assert metrics.actionable_alerts == 0
    assert all(metrics.count(level) == 0 for level in Severity)


def test_totals_match_severity_breakdown(sample_alerts: list[Alert]) -> None:
    metrics = compute_metrics(sample_alerts)
    assert metrics.total_alerts == len(sample_alerts)
    assert sum(metrics.by_severity.values()) == metrics.total_alerts


def test_actionable_alerts_counts_high_and_critical(sample_alerts: list[Alert]) -> None:
    metrics = compute_metrics(sample_alerts)
    expected = sum(
        1 for alert in sample_alerts
        if alert.severity in (Severity.HIGH, Severity.CRITICAL)
    )
    assert metrics.actionable_alerts == expected


def test_unique_agents_and_rules(sample_alerts: list[Alert]) -> None:
    metrics = compute_metrics(sample_alerts)
    assert metrics.unique_agents == len({alert.agent.name for alert in sample_alerts})
    assert metrics.unique_rules == len({alert.rule.id for alert in sample_alerts})


def test_latest_alert_is_the_newest_timestamp(sample_alerts: list[Alert]) -> None:
    metrics = compute_metrics(sample_alerts)
    assert metrics.latest_alert_at == max(alert.timestamp for alert in sample_alerts)


def test_sort_alerts_is_newest_first(sample_alerts: list[Alert]) -> None:
    ordered = sort_alerts(sample_alerts)
    timestamps = [alert.timestamp for alert in ordered]
    assert timestamps == sorted(timestamps, reverse=True)
    assert len(ordered) == len(sample_alerts)


def test_sort_alerts_does_not_mutate_input(sample_alerts: list[Alert]) -> None:
    original = list(sample_alerts)
    sort_alerts(sample_alerts)
    assert sample_alerts == original


def test_top_techniques_is_ordered_by_frequency(sample_alerts: list[Alert]) -> None:
    result = top_techniques(sample_alerts, limit=3)
    assert result
    counts = [count for _, count in result]
    assert counts == sorted(counts, reverse=True)
    assert all(technique in {t for a in sample_alerts for t in mitre_ids(a)} for technique, _ in result)


def test_top_techniques_rejects_invalid_limit(sample_alerts: list[Alert]) -> None:
    with pytest.raises(ValueError):
        top_techniques(sample_alerts, limit=0)


def test_top_techniques_on_empty_input() -> None:
    assert top_techniques([]) == []
