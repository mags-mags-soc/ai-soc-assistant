"""Tests for the dashboard filter layer."""

from __future__ import annotations

from dashboard_fixtures import reference_time, sample_alerts, sample_source  # noqa: F401

from dashboard.filters import AlertFilters, apply_filters
from soc.models import Alert
from soc.severity import Severity


def test_empty_filters_are_inactive() -> None:
    assert AlertFilters().active is False


def test_any_selection_makes_filters_active() -> None:
    assert AlertFilters(term="lsass").active is True
    assert AlertFilters(agent="win").active is True
    assert AlertFilters(mitre="T1003").active is True
    assert AlertFilters(min_severity=Severity.HIGH).active is True


def test_whitespace_only_input_stays_inactive() -> None:
    assert AlertFilters(term="   ", agent="  ").active is False


def test_inactive_filters_return_everything(sample_alerts: list[Alert]) -> None:
    assert apply_filters(sample_alerts, AlertFilters()) == list(sample_alerts)
    assert apply_filters(sample_alerts, None) == list(sample_alerts)


def test_severity_filter_uses_backend_ranks(sample_alerts: list[Alert]) -> None:
    result = apply_filters(sample_alerts, AlertFilters(min_severity=Severity.HIGH))
    assert result
    assert all(a.severity.rank >= Severity.HIGH.rank for a in result)
    assert len(result) < len(sample_alerts)


def test_agent_filter_is_case_insensitive(sample_alerts: list[Alert]) -> None:
    result = apply_filters(sample_alerts, AlertFilters(agent="WIN10-WS01"))
    assert result
    assert all(a.agent.name == "win10-ws01" for a in result)


def test_mitre_filter_matches_technique_text(sample_alerts: list[Alert]) -> None:
    result = apply_filters(sample_alerts, AlertFilters(mitre="T1003"))
    assert result
    assert all(any("T1003" in i for i in a.mitre.ids) for a in result)


def test_search_matches_the_description(sample_alerts: list[Alert]) -> None:
    result = apply_filters(sample_alerts, AlertFilters(term="lsass"))
    assert result
    assert all("lsass" in a.rule.description.lower()
               or "lsass" in a.full_log.lower() for a in result)


def test_filters_combine(sample_alerts: list[Alert]) -> None:
    """Each filter narrows the result of the previous one."""
    wide = apply_filters(sample_alerts, AlertFilters(agent="win10-ws01"))
    narrow = apply_filters(
        sample_alerts, AlertFilters(agent="win10-ws01", min_severity=Severity.CRITICAL)
    )
    assert len(narrow) <= len(wide)
    assert set(a.id for a in narrow) <= set(a.id for a in wide)


def test_no_match_returns_empty(sample_alerts: list[Alert]) -> None:
    assert apply_filters(sample_alerts, AlertFilters(term="zzz-nope")) == []


def test_order_is_preserved(sample_alerts: list[Alert]) -> None:
    """Filtering must not reorder; the views rely on newest-first input."""
    result = apply_filters(sample_alerts, AlertFilters(min_severity=Severity.MEDIUM))
    ids = [a.id for a in result]
    expected = [a.id for a in sample_alerts if a.id in set(ids)]
    assert ids == expected
