"""Tests for the analysis sources, selection rules and report builder."""

from __future__ import annotations

import pytest

from dashboard_fixtures import reference_time, sample_alerts, sample_source  # noqa: F401

from dashboard.analysis.analyzer_source import AnalyzerAnalysisSource
from dashboard.analysis.base import AnalysisError, AnalysisSource
from dashboard.analysis.disabled import DisabledAnalysisSource
from dashboard.analysis.factory import available_analysis_sources, build_analysis_source
from dashboard.selection import (
    SELECTED_ALERT_KEY,
    SELECTED_EVENT_KEY,
    find_alert,
    resolve_event,
    resolve_selection,
)
from dashboard.settings import DashboardSettings
from soc.ai.schemas import AIAnalysis, RiskLevel
from soc.models import Alert


def make_analysis(risk: RiskLevel = RiskLevel.HIGH) -> AIAnalysis:
    """Build a valid analysis object for tests."""
    return AIAnalysis(
        summary="Credential dumping attempt observed on the workstation.",
        risk_level=risk,
        risk_assessment="An unsigned binary accessed LSASS memory.",
        investigation_steps=["Isolate the host", "Collect the process tree"],
        false_positive_probability=0.15,
        mitre_commentary="Consistent with T1003.001.",
        confidence_score=88,
    )


class StubAnalyzer:
    """Records calls so caching behaviour can be asserted."""

    def __init__(self, result: AIAnalysis | None = None, fail: bool = False) -> None:
        self.result = result or make_analysis()
        self.fail = fail
        self.calls = 0

    def analyze(self, alert: Alert) -> AIAnalysis:
        self.calls += 1
        if self.fail:
            raise RuntimeError("provider unreachable")
        return self.result


# --- disabled source ---------------------------------------------------------

def test_disabled_source_satisfies_protocol() -> None:
    source = DisabledAnalysisSource()
    assert isinstance(source, AnalysisSource)
    assert source.is_available is False
    assert source.unavailable_reason


def test_disabled_source_has_no_cached_results(sample_alerts: list[Alert]) -> None:
    source = DisabledAnalysisSource()
    assert all(source.cached(alert) is None for alert in sample_alerts)


def test_disabled_source_refuses_to_analyse(sample_alerts: list[Alert]) -> None:
    with pytest.raises(AnalysisError):
        DisabledAnalysisSource().analyze(sample_alerts[0])


# --- analyzer source ---------------------------------------------------------

def test_analyzer_source_returns_validated_analysis(sample_alerts: list[Alert]) -> None:
    source = AnalyzerAnalysisSource(analyzer=StubAnalyzer())
    result = source.analyze(sample_alerts[0])
    assert isinstance(result, AIAnalysis)
    assert result.confidence_score == 88
    assert result.false_positive_percent == 15


def test_analyzer_source_caches_per_alert(sample_alerts: list[Alert]) -> None:
    stub = StubAnalyzer()
    source = AnalyzerAnalysisSource(analyzer=stub)
    alert = sample_alerts[0]

    assert source.cached(alert) is None
    source.analyze(alert)
    source.analyze(alert)

    assert stub.calls == 1
    assert source.cached(alert) is not None


def test_analyzer_source_wraps_provider_failures(sample_alerts: list[Alert]) -> None:
    source = AnalyzerAnalysisSource(analyzer=StubAnalyzer(fail=True))
    with pytest.raises(AnalysisError):
        source.analyze(sample_alerts[0])


def test_failed_analysis_is_not_cached(sample_alerts: list[Alert]) -> None:
    stub = StubAnalyzer(fail=True)
    source = AnalyzerAnalysisSource(analyzer=stub)
    with pytest.raises(AnalysisError):
        source.analyze(sample_alerts[0])
    assert source.cached(sample_alerts[0]) is None


# --- factory -----------------------------------------------------------------

def test_factory_defaults_to_disabled() -> None:
    source = build_analysis_source(DashboardSettings())
    assert isinstance(source, DisabledAnalysisSource)
    assert "disabled" in available_analysis_sources()
    assert "analyzer" in available_analysis_sources()


def test_factory_rejects_unknown_source() -> None:
    with pytest.raises(AnalysisError):
        build_analysis_source(DashboardSettings(analysis_source="nope"))


def test_settings_read_analysis_source_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASHBOARD_ANALYSIS_SOURCE", "ANALYZER")
    assert DashboardSettings.load().analysis_source == "analyzer"


# --- selection ---------------------------------------------------------------

def test_find_alert_matches_by_id(sample_alerts: list[Alert]) -> None:
    target = sample_alerts[2]
    assert find_alert(sample_alerts, target.id) is target


def test_find_alert_returns_none_for_unknown_id(sample_alerts: list[Alert]) -> None:
    assert find_alert(sample_alerts, "does-not-exist") is None
    assert find_alert(sample_alerts, None) is None


def test_resolve_selection_falls_back_to_newest(sample_alerts: list[Alert]) -> None:
    newest = max(sample_alerts, key=lambda alert: alert.timestamp)
    assert resolve_selection(sample_alerts, None) is newest
    assert resolve_selection(sample_alerts, "stale-id") is newest


def test_resolve_selection_keeps_a_valid_choice(sample_alerts: list[Alert]) -> None:
    target = sample_alerts[3]
    assert resolve_selection(sample_alerts, target.id) is target


def test_resolve_selection_on_empty_input() -> None:
    assert resolve_selection([], None) is None


def test_session_key_is_stable() -> None:
    assert SELECTED_ALERT_KEY == "selected_alert_id"


# --- report ------------------------------------------------------------------

def test_report_contains_the_alert_id(sample_alerts: list[Alert]) -> None:
    from dashboard.components.report_viewer import build_report

    alert = sample_alerts[0]
    report = build_report(alert, make_analysis())
    assert alert.id in report
    assert report.lstrip().startswith("#")


def test_resolve_event_falls_back_to_newest(sample_alerts: list[Alert]) -> None:
    newest = max(sample_alerts, key=lambda alert: alert.timestamp)
    assert resolve_event(sample_alerts, None) is newest
    assert resolve_event(sample_alerts, "stale-id") is newest


def test_resolve_event_keeps_a_valid_choice(sample_alerts: list[Alert]) -> None:
    target = sample_alerts[4]
    assert resolve_event(sample_alerts, target.id) is target


def test_resolve_event_on_empty_input() -> None:
    assert resolve_event([], None) is None


def test_event_session_key_is_stable() -> None:
    assert SELECTED_EVENT_KEY == "selected_event_id"
    assert SELECTED_EVENT_KEY != SELECTED_ALERT_KEY
