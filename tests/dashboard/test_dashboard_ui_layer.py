"""Tests for the presentation helpers: theme tokens, table shape, settings."""

from __future__ import annotations

import pytest

from dashboard_fixtures import reference_time, sample_alerts, sample_source  # noqa: F401

from dashboard.navigation import PAGE_SUBTITLES, PAGE_TITLES, Page
from dashboard.settings import DEFAULT_ALERT_LIMIT, DashboardSettings
from dashboard.tables import COLUMNS, alerts_to_frame
from dashboard.theme import SEVERITY_ORDER, build_css, severity_color, severity_label
from soc.models import Alert
from soc.severity import Severity


def test_severity_order_covers_every_band() -> None:
    assert set(SEVERITY_ORDER) == set(Severity)
    ranks = [level.rank for level in SEVERITY_ORDER]
    assert ranks == sorted(ranks, reverse=True)


def test_colors_come_from_the_backend() -> None:
    for level in Severity:
        assert severity_color(level) == level.color
        assert severity_label(level) == level.value.upper()


def test_css_declares_every_severity_variable() -> None:
    css = build_css()
    assert css.startswith("<style>") and css.rstrip().endswith("</style>")
    for level in Severity:
        assert f"--sev-{level.value}: {level.color};" in css


def test_table_columns_and_order(sample_alerts: list[Alert]) -> None:
    frame = alerts_to_frame(sample_alerts)
    assert list(frame.columns) == list(COLUMNS)
    assert len(frame) == len(sample_alerts)
    assert list(frame["Time"]) == sorted(frame["Time"], reverse=True)


def test_table_handles_empty_input() -> None:
    frame = alerts_to_frame([])
    assert frame.empty
    assert list(frame.columns) == list(COLUMNS)


def test_table_severity_labels_are_uppercase(sample_alerts: list[Alert]) -> None:
    frame = alerts_to_frame(sample_alerts)
    assert set(frame["Severity"]) <= {level.value.upper() for level in Severity}


def test_every_page_has_a_title_and_subtitle() -> None:
    for page in Page:
        assert PAGE_TITLES[page]
        assert PAGE_SUBTITLES[page]


def test_settings_defaults() -> None:
    settings = DashboardSettings()
    assert settings.source == "sample"
    assert settings.alert_limit == DEFAULT_ALERT_LIMIT


def test_settings_reject_out_of_range_limit() -> None:
    with pytest.raises(ValueError):
        DashboardSettings(alert_limit=1)


def test_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASHBOARD_ALERT_LIMIT", "120")
    monkeypatch.setenv("DASHBOARD_SOURCE", "SAMPLE")
    settings = DashboardSettings.load()
    assert settings.alert_limit == 120
    assert settings.source == "sample"


def test_settings_reject_non_integer_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASHBOARD_ALERT_LIMIT", "many")
    with pytest.raises(ValueError):
        DashboardSettings.load()
