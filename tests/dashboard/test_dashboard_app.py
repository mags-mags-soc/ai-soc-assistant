"""Headless smoke tests for the Streamlit app.

Uses Streamlit's own ``AppTest`` runner: the real script is executed, so an
import error, a bad component call or a crashing view fails the build. Skipped
automatically when Streamlit is not installed, keeping the backend-only test
run green.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit", reason="dashboard extras not installed")

from streamlit.testing.v1 import AppTest  # noqa: E402

APP_PATH = Path(__file__).resolve().parents[2] / "dashboard" / "app.py"


@pytest.fixture()
def app() -> AppTest:
    """Run the dashboard once and return the resulting app state."""
    return AppTest.from_file(str(APP_PATH), default_timeout=30).run()


def test_app_runs_without_exceptions(app: AppTest) -> None:
    assert not app.exception
    assert not app.error


def test_navigation_lists_every_page(app: AppTest) -> None:
    from dashboard.navigation import PAGE_TITLES

    assert app.radio[0].options == list(PAGE_TITLES.values())


def test_overview_renders_an_alerts_table(app: AppTest) -> None:
    assert len(app.dataframe) == 1


def test_alert_limit_slider_matches_settings(app: AppTest) -> None:
    from dashboard.settings import DEFAULT_ALERT_LIMIT

    assert app.slider[0].value == DEFAULT_ALERT_LIMIT


def test_switching_to_the_alert_queue_page(app: AppTest) -> None:
    from dashboard.navigation import PAGE_TITLES, Page

    result = app.radio[0].set_value(PAGE_TITLES[Page.ALERTS]).run()
    assert not result.exception
    assert len(result.dataframe) == 1
