"""Streamlit entrypoint for the AI SOC Assistant dashboard.

Run from the repository root::

    streamlit run dashboard/app.py

The dashboard is read-only: it renders whatever the configured data source
returns and never mutates backend state.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Allow `streamlit run dashboard/app.py`, which puts dashboard/ (not the
# repository root) on sys.path.
if __package__ in (None, ""):  # pragma: no cover - runtime bootstrap
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st

from dashboard.components.sidebar import render_sidebar
from dashboard.data.base import DataSourceError
from dashboard.data.factory import build_data_source
from dashboard.settings import DashboardSettings
from dashboard.theme import build_css
from dashboard.views import PAGE_RENDERERS

log = logging.getLogger(__name__)


def main() -> None:
    """Configure the page, resolve the data source and render the active view."""
    settings = DashboardSettings.load()

    st.set_page_config(
        page_title=settings.page_title,
        page_icon="🛡",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(build_css(), unsafe_allow_html=True)

    state = render_sidebar(settings)

    try:
        source = build_data_source(settings)
        alerts = source.fetch_alerts(limit=state.alert_limit)
    except DataSourceError as exc:
        log.error("data source failure: %s", exc)
        st.error(f"Alerts could not be loaded. {exc}")
        return

    PAGE_RENDERERS[state.page](alerts, source)


if __name__ == "__main__":
    main()
