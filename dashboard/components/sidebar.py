"""Sidebar: navigation and the controls that drive every view."""

from __future__ import annotations

from dataclasses import dataclass

import streamlit as st

from ..settings import MAX_ALERT_LIMIT, MIN_ALERT_LIMIT, DashboardSettings
from ..theme import PALETTE
from ..navigation import PAGE_TITLES, Page


@dataclass(frozen=True)
class SidebarState:
    """User selections that the page renderers depend on."""

    page: Page
    alert_limit: int


def render_sidebar(settings: DashboardSettings) -> SidebarState:
    """Render the sidebar and return the current selections."""
    with st.sidebar:
        st.markdown(
            f'<div style="font-weight:600;letter-spacing:-0.01em;font-size:1.02rem;">'
            f"AI SOC Assistant</div>"
            f'<div style="color:{PALETTE["text_muted"]};font-size:0.75rem;'
            f'margin-bottom:18px;">Blue team console</div>',
            unsafe_allow_html=True,
        )

        selected = st.radio(
            "View",
            options=list(Page),
            format_func=lambda page: PAGE_TITLES[page],
            label_visibility="collapsed",
        )

        st.divider()

        alert_limit = st.slider(
            "Alerts to load",
            min_value=MIN_ALERT_LIMIT,
            max_value=MAX_ALERT_LIMIT,
            value=settings.alert_limit,
            step=10,
            help="Maximum number of alerts read from the data source.",
        )

        if st.button("Reload alerts", width="stretch"):
            st.rerun()

    return SidebarState(page=selected, alert_limit=alert_limit)
