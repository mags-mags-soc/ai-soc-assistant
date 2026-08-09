"""Overview page: metrics, queue composition and the newest detections."""

from __future__ import annotations

from typing import Final, Sequence

import streamlit as st

from soc.models import Alert

from ..components.alerts_table import render_alerts_table
from ..components.header import render_header, render_severity_spine
from ..components.metric_cards import render_metric_cards
from ..data.base import AlertDataSource
from ..metrics import compute_metrics, top_techniques
from ..navigation import PAGE_SUBTITLES, PAGE_TITLES, Page
from ..theme import PALETTE

RECENT_ALERT_COUNT: Final[int] = 10


def render(alerts: Sequence[Alert], source: AlertDataSource) -> None:
    """Render the overview page."""
    metrics = compute_metrics(alerts)

    render_header(
        title=PAGE_TITLES[Page.OVERVIEW],
        subtitle=PAGE_SUBTITLES[Page.OVERVIEW],
        source=source,
        metrics=metrics,
    )
    render_severity_spine(metrics)
    render_metric_cards(metrics)

    table_column, technique_column = st.columns([3, 1], gap="medium")

    with table_column:
        st.markdown(
            f'<div class="soc-section">Newest {RECENT_ALERT_COUNT} detections</div>',
            unsafe_allow_html=True,
        )
        render_alerts_table(list(alerts)[:RECENT_ALERT_COUNT], height=380)

    with technique_column:
        st.markdown('<div class="soc-section">Top MITRE techniques</div>', unsafe_allow_html=True)
        techniques = top_techniques(alerts)
        if not techniques:
            st.markdown(
                f'<div style="color:{PALETTE["text_muted"]};font-size:0.82rem;">'
                "No MITRE mappings on the loaded alerts.</div>",
                unsafe_allow_html=True,
            )
            return
        for technique, count in techniques:
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;'
                f"padding:7px 0;border-bottom:1px solid {PALETTE['border']};"
                f'font-family:ui-monospace,monospace;font-size:0.8rem;">'
                f"<span>{technique}</span>"
                f'<span style="color:{PALETTE["text_muted"]};">{count}</span></div>',
                unsafe_allow_html=True,
            )
