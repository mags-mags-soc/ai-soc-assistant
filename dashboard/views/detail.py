"""Alert detail page: details, AI analysis and the incident report."""

from __future__ import annotations

from typing import Sequence

import streamlit as st

from soc.models import Alert

from ..analysis.base import AnalysisSource
from ..components.ai_analysis import render_ai_analysis
from ..components.alert_details import render_alert_details
from ..components.header import render_header
from ..components.report_viewer import render_report_viewer
from ..data.base import AlertDataSource
from ..metrics import compute_metrics, sort_alerts
from ..navigation import PAGE_SUBTITLES, PAGE_TITLES, Page
from ..selection import SELECTED_ALERT_KEY, resolve_selection
from ..theme import severity_label


def _option_label(alert: Alert) -> str:
    """Return the picker label for an alert."""
    stamp = alert.timestamp.strftime("%H:%M:%S")
    return f"{stamp} · {severity_label(alert.severity)} · {alert.rule.description}"


def render(
    alerts: Sequence[Alert],
    source: AlertDataSource,
    analysis_source: AnalysisSource,
) -> None:
    """Render the alert detail page."""
    render_header(
        title=PAGE_TITLES[Page.DETAIL],
        subtitle=PAGE_SUBTITLES[Page.DETAIL],
        source=source,
        metrics=compute_metrics(alerts),
    )

    if not alerts:
        st.info("No alerts are loaded. Raise the alert limit in the sidebar.")
        return

    ordered = sort_alerts(alerts)
    by_id = {alert.id: alert for alert in ordered}
    ids = list(by_id)

    # Select on the stable alert id: the sample source re-stamps timestamps on
    # every rerun, so selecting on Alert objects would reset the widget.
    previous = st.session_state.get(SELECTED_ALERT_KEY)
    index = ids.index(previous) if previous in by_id else 0

    chosen_id = st.selectbox(
        "Alert",
        options=ids,
        index=index,
        format_func=lambda alert_id: _option_label(by_id[alert_id]),
        label_visibility="collapsed",
        key="alert_picker",
    )
    st.session_state[SELECTED_ALERT_KEY] = chosen_id
    chosen = by_id[chosen_id]

    details_column, analysis_column = st.columns([1, 1], gap="medium")
    with details_column:
        render_alert_details(chosen)
    with analysis_column:
        render_ai_analysis(chosen, analysis_source)

    render_report_viewer(chosen, analysis_source)
