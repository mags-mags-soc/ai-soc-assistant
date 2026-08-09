"""Incident report viewer.

Renders the Markdown report produced by ``soc.report.markdown_report`` and
offers it as a download. A report needs both an alert and its analysis, so the
panel shows a prompt until the alert has been analysed.
"""

from __future__ import annotations

import streamlit as st

from soc.ai.schemas import AIAnalysis
from soc.models import Alert

from ..analysis.base import AnalysisSource


def build_report(alert: Alert, analysis: AIAnalysis) -> str:
    """Return the Markdown incident report for an analysed alert."""
    from soc.report.markdown_report import build_markdown_report

    return build_markdown_report(alert, analysis)


def render_report_viewer(alert: Alert, source: AnalysisSource) -> None:
    """Render the incident report for the selected alert, if it can be built."""
    st.markdown('<div class="soc-section">Incident report</div>', unsafe_allow_html=True)

    analysis = source.cached(alert)
    if analysis is None:
        st.info("An incident report needs an AI analysis. Analyse this alert first.")
        return

    try:
        report = build_report(alert, analysis)
    except Exception as exc:  # noqa: BLE001 - report errors are shown, not raised
        st.error(f"The report could not be generated: {exc}")
        return

    st.download_button(
        "Download report",
        data=report,
        file_name=f"incident_{alert.id}.md",
        mime="text/markdown",
        key=f"download-{alert.id}",
    )
    with st.expander("Preview", expanded=True):
        st.markdown(report)
