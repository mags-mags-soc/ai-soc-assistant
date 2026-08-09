"""AI analysis panel.

Renders a validated :class:`soc.ai.schemas.AIAnalysis` when one exists, and an
explicit empty state when no provider is configured. It never fabricates a
result.
"""

from __future__ import annotations

from html import escape

import streamlit as st

from soc.ai.schemas import AIAnalysis
from soc.models import Alert
from soc.severity import Severity

from ..analysis.base import AnalysisError, AnalysisSource
from ..theme import PALETTE


def _risk_color(analysis: AIAnalysis) -> str:
    """Map the AI risk level onto the backend severity palette."""
    try:
        return Severity(analysis.risk_level.value).color
    except ValueError:  # pragma: no cover - risk levels mirror Severity
        return PALETTE["accent"]


def render_ai_analysis(alert: Alert, source: AnalysisSource) -> None:
    """Render the analysis panel for one alert."""
    st.markdown('<div class="soc-section">AI analysis</div>', unsafe_allow_html=True)

    analysis = source.cached(alert)

    if analysis is None:
        if not source.is_available:
            st.info(f"This alert has not been analysed. {source.unavailable_reason}")
            return
        st.markdown(
            f'<div style="color:{PALETTE["text_muted"]};font-size:0.85rem;'
            'margin-bottom:10px;">This alert has not been analysed yet.</div>',
            unsafe_allow_html=True,
        )
        if st.button("Analyse this alert", key=f"analyse-{alert.id}"):
            try:
                with st.spinner("Calling the AI engine..."):
                    source.analyze(alert)
            except AnalysisError as exc:
                st.error(str(exc))
                return
            st.rerun()
        return

    render_analysis_body(analysis)

    if source.is_available and st.button("Re-analyse", key=f"reanalyse-{alert.id}"):
        source.forget(alert)
        st.rerun()


def render_analysis_body(analysis: AIAnalysis) -> None:
    """Render the fields of a completed analysis."""
    color = _risk_color(analysis)

    st.markdown(
        f'<div class="soc-cards" style="grid-template-columns:repeat(3,1fr);">'
        f'<div class="soc-card" style="--rail:{color};">'
        f'<div class="soc-card-label">Risk level</div>'
        f'<div class="soc-card-value" style="color:{color};">'
        f"{escape(analysis.risk_level.value.upper())}</div></div>"
        f'<div class="soc-card">'
        f'<div class="soc-card-label">Confidence</div>'
        f'<div class="soc-card-value">{analysis.confidence_score}</div>'
        f'<div class="soc-card-note">out of 100</div></div>'
        f'<div class="soc-card">'
        f'<div class="soc-card-label">False positive</div>'
        f'<div class="soc-card-value">{analysis.false_positive_percent}%</div>'
        f'<div class="soc-card-note">estimated probability</div></div>'
        f"</div>",
        unsafe_allow_html=True,
    )

    st.markdown("**Summary**")
    st.write(analysis.summary)

    st.markdown("**Risk assessment**")
    st.write(analysis.risk_assessment)

    st.markdown("**Investigation steps**")
    for index, step in enumerate(analysis.investigation_steps, start=1):
        st.markdown(f"{index}. {step}")

    if analysis.mitre_commentary:
        st.markdown("**MITRE commentary**")
        st.write(analysis.mitre_commentary)
