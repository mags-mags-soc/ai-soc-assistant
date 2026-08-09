"""Metric cards summarising the current alert queue."""

from __future__ import annotations

from dataclasses import dataclass
from html import escape

import streamlit as st

from ..metrics import DashboardMetrics
from ..theme import PALETTE
from soc.severity import Severity


@dataclass(frozen=True)
class MetricCard:
    """A single card: label, value, supporting note and rail color."""

    label: str
    value: str
    note: str
    rail: str


def build_cards(metrics: DashboardMetrics) -> list[MetricCard]:
    """Derive the cards shown above the alert table."""
    total = metrics.total_alerts
    actionable = metrics.actionable_alerts
    share = f"{actionable / total * 100:.0f}% of queue" if total else "queue empty"

    return [
        MetricCard(
            label="Alerts in view",
            value=str(total),
            note=f"{metrics.unique_rules} distinct rules",
            rail=PALETTE["accent"],
        ),
        MetricCard(
            label="Critical",
            value=str(metrics.count(Severity.CRITICAL)),
            note="level 13 and above",
            rail=Severity.CRITICAL.color,
        ),
        MetricCard(
            label="High",
            value=str(metrics.count(Severity.HIGH)),
            note="level 11-12",
            rail=Severity.HIGH.color,
        ),
        MetricCard(
            label="Needs triage",
            value=str(actionable),
            note=share,
            rail=Severity.MEDIUM.color,
        ),
        MetricCard(
            label="Agents reporting",
            value=str(metrics.unique_agents),
            note=f"{metrics.mitre_technique_count} MITRE techniques",
            rail=PALETTE["border"],
        ),
    ]


def render_metric_cards(metrics: DashboardMetrics) -> None:
    """Render the metric cards as a responsive CSS grid."""
    cards = "".join(
        f'<div class="soc-card" style="--rail:{card.rail};">'
        f'<div class="soc-card-label">{escape(card.label)}</div>'
        f'<div class="soc-card-value">{escape(card.value)}</div>'
        f'<div class="soc-card-note">{escape(card.note)}</div>'
        f"</div>"
        for card in build_cards(metrics)
    )
    st.markdown(f'<div class="soc-cards">{cards}</div>', unsafe_allow_html=True)
