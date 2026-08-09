"""Page header and the severity spine that summarises the current queue."""

from __future__ import annotations

from html import escape

import streamlit as st

from ..data.base import AlertDataSource
from ..metrics import DashboardMetrics
from ..theme import SEVERITY_ORDER, severity_label

_TIME_FORMAT = "%Y-%m-%d %H:%M:%S %Z"


def render_header(
    title: str,
    subtitle: str,
    source: AlertDataSource,
    metrics: DashboardMetrics,
) -> None:
    """Render the page title, subtitle and source metadata."""
    latest = (
        metrics.latest_alert_at.strftime(_TIME_FORMAT)
        if metrics.latest_alert_at
        else "no alerts yet"
    )
    mode = "live" if source.is_live else "sample"

    st.markdown(
        f"""<div class="soc-header">
  <div>
    <h1>{escape(title)}</h1>
    <div class="soc-subtitle">{escape(subtitle)}</div>
  </div>
  <div class="soc-meta">
    source <strong>{escape(source.name)}</strong> · mode <strong>{mode}</strong><br>
    newest alert <strong>{escape(latest)}</strong>
  </div>
</div>""",
        unsafe_allow_html=True,
    )


def render_severity_spine(metrics: DashboardMetrics) -> None:
    """Render a single bar showing how the queue splits across severity bands."""
    total = metrics.total_alerts
    if total == 0:
        return

    segments = []
    legend = []
    for level in SEVERITY_ORDER:
        count = metrics.count(level)
        if count == 0:
            continue
        width = count / total * 100
        segments.append(
            f'<span style="width:{width:.4f}%;background:{level.color};" '
            f'title="{severity_label(level)}: {count}"></span>'
        )
        legend.append(
            f'<span><i style="background:{level.color};"></i>'
            f"{severity_label(level)} {count}</span>"
        )

    st.markdown(
        f'<div class="soc-spine">{"".join(segments)}</div>'
        f'<div class="soc-spine-legend">{"".join(legend)}</div>',
        unsafe_allow_html=True,
    )
