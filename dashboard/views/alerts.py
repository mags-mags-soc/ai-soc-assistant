"""Alert queue page: the full table for the loaded window."""

from __future__ import annotations

from typing import Sequence

from soc.models import Alert

from ..components.alerts_table import render_alerts_table
from ..components.header import render_header, render_severity_spine
from ..data.base import AlertDataSource
from ..metrics import compute_metrics
from ..navigation import PAGE_SUBTITLES, PAGE_TITLES, Page


def render(
    alerts: Sequence[Alert],
    source: AlertDataSource,
    analysis_source: object | None = None,
) -> None:
    """Render the alert queue page."""
    metrics = compute_metrics(alerts)

    render_header(
        title=PAGE_TITLES[Page.ALERTS],
        subtitle=PAGE_SUBTITLES[Page.ALERTS],
        source=source,
        metrics=metrics,
    )
    render_severity_spine(metrics)
    render_alerts_table(list(alerts), height=620, occurrences=source.occurrences)
