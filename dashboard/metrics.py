"""Aggregations used by the dashboard header and metric cards.

Only read-only aggregation lives here. Severity bands, MITRE mappings and
alert parsing all come from the backend ``soc`` package.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Sequence

from soc.models import Alert
from soc.severity import Severity

from .theme import SEVERITY_ORDER


@dataclass(frozen=True)
class DashboardMetrics:
    """Counters rendered by the metric cards."""

    total_alerts: int
    by_severity: dict[Severity, int] = field(default_factory=dict)
    unique_agents: int = 0
    unique_rules: int = 0
    mitre_technique_count: int = 0
    latest_alert_at: datetime | None = None

    def count(self, severity: Severity) -> int:
        """Return the number of alerts in a severity band."""
        return self.by_severity.get(severity, 0)

    @property
    def actionable_alerts(self) -> int:
        """Alerts at HIGH or above: the Tier 1 working queue."""
        return self.count(Severity.HIGH) + self.count(Severity.CRITICAL)


def mitre_ids(alert: Alert) -> list[str]:
    """Return the MITRE technique identifiers attached to an alert.

    ``soc.mitre.MitreMapping`` exposes the identifiers as ``ids``; older
    revisions of the mapping used ``techniques``. Both are accepted so the
    dashboard keeps working across backend revisions.
    """
    mapping: Any = alert.mitre
    values = getattr(mapping, "ids", None) or getattr(mapping, "techniques", None) or []
    return [str(value) for value in values if str(value).strip()]


def sort_alerts(alerts: Sequence[Alert]) -> list[Alert]:
    """Sort alerts newest first, breaking ties by descending severity."""
    return sorted(
        alerts,
        key=lambda alert: (alert.timestamp, alert.severity.rank),
        reverse=True,
    )


def compute_metrics(alerts: Sequence[Alert]) -> DashboardMetrics:
    """Aggregate a collection of alerts into dashboard counters."""
    by_severity = {level: 0 for level in SEVERITY_ORDER}
    agents: set[str] = set()
    rules: set[str] = set()
    techniques: set[str] = set()
    latest: datetime | None = None

    for alert in alerts:
        by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
        agents.add(alert.agent.name)
        rules.add(alert.rule.id)
        techniques.update(mitre_ids(alert))
        if latest is None or alert.timestamp > latest:
            latest = alert.timestamp

    return DashboardMetrics(
        total_alerts=len(alerts),
        by_severity=by_severity,
        unique_agents=len(agents),
        unique_rules=len(rules),
        mitre_technique_count=len(techniques),
        latest_alert_at=latest,
    )


def top_techniques(alerts: Sequence[Alert], limit: int = 5) -> list[tuple[str, int]]:
    """Return the most frequent MITRE technique ids with their counts."""
    if limit < 1:
        raise ValueError("limit must be >= 1")
    counter: Counter[str] = Counter()
    for alert in alerts:
        counter.update(mitre_ids(alert))
    return counter.most_common(limit)
