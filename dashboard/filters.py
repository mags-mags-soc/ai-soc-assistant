"""Filtering and search applied to the loaded alert window.

Kept free of Streamlit imports so the rules can be unit tested. The query
logic itself lives in :class:`soc.alert_reader.AlertReader`; this module only
decides which of its helpers to call, so the dashboard never grows a second
implementation of the same predicates.

Filters run on the *deduplicated representatives*, after the data source has
built its occurrence counts. Filtering earlier would make the ``Seen`` column
report "times seen matching this filter" rather than the true total.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from soc.alert_reader import AlertReader
from soc.models import Alert
from soc.severity import Severity


@dataclass(frozen=True)
class AlertFilters:
    """The filter selections a view should apply."""

    min_severity: Severity | None = None
    agent: str = ""
    mitre: str = ""
    term: str = ""

    @property
    def active(self) -> bool:
        """``True`` when at least one filter would narrow the result."""
        return bool(
            self.min_severity is not None
            or self.agent.strip()
            or self.mitre.strip()
            or self.term.strip()
        )


def apply_filters(
    alerts: Sequence[Alert],
    filters: AlertFilters | None = None,
) -> list[Alert]:
    """Return the alerts matching ``filters``, newest-first order preserved.

    Each step delegates to the backend query helpers. An inactive filter set
    returns the input unchanged.
    """
    result = list(alerts)
    if filters is None or not filters.active:
        return result

    if filters.min_severity is not None:
        result = AlertReader.filter_by_severity(result, filters.min_severity)
    if filters.agent.strip():
        result = AlertReader.filter_by_agent(result, filters.agent)
    if filters.mitre.strip():
        result = AlertReader.filter_by_mitre(result, filters.mitre)
    if filters.term.strip():
        result = AlertReader.search(result, filters.term)
    return result
