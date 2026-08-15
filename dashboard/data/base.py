"""Data source contract for the dashboard.

Every view reads alerts through this protocol, so swapping the sample source
for the live Wazuh pipeline in Sprint 4.3 touches one factory function and
nothing else.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from soc.models import Alert


class DataSourceError(RuntimeError):
    """Raised when a data source cannot deliver alerts."""


@runtime_checkable
class AlertDataSource(Protocol):
    """Read-only source of normalized :class:`soc.models.Alert` objects."""

    @property
    def name(self) -> str:
        """Short human-readable source name shown in the header."""
        ...

    @property
    def is_live(self) -> bool:
        """``True`` when the source is backed by real Wazuh data."""
        ...

    @property
    def occurrences(self) -> dict[str, int]:
        """Alert id to how many times it was seen. Empty when not deduplicated."""
        ...

    def fetch_alerts(self, limit: int) -> list[Alert]:
        """Return at most ``limit`` alerts, newest first.

        Raises:
            DataSourceError: If the alerts cannot be retrieved.
        """
        ...

    def fetch_group(self, alert_id: str) -> list[Alert]:
        """Return every alert that was collapsed into the row ``alert_id``.

        The representative alert is included and the list is newest first.
        Sources that do not deduplicate return a single-element list. An
        unknown id yields an empty list rather than raising, so the caller can
        fall back to the representative it already holds.

        The list may be shorter than the count reported by :attr:`occurrences`
        when a group exceeds the source's retention limit.
        """
        ...
