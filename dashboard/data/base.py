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

    def fetch_alerts(self, limit: int) -> list[Alert]:
        """Return at most ``limit`` alerts, newest first.

        Raises:
            DataSourceError: If the alerts cannot be retrieved.
        """
        ...
