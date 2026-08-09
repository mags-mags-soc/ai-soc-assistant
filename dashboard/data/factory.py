"""Resolve the configured alert data source.

Sprint 4.3 registers the live Wazuh source here; the rest of the dashboard
stays untouched because every view depends on
:class:`~dashboard.data.base.AlertDataSource` only.
"""

from __future__ import annotations

from typing import Callable, Final

from ..settings import DashboardSettings
from .base import AlertDataSource, DataSourceError
from .sample import SampleAlertDataSource

_REGISTRY: Final[dict[str, Callable[[], AlertDataSource]]] = {
    "sample": SampleAlertDataSource,
}


def available_sources() -> tuple[str, ...]:
    """Return the names of the registered data sources."""
    return tuple(_REGISTRY)


def build_data_source(settings: DashboardSettings) -> AlertDataSource:
    """Instantiate the data source named in ``settings``.

    Raises:
        DataSourceError: If the configured source is not registered.
    """
    try:
        factory = _REGISTRY[settings.source]
    except KeyError as exc:
        raise DataSourceError(
            f"Unknown data source {settings.source!r}. "
            f"Available: {', '.join(available_sources())}."
        ) from exc
    return factory()
