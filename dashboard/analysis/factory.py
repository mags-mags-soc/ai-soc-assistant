"""Resolve the configured analysis source."""

from __future__ import annotations

from typing import Callable, Final

from ..settings import DashboardSettings
from .analyzer_source import AnalyzerAnalysisSource
from .base import AnalysisError, AnalysisSource
from .disabled import DisabledAnalysisSource

_REGISTRY: Final[dict[str, Callable[[], AnalysisSource]]] = {
    "disabled": DisabledAnalysisSource,
    "analyzer": AnalyzerAnalysisSource,
}


def available_analysis_sources() -> tuple[str, ...]:
    """Return the names of the registered analysis sources."""
    return tuple(_REGISTRY)


def build_analysis_source(settings: DashboardSettings) -> AnalysisSource:
    """Instantiate the analysis source named in ``settings``.

    Raises:
        AnalysisError: If the configured source is not registered.
    """
    try:
        factory = _REGISTRY[settings.analysis_source]
    except KeyError as exc:
        raise AnalysisError(
            f"Unknown analysis source {settings.analysis_source!r}. "
            f"Available: {', '.join(available_analysis_sources())}."
        ) from exc
    return factory()
