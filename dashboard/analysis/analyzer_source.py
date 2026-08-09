"""Analysis source backed by the backend :class:`soc.ai.analyzer.AlertAnalyzer`.

Results are cached per alert id for the lifetime of the source, so re-rendering
a page never re-bills the provider. ``soc.ai.analyzer`` is imported lazily so
the dashboard runs without a configured provider.
"""

from __future__ import annotations

from typing import Any

from soc.ai.schemas import AIAnalysis
from soc.models import Alert

from .base import AnalysisError


class AnalyzerAnalysisSource:
    """Calls the real AI engine and remembers what it has already analysed."""

    name = "AI engine"
    is_available = True
    unavailable_reason = ""

    def __init__(self, analyzer: Any | None = None) -> None:
        """Args:
        analyzer: An object exposing ``analyze(alert) -> AIAnalysis``. When
            omitted, a :class:`soc.ai.analyzer.AlertAnalyzer` is constructed.
        """
        if analyzer is None:
            try:
                from soc.ai.analyzer import AlertAnalyzer
            except ImportError as exc:  # pragma: no cover - depends on extras
                raise AnalysisError(f"AI engine is not importable: {exc}") from exc
            analyzer = AlertAnalyzer()
        self._analyzer = analyzer
        self._cache: dict[str, AIAnalysis] = {}

    def cached(self, alert: Alert) -> AIAnalysis | None:
        """Return the stored analysis for this alert, if one exists."""
        return self._cache.get(alert.id)

    def analyze(self, alert: Alert) -> AIAnalysis:
        """Analyze the alert, reusing a cached result when available.

        Raises:
            AnalysisError: If the underlying AI call fails for any reason.
        """
        existing = self._cache.get(alert.id)
        if existing is not None:
            return existing

        try:
            result = self._analyzer.analyze(alert)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI as one type
            raise AnalysisError(f"Analysis of alert {alert.id} failed: {exc}") from exc

        self._cache[alert.id] = result
        return result
