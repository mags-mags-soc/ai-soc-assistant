"""Contract for retrieving AI analysis of an alert.

The dashboard never calls the AI engine directly. It asks an
:class:`AnalysisSource`, which may or may not have a configured provider
behind it. When no provider is configured the panel renders an explicit
"not analysed" state rather than inventing a result.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from soc.ai.schemas import AIAnalysis
from soc.models import Alert


class AnalysisError(RuntimeError):
    """Raised when an analysis attempt fails."""


@runtime_checkable
class AnalysisSource(Protocol):
    """Produces validated :class:`soc.ai.schemas.AIAnalysis` objects."""

    @property
    def name(self) -> str:
        """Short human-readable source name shown in the panel."""
        ...

    @property
    def is_available(self) -> bool:
        """``True`` when an AI provider is configured and usable."""
        ...

    @property
    def unavailable_reason(self) -> str:
        """Why analysis cannot run. Empty when :attr:`is_available` is ``True``."""
        ...

    def cached(self, alert: Alert) -> AIAnalysis | None:
        """Return a previously computed analysis, or ``None`` if there is none."""
        ...

    def forget(self, alert: Alert) -> None:
        """Drop any cached analysis for this alert."""
        ...

    def analyze(self, alert: Alert) -> AIAnalysis:
        """Analyze an alert and return the validated result.

        Raises:
            AnalysisError: If no provider is configured or the call fails.
        """
        ...
