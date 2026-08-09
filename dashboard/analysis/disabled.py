"""Analysis source used while no AI provider is configured.

This is the default. It holds no canned results: every lookup returns ``None``
and every analysis attempt raises, so the panel shows an honest empty state.
"""

from __future__ import annotations

from typing import Final

from soc.ai.schemas import AIAnalysis
from soc.models import Alert

from .base import AnalysisError

_REASON: Final[str] = (
    "No AI provider is configured. Set AI_BASE_URL, AI_API_KEY and AI_MODEL, "
    "then set DASHBOARD_ANALYSIS_SOURCE=analyzer."
)


class DisabledAnalysisSource:
    """Reports that analysis is unavailable and refuses to fabricate results."""

    name = "Disabled"
    is_available = False
    unavailable_reason = _REASON

    def cached(self, alert: Alert) -> AIAnalysis | None:
        """Always ``None``: nothing has been analysed."""
        return None

    def analyze(self, alert: Alert) -> AIAnalysis:
        """Always raises: there is no provider to call."""
        raise AnalysisError(_REASON)
