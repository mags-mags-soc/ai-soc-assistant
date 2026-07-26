"""High-level orchestration: turn an Alert into a validated AIAnalysis.

The AlertAnalyzer wires together prompt construction, the AI client, and the
strict schema validation. It is the single entry point the rest of the app
(dashboard, reporting) uses for AI triage.
"""

from __future__ import annotations

from typing import Iterable

from ..config import Settings, settings as default_settings
from ..logging_setup import setup_logging
from ..models import Alert
from .client import AIClient
from .prompts import SYSTEM_PROMPT, build_user_prompt
from .schemas import AIAnalysis


class AlertAnalyzer:
    """Analyze alerts with the AI engine and return validated results."""

    def __init__(
        self,
        config: Settings | None = None,
        client: AIClient | None = None,
    ) -> None:
        self._settings = config or default_settings
        self._log = setup_logging(self._settings.logs_dir, self._settings.log_level)
        self._client = client or AIClient(self._settings)

    def analyze(self, alert: Alert) -> AIAnalysis:
        """Analyze a single alert and return a validated AIAnalysis.

        Any AIEngineError (config, provider, parse, validation) propagates to
        the caller unchanged — invalid AI output never becomes a result.
        """
        self._log.info("AI analysis started for alert %s (rule %s, severity %s)",
                       alert.id, alert.rule.id, alert.severity.value)
        user_prompt = build_user_prompt(alert)
        result = self._client.analyze(SYSTEM_PROMPT, user_prompt)
        self._log.info(
            "AI analysis complete for alert %s: risk=%s confidence=%d fp=%d%%",
            alert.id, result.risk_level.value, result.confidence_score,
            result.false_positive_percent,
        )
        return result

    def analyze_many(
        self,
        alerts: Iterable[Alert],
        stop_on_error: bool = False,
    ) -> list[tuple[Alert, AIAnalysis | None]]:
        """Analyze several alerts.

        Returns a list of (alert, analysis) pairs. On error, analysis is None
        for that alert unless stop_on_error is True, in which case the error
        propagates.
        """
        results: list[tuple[Alert, AIAnalysis | None]] = []
        for alert in alerts:
            try:
                results.append((alert, self.analyze(alert)))
            except Exception as exc:  # noqa: BLE001
                if stop_on_error:
                    raise
                self._log.error("AI analysis failed for alert %s: %s", alert.id, exc)
                results.append((alert, None))
        return results
