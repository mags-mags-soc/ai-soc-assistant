"""End-to-end SOC pipeline orchestration.

Flow:  Alert -> AI analysis -> Telegram -> Email -> Markdown report.

Notification and report steps are resilient: a failure in one channel is
recorded but does not abort the pipeline. AI analysis is critical — if it
fails, the pipeline stops because every later step depends on it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from .models import Alert
from .ai.schemas import AIAnalysis
from .ai.analyzer import AlertAnalyzer
from .ai.exceptions import AIEngineError
from .notify.telegram import TelegramNotifier
from .notify.email import EmailNotifier
from .notify.exceptions import NotificationError

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Outcome of a single alert run through the pipeline."""

    alert_id: str
    analysis: Optional[AIAnalysis] = None
    telegram_sent: bool = False
    email_sent: bool = False
    report_path: Optional[str] = None
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True if analysis succeeded and no step recorded an error."""
        return self.analysis is not None and not self.errors


class SOCPipeline:
    """Orchestrates analysis, notification and reporting for alerts."""

    def __init__(
        self,
        analyzer: AlertAnalyzer,
        *,
        telegram: TelegramNotifier | None = None,
        email: EmailNotifier | None = None,
        report_writer=None,
    ):
        self._analyzer = analyzer
        self._telegram = telegram
        self._email = email
        self._report_writer = report_writer

    def process(self, alert: Alert) -> PipelineResult:
        """Run a single alert through the full pipeline."""
        result = PipelineResult(alert_id=alert.id)

        # --- Critical step: AI analysis ---
        try:
            analysis = self._analyzer.analyze(alert)
            result.analysis = analysis
        except AIEngineError as exc:
            logger.error("AI analysis failed for alert %s: %s", alert.id, exc)
            result.errors["analysis"] = str(exc)
            return result  # cannot continue without analysis

        # --- Resilient step: Telegram ---
        if self._telegram is not None:
            try:
                self._telegram.send(alert, analysis)
                result.telegram_sent = True
            except NotificationError as exc:
                logger.warning("Telegram delivery failed for alert %s: %s", alert.id, exc)
                result.errors["telegram"] = str(exc)

        # --- Resilient step: Email ---
        if self._email is not None:
            try:
                self._email.send(alert, analysis)
                result.email_sent = True
            except NotificationError as exc:
                logger.warning("Email delivery failed for alert %s: %s", alert.id, exc)
                result.errors["email"] = str(exc)

        # --- Resilient step: Markdown report ---
        if self._report_writer is not None:
            try:
                result.report_path = self._report_writer(alert, analysis)
            except Exception as exc:  # report writer is a plain callable
                logger.warning("Report generation failed for alert %s: %s", alert.id, exc)
                result.errors["report"] = str(exc)

        return result
