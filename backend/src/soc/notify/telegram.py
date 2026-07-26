"""Telegram notification channel.

Formats an alert + AI analysis into a compact Telegram message and sends it via
the Bot API. The HTTP call is isolated so it can be fully mocked in tests.
"""

from __future__ import annotations

import requests

from ..models import Alert
from ..ai.schemas import AIAnalysis
from .exceptions import NotificationConfigError, NotificationDeliveryError

_API_URL = "https://api.telegram.org/bot{token}/sendMessage"
_TIMEOUT = 10

_RISK_EMOJI = {
    "info": "⚪",
    "low": "🟢",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🔴",
}


def build_telegram_message(alert: Alert, analysis: AIAnalysis) -> str:
    """Build a compact HTML-formatted Telegram message."""
    emoji = _RISK_EMOJI.get(analysis.risk_level.value, "⚪")
    mitre = ", ".join(alert.mitre.ids) if alert.mitre.ids else "—"
    lines = [
        f"{emoji} <b>SOC ALERT — {analysis.risk_level.value.upper()}</b>",
        "",
        f"<b>Alert:</b> <code>{alert.id}</code>",
        f"<b>Agent:</b> {alert.agent.name} ({alert.agent.ip or '—'})",
        f"<b>Rule:</b> {alert.rule.description} (lvl {alert.rule.level})",
        f"<b>MITRE:</b> {mitre}",
        "",
        f"<b>Confidence:</b> {analysis.confidence_score}/100  |  "
        f"<b>FP:</b> {analysis.false_positive_percent}%",
        "",
        f"<b>Summary:</b> {analysis.summary}",
    ]
    return "\n".join(lines)


class TelegramNotifier:
    """Sends notifications to a Telegram chat via the Bot API."""

    def __init__(self, token: str, chat_id: str, *, session: requests.Session | None = None):
        if not token or not chat_id:
            raise NotificationConfigError("Telegram token and chat_id are required")
        self._token = token
        self._chat_id = chat_id
        self._session = session or requests.Session()

    def send(self, alert: Alert, analysis: AIAnalysis) -> dict:
        """Send an alert notification. Returns the parsed API response."""
        text = build_telegram_message(alert, analysis)
        url = _API_URL.format(token=self._token)
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        try:
            resp = self._session.post(url, json=payload, timeout=_TIMEOUT)
        except requests.RequestException as exc:
            raise NotificationDeliveryError(f"Telegram request failed: {exc}") from exc

        if resp.status_code != 200:
            raise NotificationDeliveryError(
                f"Telegram API returned HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        data = resp.json()
        if not data.get("ok", False):
            raise NotificationDeliveryError(
                f"Telegram API error: {data.get('description', 'unknown')}"
            )
        return data
