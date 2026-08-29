"""Telegram notification channel.

Formats an alert + AI analysis into a compact Telegram message and sends it via
the Bot API. The HTTP call is isolated so it can be fully mocked in tests.
"""

from __future__ import annotations

import time
from html import escape

import requests

from ..models import Alert, decoded_event_fields
from ..ai.schemas import AIAnalysis
from .exceptions import NotificationConfigError, NotificationDeliveryError

_API_URL = "https://api.telegram.org/bot{token}/sendMessage"
_TIMEOUT = 10

#: Telegram rejects messages longer than this many characters.
_MAX_LENGTH = 4096

#: Decoded fields worth showing on a phone screen. The full set would push the
#: summary out of view; these are what a first responder acts on.
_KEY_FIELDS = ("targetFilename", "image", "commandLine", "destinationIp", "user")

#: Delivery is retried on transport errors and Telegram rate limiting.
_MAX_ATTEMPTS = 3
_BACKOFF_SECONDS = 2

_RISK_EMOJI = {
    "info": "⚪",
    "low": "🟢",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🔴",
}


def _redact(text: str, token: str) -> str:
    """Strip a bot token out of text that is headed for a log or an exception.

    ``requests`` puts the full request URL into its exception messages, and the
    token lives in that URL. Without this, the first dropped connection writes
    the bot token into ``logs/soc.log`` in cleartext (CWE-532).
    """
    if not token:
        return text
    return text.replace(token, "<redacted>")


def build_telegram_message(alert: Alert, analysis: AIAnalysis) -> str:
    """Build a compact HTML-formatted Telegram message."""
    emoji = _RISK_EMOJI.get(analysis.risk_level.value, "⚪")
    mitre = ", ".join(alert.mitre.ids) if alert.mitre.ids else "—"
    # Every value below reaches Telegram inside an HTML message, and all of
    # them originate outside this process. Wazuh expands $(field) placeholders
    # into rule descriptions, so an attacker-chosen user name or file name can
    # land there. Unescaped, a stray "<" makes Telegram reject the message with
    # HTTP 400 - which is not retried - and the alert is silently never
    # delivered. Escaping is what stops an attacker suppressing their own alert.
    lines = [
        f"{emoji} <b>SOC ALERT — {analysis.risk_level.value.upper()}</b>",
        "",
        f"<b>Alert:</b> <code>{escape(alert.id)}</code>",
        f"<b>Agent:</b> {escape(alert.agent.name)} ({escape(alert.agent.ip or '—')})",
        f"<b>Rule:</b> {escape(alert.rule.description)} (lvl {alert.rule.level})",
        f"<b>MITRE:</b> {escape(mitre)}",
        "",
        f"<b>Confidence:</b> {analysis.confidence_score}/100  |  "
        f"<b>FP:</b> {analysis.false_positive_percent}%",
        "",
        f"<b>Summary:</b> {escape(analysis.summary)}",
    ]

    # A Sysmon alert has no full_log, so without these the responder sees the
    # rule name and nothing about what actually happened.
    fields = decoded_event_fields(alert)
    shown = [(k, v) for k, v in fields.items() if k in _KEY_FIELDS]
    if shown:
        lines += ["", "<b>Indicators:</b>"]
        lines += [f"• <code>{escape(k)}</code>: {escape(v)}" for k, v in shown]

    text = "\n".join(lines)
    if len(text) > _MAX_LENGTH:
        text = text[: _MAX_LENGTH - 20].rstrip() + "\n… [truncated]"
    return text


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
        # A dropped connection or a rate limit must not lose an alert; the
        # error is only raised once the retries are exhausted.
        last_error: Exception | None = None
        resp = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                resp = self._session.post(url, json=payload, timeout=_TIMEOUT)
            except requests.RequestException as exc:
                last_error = exc
                resp = None
            else:
                if resp.status_code == 200:
                    break
                if resp.status_code not in (429, 500, 502, 503, 504):
                    raise NotificationDeliveryError(
                        f"Telegram API returned HTTP {resp.status_code}",
                        status_code=resp.status_code,
                    )
                last_error = NotificationDeliveryError(
                    f"Telegram API returned HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            if attempt < _MAX_ATTEMPTS:
                time.sleep(_BACKOFF_SECONDS * attempt)

        if resp is None or resp.status_code != 200:
            raise NotificationDeliveryError(
                f"Telegram delivery failed after {_MAX_ATTEMPTS} attempts: "
                f"{_redact(str(last_error), self._token)}"
            )

        data = resp.json()
        if not data.get("ok", False):
            raise NotificationDeliveryError(
                f"Telegram API error: {data.get('description', 'unknown')}"
            )
        return data
