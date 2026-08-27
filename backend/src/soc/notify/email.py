"""Email (SMTP) notification channel.

Renders an alert + AI analysis into an HTML email and sends it via SMTP.
The SMTP connection is injected through a factory so it can be fully mocked
in tests without touching the network.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from html import escape
from typing import Callable, Sequence

from ..models import Alert, decoded_event_fields
from ..ai.schemas import AIAnalysis
from .exceptions import NotificationConfigError, NotificationDeliveryError

# A factory returning an object compatible with smtplib.SMTP (context manager).
SMTPFactory = Callable[[], smtplib.SMTP]

_RISK_COLOR = {
    "info": "#9e9e9e",
    "low": "#2e7d32",
    "medium": "#f9a825",
    "high": "#ef6c00",
    "critical": "#c62828",
}


def build_email_html(alert: Alert, analysis: AIAnalysis) -> str:
    """Build an HTML body for the incident email."""
    color = _RISK_COLOR.get(analysis.risk_level.value, "#9e9e9e")
    mitre = ", ".join(alert.mitre.ids) if alert.mitre.ids else "—"
    steps = "".join(f"<li>{escape(s)}</li>" for s in analysis.investigation_steps)

    # EventChannel alerts carry no full_log: without the decoded fields the
    # email names a rule but never says which file or process triggered it.
    fields = decoded_event_fields(alert)
    if fields:
        rows = "".join(
            f"<tr><td><b>{escape(k)}</b></td><td><code>{escape(v)}</code></td></tr>"
            for k, v in fields.items()
        )
        evidence = f"<h3>Event Data</h3><table style='border-collapse:collapse;'>{rows}</table>"
    elif alert.full_log and alert.full_log.strip():
        evidence = f"<h3>Raw Log</h3><pre>{escape(alert.full_log)}</pre>"
    else:
        evidence = ""
    return f"""\
<html><body style="font-family:Arial,sans-serif;color:#1a1a1a;">
  <div style="background:{color};color:#fff;padding:12px 16px;border-radius:6px;">
    <h2 style="margin:0;">SOC ALERT — {analysis.risk_level.value.upper()}</h2>
  </div>
  <table style="margin-top:12px;border-collapse:collapse;">
    <tr><td><b>Alert ID</b></td><td>{alert.id}</td></tr>
    <tr><td><b>Agent</b></td><td>{alert.agent.name} ({alert.agent.ip or '—'})</td></tr>
    <tr><td><b>Rule</b></td><td>{escape(alert.rule.description)} (level {alert.rule.level})</td></tr>
    <tr><td><b>MITRE</b></td><td>{mitre}</td></tr>
    <tr><td><b>Confidence</b></td><td>{analysis.confidence_score}/100</td></tr>
    <tr><td><b>False Positive</b></td><td>{analysis.false_positive_percent}%</td></tr>
  </table>
  <h3>Summary</h3><p>{escape(analysis.summary)}</p>
  <h3>Risk Assessment</h3><p>{escape(analysis.risk_assessment)}</p>
  <h3>Investigation Steps</h3><ol>{steps}</ol>
  <h3>MITRE Commentary</h3><p>{escape(analysis.mitre_commentary or '—')}</p>
  {evidence}
</body></html>"""


class EmailNotifier:
    """Sends incident emails over SMTP."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        sender: str,
        recipients: Sequence[str],
        *,
        use_tls: bool = True,
        smtp_factory: SMTPFactory | None = None,
    ):
        if not host or not sender or not recipients:
            raise NotificationConfigError("SMTP host, sender and recipients are required")
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._sender = sender
        self._recipients = list(recipients)
        self._use_tls = use_tls
        self._smtp_factory = smtp_factory or (lambda: smtplib.SMTP(self._host, self._port, timeout=10))

    def _build_message(self, alert: Alert, analysis: AIAnalysis) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = (
            f"[SOC {analysis.risk_level.value.upper()}] "
            f"{alert.agent.name}: {alert.rule.description}"
        )
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)
        msg.set_content(analysis.summary)  # plain-text fallback
        msg.add_alternative(build_email_html(alert, analysis), subtype="html")
        return msg

    def send(self, alert: Alert, analysis: AIAnalysis) -> None:
        """Render and deliver the incident email."""
        msg = self._build_message(alert, analysis)
        try:
            with self._smtp_factory() as smtp:
                if self._use_tls:
                    smtp.starttls()
                if self._username:
                    smtp.login(self._username, self._password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotificationDeliveryError(f"SMTP delivery failed: {exc}") from exc
