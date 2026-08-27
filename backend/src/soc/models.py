"""Domain models for SOC alerts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .mitre import MitreMapping, extract_mitre
from .severity import Severity, severity_from_level


class AgentInfo(BaseModel):
    """The Wazuh agent that produced the alert."""

    id: str = "unknown"
    name: str = "unknown"
    ip: str | None = None


class RuleInfo(BaseModel):
    """The Wazuh rule that fired."""

    id: str = "unknown"
    level: int = 0
    description: str = ""
    groups: list[str] = Field(default_factory=list)


class Alert(BaseModel):
    """Normalized SOC alert."""

    id: str
    timestamp: datetime
    severity: Severity
    agent: AgentInfo
    rule: RuleInfo
    mitre: MitreMapping = Field(default_factory=MitreMapping)
    full_log: str = ""
    location: str = ""
    decoder: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @classmethod
    def from_wazuh(cls, data: dict[str, Any]) -> "Alert":
        """Build a normalized Alert from a single raw Wazuh alert dict."""
        if not isinstance(data, dict):
            raise ValueError("Wazuh alert must be a JSON object")

        rule_raw = data.get("rule") or {}
        if not isinstance(rule_raw, dict):
            rule_raw = {}

        agent_raw = data.get("agent") or {}
        if not isinstance(agent_raw, dict):
            agent_raw = {}

        level = _coerce_int(rule_raw.get("level"), default=0)
        timestamp = _parse_timestamp(data.get("timestamp"))

        alert_id = str(
            data.get("id")
            or f"{agent_raw.get('id', 'x')}-{rule_raw.get('id', 'x')}-{timestamp.timestamp():.3f}"
        )

        decoder_raw = data.get("decoder") or {}
        decoder_name = (
            decoder_raw.get("name") if isinstance(decoder_raw, dict) else str(decoder_raw)
        )

        return cls(
            id=alert_id,
            timestamp=timestamp,
            severity=severity_from_level(level),
            agent=AgentInfo(
                id=str(agent_raw.get("id", "unknown")),
                name=str(agent_raw.get("name", "unknown")),
                ip=agent_raw.get("ip"),
            ),
            rule=RuleInfo(
                id=str(rule_raw.get("id", "unknown")),
                level=level,
                description=str(rule_raw.get("description", "")),
                groups=_as_str_list(rule_raw.get("groups")),
            ),
            mitre=extract_mitre(rule_raw),
            full_log=str(data.get("full_log", "")),
            location=str(data.get("location", "")),
            decoder=decoder_name,
            raw=data,
        )


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()]


def _parse_timestamp(value: Any) -> datetime:
    """Parse a Wazuh timestamp; fall back to now() if unparseable."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
            text = f"{text[:-2]}:{text[-2:]}"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass
    return datetime.now().astimezone()


#: Decoded Windows event fields worth surfacing, in priority order.
NOTABLE_EVENT_FIELDS: tuple[str, ...] = (
    "targetFilename",
    "image",
    "parentImage",
    "commandLine",
    "parentCommandLine",
    "targetImage",
    "sourceImage",
    "grantedAccess",
    "destinationIp",
    "destinationPort",
    "queryName",
    "hashes",
    "user",
    "processId",
)


def decoded_event_fields(alert: Alert, limit: int = 400) -> dict[str, str]:
    """Return notable decoded fields from a Windows EventChannel alert.

    Sysmon alerts leave ``full_log`` empty and carry their fields under
    ``data.win.eventdata``. Only known string fields are returned, so a caller
    never has to render or transmit an entire Wazuh document.
    """
    raw = alert.raw if isinstance(alert.raw, dict) else {}
    data = raw.get("data")
    if not isinstance(data, dict):
        return {}
    win = data.get("win")
    eventdata = win.get("eventdata") if isinstance(win, dict) else None
    if not isinstance(eventdata, dict):
        eventdata = data
    fields: dict[str, str] = {}
    for name in NOTABLE_EVENT_FIELDS:
        value = eventdata.get(name)
        if isinstance(value, str) and value.strip():
            text = value.strip()
            fields[name] = text if len(text) <= limit else text[:limit] + " …[truncated]"
    return fields
