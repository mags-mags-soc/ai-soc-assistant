"""Turn backend alerts into the tabular shape the UI renders.

Kept free of Streamlit imports so it can be unit tested without a runtime.
"""

from __future__ import annotations

from typing import Final, Sequence

import pandas as pd

from soc.models import Alert

from .metrics import mitre_ids, sort_alerts
from .theme import severity_label

#: Column order used by the live alerts table.
COLUMNS: Final[tuple[str, ...]] = (
    "Time",
    "Seen",
    "Severity",
    "Level",
    "Rule",
    "Description",
    "Agent",
    "Source",
    "MITRE",
    "Alert ID",
)

#: Column order used by the per-group occurrence table.
GROUP_COLUMNS: Final[tuple[str, ...]] = (
    "Time",
    "Level",
    "Agent",
    "Source",
    "Log",
    "Alert ID",
)

#: Characters of ``full_log`` shown in the occurrence table.
LOG_PREVIEW: Final[int] = 160


def alerts_to_frame(
    alerts: Sequence[Alert],
    occurrences: dict[str, int] | None = None,
) -> pd.DataFrame:
    """Build a display DataFrame, newest alert first.

    An empty input produces an empty frame with the correct columns, so the
    table renders consistently whether or not alerts are present.
    """
    counts = occurrences or {}
    rows = [
        {
            "Time": alert.timestamp,
            "Seen": counts.get(alert.id, 1),
            "Severity": severity_label(alert.severity),
            "Level": alert.rule.level,
            "Rule": alert.rule.id,
            "Description": alert.rule.description,
            "Agent": alert.agent.name,
            "Source": alert.location,
            "MITRE": ", ".join(mitre_ids(alert)),
            "Alert ID": alert.id,
        }
        for alert in sort_alerts(alerts)
    ]
    return pd.DataFrame(rows, columns=list(COLUMNS))


#: Decoded Windows event fields worth surfacing, in priority order.
_EVENT_FIELDS: Final[tuple[str, ...]] = (
    "targetFilename",
    "image",
    "commandLine",
    "targetImage",
    "sourceImage",
    "destinationIp",
    "queryName",
    "user",
)


def event_fields(alert: Alert) -> dict[str, str]:
    """Return the notable decoded fields of a Windows EventChannel alert.

    Sysmon alerts leave ``full_log`` empty and carry their fields in the Wazuh
    ``data`` block instead. Only string fields from :data:`_EVENT_FIELDS` are
    returned, so the caller never has to render a whole document.
    """
    raw = alert.raw if isinstance(alert.raw, dict) else {}
    data = raw.get("data")
    if not isinstance(data, dict):
        return {}
    win = data.get("win")
    eventdata = win.get("eventdata") if isinstance(win, dict) else None
    if not isinstance(eventdata, dict):
        eventdata = data
    result: dict[str, str] = {}
    for field in _EVENT_FIELDS:
        value = eventdata.get(field)
        if isinstance(value, str) and value.strip():
            result[field] = value.strip()
    return result


def _log_preview(alert: Alert) -> str:
    """Return a one-line excerpt identifying the event."""
    text = (alert.full_log or "").strip()
    if text:
        return text[:LOG_PREVIEW]
    for value in event_fields(alert).values():
        return value[:LOG_PREVIEW]
    return ""


def group_to_frame(members: Sequence[Alert]) -> pd.DataFrame:
    """Build a display DataFrame for the members of one deduplicated group.

    Severity, rule id and description are identical across a group by
    construction, so the columns that vary are the ones shown.
    """
    rows = [
        {
            "Time": alert.timestamp,
            "Level": alert.rule.level,
            "Agent": alert.agent.name,
            "Source": alert.location,
            "Log": _log_preview(alert),
            "Alert ID": alert.id,
        }
        for alert in sort_alerts(members)
    ]
    return pd.DataFrame(rows, columns=list(GROUP_COLUMNS))
