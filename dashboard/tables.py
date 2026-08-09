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
