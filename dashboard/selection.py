"""Resolving which alert the detail panels should show.

Kept free of Streamlit imports so the resolution rules can be unit tested.
The session key itself lives here so producers and consumers cannot disagree.
"""

from __future__ import annotations

from typing import Final, Sequence

from soc.models import Alert

from .metrics import sort_alerts

#: Session-state key holding the id of the currently selected alert.
SELECTED_ALERT_KEY: Final[str] = "selected_alert_id"

#: Session-state key holding the id of the selected event inside a group.
SELECTED_EVENT_KEY: Final[str] = "selected_event_id"


def find_alert(alerts: Sequence[Alert], alert_id: str | None) -> Alert | None:
    """Return the alert with ``alert_id``, or ``None`` if it is not present."""
    if not alert_id:
        return None
    for alert in alerts:
        if alert.id == alert_id:
            return alert
    return None


def resolve_selection(alerts: Sequence[Alert], alert_id: str | None) -> Alert | None:
    """Pick the alert to display.

    Falls back to the newest alert when nothing is selected or when the
    previous selection is no longer in the loaded window — so the detail page
    is never blank while alerts exist.
    """
    if not alerts:
        return None
    return find_alert(alerts, alert_id) or sort_alerts(alerts)[0]


def resolve_event(members: Sequence[Alert], event_id: str | None) -> Alert | None:
    """Pick which member of a deduplicated group the panels should show.

    Mirrors :func:`resolve_selection`: falls back to the newest member so the
    panels are never blank while the group has events.
    """
    if not members:
        return None
    return find_alert(members, event_id) or sort_alerts(members)[0]
