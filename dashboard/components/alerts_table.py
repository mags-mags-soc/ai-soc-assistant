"""Live alerts table."""

from __future__ import annotations

from typing import Sequence

import streamlit as st

from soc.models import Alert
from soc.severity import Severity

from ..tables import alerts_to_frame
from ..theme import PALETTE, severity_label

_SEVERITY_STYLES = {
    severity_label(level): f"color:{level.color};font-weight:600;" for level in Severity
}


def _style_severity(value: object) -> str:
    """Return the inline style for a severity cell."""
    return _SEVERITY_STYLES.get(str(value), "")


def render_alerts_table(
    alerts: Sequence[Alert],
    height: int = 460,
    occurrences: dict[str, int] | None = None,
) -> None:
    """Render alerts as a sortable table, newest first."""
    if not alerts:
        st.markdown(
            f'<div style="color:{PALETTE["text_muted"]};padding:26px 0;">'
            "No alerts in the selected window. Raise the alert limit in the sidebar "
            "or point the dashboard at a live source.</div>",
            unsafe_allow_html=True,
        )
        return

    frame = alerts_to_frame(alerts, occurrences)
    styled = frame.style.map(_style_severity, subset=["Severity"])

    st.dataframe(
        styled,
        hide_index=True,
        width="stretch",
        height=height,
        column_config={
            "Time": st.column_config.DatetimeColumn("Time", format="YYYY-MM-DD HH:mm:ss"),
            "Level": st.column_config.NumberColumn("Lvl", width="small"),
            "Seen": st.column_config.NumberColumn("Seen", width="small"),
            "Description": st.column_config.TextColumn("Description", width="large"),
            "Alert ID": st.column_config.TextColumn("Alert ID", width="medium"),
        },
    )
