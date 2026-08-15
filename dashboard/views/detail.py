"""Alert detail page: details, AI analysis and the incident report."""

from __future__ import annotations

from typing import Final, Sequence

import streamlit as st

from soc.models import Alert

from ..analysis.base import AnalysisSource
from ..components.ai_analysis import render_ai_analysis
from ..components.alert_details import render_alert_details
from ..components.header import render_header
from ..components.report_viewer import render_report_viewer
from ..data.base import AlertDataSource
from ..metrics import compute_metrics, sort_alerts
from ..navigation import PAGE_SUBTITLES, PAGE_TITLES, Page
from ..selection import SELECTED_ALERT_KEY, SELECTED_EVENT_KEY, resolve_event
from ..tables import group_to_frame
from ..theme import severity_label

#: How many occurrences of a group are listed before the table is truncated.
GROUP_ROWS_SHOWN: Final[int] = 50


def _option_label(alert: Alert, occurrences: dict[str, int]) -> str:
    """Return the picker label for a deduplicated group."""
    stamp = alert.timestamp.strftime("%H:%M:%S")
    seen = occurrences.get(alert.id, 1)
    suffix = f"  x{seen}" if seen > 1 else ""
    return (
        f"{stamp} - {severity_label(alert.severity)} - "
        f"[{alert.rule.id}] lvl{alert.rule.level} - {alert.rule.description}{suffix}"
    )


def _event_label(alert: Alert) -> str:
    """Return the picker label for one occurrence inside a group."""
    return f"{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {alert.id}"


def render(
    alerts: Sequence[Alert],
    source: AlertDataSource,
    analysis_source: AnalysisSource,
) -> None:
    """Render the alert detail page."""
    render_header(
        title=PAGE_TITLES[Page.DETAIL],
        subtitle=PAGE_SUBTITLES[Page.DETAIL],
        source=source,
        metrics=compute_metrics(alerts),
    )

    if not alerts:
        st.info("No alerts are loaded. Raise the alert limit in the sidebar.")
        return

    ordered = sort_alerts(alerts)
    by_id = {alert.id: alert for alert in ordered}
    ids = list(by_id)

    # Select on the stable alert id: the sample source re-stamps timestamps on
    # every rerun, so selecting on Alert objects would reset the widget.
    previous = st.session_state.get(SELECTED_ALERT_KEY)
    index = ids.index(previous) if previous in by_id else 0

    occurrences = source.occurrences

    chosen_id = st.selectbox(
        "Alert",
        options=ids,
        index=index,
        format_func=lambda alert_id: _option_label(by_id[alert_id], occurrences),
        label_visibility="collapsed",
        key="alert_picker",
    )
    st.session_state[SELECTED_ALERT_KEY] = chosen_id
    chosen = by_id[chosen_id]

    # A deduplicated row stands for every event sharing its fingerprint. Let the
    # analyst walk those events instead of only seeing the newest one.
    members = source.fetch_group(chosen_id) or [chosen]
    total_seen = occurrences.get(chosen_id, len(members))

    if len(members) > 1:
        shown = members[:GROUP_ROWS_SHOWN]
        st.markdown(
            '<div class="soc-section">Occurrences in this group</div>',
            unsafe_allow_html=True,
        )
        if len(shown) < total_seen:
            st.caption(
                f"Showing {len(shown)} of {total_seen} occurrences "
                "seen in the current window."
            )
        else:
            st.caption(f"{total_seen} occurrences seen in the current window.")

        frame = group_to_frame(shown)
        event_key = f"event_picker-{chosen_id}"
        table = st.dataframe(
            frame,
            hide_index=True,
            width="stretch",
            height=min(300, 44 + 35 * len(shown)),
            on_select="rerun",
            selection_mode="single-row",
            key=f"group_table-{chosen_id}",
            column_config={
                "Time": st.column_config.DatetimeColumn(
                    "Time", format="YYYY-MM-DD HH:mm:ss"
                ),
                "Level": st.column_config.NumberColumn("Lvl", width="small"),
                "Log": st.column_config.TextColumn("Log", width="large"),
                "Alert ID": st.column_config.TextColumn("Alert ID", width="medium"),
            },
        )

        # Clicking a row selects that occurrence. The id is read out of the very
        # frame that was rendered, so the row can never map to another alert.
        selection = getattr(table, "selection", None)
        picked = list(getattr(selection, "rows", []) or []) if selection else []
        if picked:
            clicked_id = str(frame.iloc[picked[0]]["Alert ID"])
            if st.session_state.get(SELECTED_EVENT_KEY) != clicked_id:
                st.session_state[SELECTED_EVENT_KEY] = clicked_id
                st.session_state[event_key] = clicked_id
                st.rerun()

        event_ids = [alert.id for alert in shown]
        previous_event = st.session_state.get(SELECTED_EVENT_KEY)
        event_index = (
            event_ids.index(previous_event) if previous_event in event_ids else 0
        )
        # The widget key carries the group id: switching groups must not leave a
        # stale event id in a widget whose options no longer contain it.
        chosen_event_id = st.selectbox(
            "Occurrence",
            options=event_ids,
            index=event_index,
            format_func=lambda event_id: _event_label(
                next(alert for alert in shown if alert.id == event_id)
            ),
            key=event_key,
        )
        st.session_state[SELECTED_EVENT_KEY] = chosen_event_id
        chosen = resolve_event(shown, chosen_event_id) or chosen

    details_column, analysis_column = st.columns([1, 1], gap="medium")
    with details_column:
        render_alert_details(chosen)
    with analysis_column:
        render_ai_analysis(chosen, analysis_source)

    render_report_viewer(chosen, analysis_source)
