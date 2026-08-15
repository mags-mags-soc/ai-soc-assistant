"""Alert details panel: every field of the selected alert."""

from __future__ import annotations

from html import escape

import streamlit as st

from soc.models import Alert

from ..metrics import mitre_ids
from ..tables import event_fields
from ..theme import PALETTE, severity_label


def _rows(alert: Alert) -> list[tuple[str, str]]:
    """Return the label/value pairs shown in the details grid."""
    mapping = alert.mitre
    rows = [
        ("Alert ID", alert.id),
        ("Time", alert.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")),
        ("Severity", severity_label(alert.severity)),
        ("Rule level", str(alert.rule.level)),
        ("Rule ID", alert.rule.id),
        ("Rule groups", ", ".join(alert.rule.groups) or "—"),
        ("Agent", f"{alert.agent.name} ({alert.agent.id})"),
        ("Agent IP", alert.agent.ip or "—"),
        ("Location", alert.location),
        ("Decoder", alert.decoder or "—"),
        ("MITRE IDs", ", ".join(mitre_ids(alert)) or "—"),
        ("MITRE tactics", ", ".join(getattr(mapping, "tactics", []) or []) or "—"),
        ("MITRE techniques", ", ".join(getattr(mapping, "techniques", []) or []) or "—"),
    ]
    rows.extend((name, value) for name, value in event_fields(alert).items())
    return rows


def render_alert_details(alert: Alert) -> None:
    """Render the selected alert's fields and its raw log line."""
    st.markdown('<div class="soc-section">Alert details</div>', unsafe_allow_html=True)

    cells = "".join(
        f'<div class="soc-kv">'
        f'<span class="soc-kv-label">{escape(label)}</span>'
        f'<span class="soc-kv-value">{escape(value)}</span>'
        f"</div>"
        for label, value in _rows(alert)
    )
    st.markdown(
        f'<div class="soc-card" style="--rail:{alert.severity.color};">'
        f'<div style="font-size:1.02rem;font-weight:600;margin-bottom:12px;">'
        f"{escape(alert.rule.description)}</div>"
        f'<div class="soc-kv-grid">{cells}</div>'
        f"</div>",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="soc-section">Raw log</div>', unsafe_allow_html=True)
    text = (getattr(alert, "full_log", "") or "").strip()
    if text:
        st.code(text, language="text")
    elif isinstance(alert.raw, dict) and alert.raw:
        # EventChannel alerts have no full_log. Keep the Wazuh document behind a
        # collapsed expander so it never dominates the page.
        with st.expander("Show the raw Wazuh document"):
            st.json(alert.raw, expanded=False)
    else:
        st.markdown(
            f'<div style="color:{PALETTE["text_muted"]};font-size:0.82rem;">'
            "No raw log was attached to this alert.</div>",
            unsafe_allow_html=True,
        )
