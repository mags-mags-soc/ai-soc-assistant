"""Dark theme tokens and CSS for the SOC dashboard.

Severity colors are **not** defined here. They are read from
``soc.severity.Severity.color`` so the dashboard and the backend can never
drift apart. This module imports no Streamlit APIs and is therefore testable
without a Streamlit runtime.
"""

from __future__ import annotations

from typing import Final

from soc.severity import Severity

#: Base surface palette. Deep slate rather than pure black so that the
#: severity colors (the only saturated hues on screen) stay readable.
PALETTE: Final[dict[str, str]] = {
    "bg": "#0b1017",
    "surface": "#121a24",
    "surface_alt": "#18222f",
    "border": "#243040",
    "text": "#e6edf5",
    "text_muted": "#8ea0b5",
    "accent": "#38bdf8",
}

#: Utility face for machine data (rule ids, timestamps, MITRE ids, agents).
FONT_MONO: Final[str] = (
    '"JetBrains Mono", "SFMono-Regular", "Cascadia Mono", Menlo, Consolas, monospace'
)
#: Body face.
FONT_SANS: Final[str] = (
    '"Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
)

#: Severity bands ordered from most to least urgent.
SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def severity_color(severity: Severity) -> str:
    """Return the hex color for a severity band, sourced from the backend."""
    return severity.color


def severity_label(severity: Severity) -> str:
    """Return the uppercase display label for a severity band."""
    return severity.value.upper()


def build_css() -> str:
    """Return the dashboard stylesheet as a single ``<style>`` block."""
    severity_vars = "\n".join(
        f"    --sev-{level.value}: {level.color};" for level in SEVERITY_ORDER
    )
    return f"""<style>
:root {{
    --bg: {PALETTE["bg"]};
    --surface: {PALETTE["surface"]};
    --surface-alt: {PALETTE["surface_alt"]};
    --border: {PALETTE["border"]};
    --text: {PALETTE["text"]};
    --muted: {PALETTE["text_muted"]};
    --accent: {PALETTE["accent"]};
{severity_vars}
    --radius: 10px;
}}

.stApp {{
    background: var(--bg);
    font-family: {FONT_SANS};
}}

section[data-testid="stSidebar"] {{
    background: var(--surface);
    border-right: 1px solid var(--border);
}}

/* ---------- Header ---------- */
.soc-header {{
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    justify-content: space-between;
    gap: 12px;
    padding: 4px 0 14px 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 18px;
}}
.soc-header h1 {{
    font-size: 1.55rem;
    font-weight: 650;
    letter-spacing: -0.02em;
    color: var(--text);
    margin: 0;
}}
.soc-header .soc-subtitle {{
    color: var(--muted);
    font-size: 0.86rem;
    margin-top: 2px;
}}
.soc-meta {{
    font-family: {FONT_MONO};
    font-size: 0.74rem;
    color: var(--muted);
    text-align: right;
    line-height: 1.6;
}}
.soc-meta strong {{
    color: var(--text);
    font-weight: 500;
}}

/* ---------- Severity spine: the composition of the current queue ---------- */
.soc-spine {{
    display: flex;
    width: 100%;
    height: 6px;
    border-radius: 999px;
    overflow: hidden;
    background: var(--surface-alt);
    margin-bottom: 6px;
}}
.soc-spine span {{ display: block; height: 100%; }}
.soc-spine-legend {{
    display: flex;
    flex-wrap: wrap;
    gap: 14px;
    font-family: {FONT_MONO};
    font-size: 0.72rem;
    color: var(--muted);
    margin-bottom: 20px;
}}
.soc-spine-legend i {{
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 2px;
    margin-right: 6px;
}}

/* ---------- Metric cards ---------- */
.soc-cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(165px, 1fr));
    gap: 12px;
    margin-bottom: 22px;
}}
.soc-card {{
    position: relative;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 16px 14px 18px;
    overflow: hidden;
}}
.soc-card::before {{
    content: "";
    position: absolute;
    left: 0; top: 0; bottom: 0;
    width: 3px;
    background: var(--rail, var(--border));
}}
.soc-card .soc-card-label {{
    font-family: {FONT_MONO};
    font-size: 0.68rem;
    letter-spacing: 0.09em;
    text-transform: uppercase;
    color: var(--muted);
}}
.soc-card .soc-card-value {{
    font-size: 1.9rem;
    font-weight: 600;
    line-height: 1.15;
    color: var(--text);
    margin-top: 6px;
}}
.soc-card .soc-card-note {{
    font-family: {FONT_MONO};
    font-size: 0.7rem;
    color: var(--muted);
    margin-top: 4px;
}}

/* ---------- Section titles ---------- */
.soc-section {{
    font-family: {FONT_MONO};
    font-size: 0.72rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin: 6px 0 10px 0;
}}

/* ---------- Data table ---------- */
div[data-testid="stDataFrame"] {{
    border: 1px solid var(--border);
    border-radius: var(--radius);
}}

@media (max-width: 640px) {{
    .soc-header {{ flex-direction: column; align-items: flex-start; }}
    .soc-meta {{ text-align: left; }}
    .soc-card .soc-card-value {{ font-size: 1.6rem; }}
}}

@media (prefers-reduced-motion: reduce) {{
    * {{ animation: none !important; transition: none !important; }}
}}
</style>"""


#: Extra styles introduced in Sprint 4.2 for the detail page.
DETAIL_CSS: Final[str] = f"""<style>
.soc-kv-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 10px 20px;
}}
.soc-kv {{ display: flex; flex-direction: column; gap: 2px; }}
.soc-kv-label {{
    font-family: {FONT_MONO};
    font-size: 0.66rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: {PALETTE["text_muted"]};
}}
.soc-kv-value {{
    font-family: {FONT_MONO};
    font-size: 0.82rem;
    color: {PALETTE["text"]};
    word-break: break-word;
}}
</style>"""
