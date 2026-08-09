"""Page identifiers and their display titles.

Defined outside ``dashboard.views`` so that both the views and the sidebar can
import them without a circular dependency.
"""

from __future__ import annotations

from enum import Enum
from typing import Final


class Page(str, Enum):
    """Pages available in the dashboard."""

    OVERVIEW = "overview"
    ALERTS = "alerts"


PAGE_TITLES: Final[dict[Page, str]] = {
    Page.OVERVIEW: "Overview",
    Page.ALERTS: "Alert queue",
}

PAGE_SUBTITLES: Final[dict[Page, str]] = {
    Page.OVERVIEW: "Queue health at a glance, newest detections first",
    Page.ALERTS: "Every alert loaded from the current source, newest first",
}
