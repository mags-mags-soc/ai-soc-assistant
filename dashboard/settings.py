"""Runtime settings for the dashboard, loaded from environment variables.

These settings are deliberately separate from ``soc.config.Settings``: they
describe the *presentation* layer (which data source to render, how many rows
to show) and never duplicate backend configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

DEFAULT_SOURCE: Final[str] = "sample"
DEFAULT_ANALYSIS_SOURCE: Final[str] = "disabled"
DEFAULT_PAGE_TITLE: Final[str] = "AI SOC Assistant"
DEFAULT_ALERT_LIMIT: Final[int] = 50
MIN_ALERT_LIMIT: Final[int] = 10
MAX_ALERT_LIMIT: Final[int] = 500


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class DashboardSettings:
    """Immutable dashboard settings."""

    source: str = DEFAULT_SOURCE
    analysis_source: str = DEFAULT_ANALYSIS_SOURCE
    page_title: str = DEFAULT_PAGE_TITLE
    alert_limit: int = DEFAULT_ALERT_LIMIT

    def __post_init__(self) -> None:
        if not MIN_ALERT_LIMIT <= self.alert_limit <= MAX_ALERT_LIMIT:
            raise ValueError(
                f"alert_limit must be between {MIN_ALERT_LIMIT} and {MAX_ALERT_LIMIT}, "
                f"got {self.alert_limit}"
            )

    @classmethod
    def load(cls) -> "DashboardSettings":
        """Build settings from ``DASHBOARD_*`` environment variables."""
        return cls(
            source=os.getenv("DASHBOARD_SOURCE", DEFAULT_SOURCE).strip().lower() or DEFAULT_SOURCE,
            analysis_source=(
                os.getenv("DASHBOARD_ANALYSIS_SOURCE", DEFAULT_ANALYSIS_SOURCE)
                .strip().lower() or DEFAULT_ANALYSIS_SOURCE
            ),
            page_title=os.getenv("DASHBOARD_PAGE_TITLE", DEFAULT_PAGE_TITLE),
            alert_limit=_env_int("DASHBOARD_ALERT_LIMIT", DEFAULT_ALERT_LIMIT),
        )
