"""Page renderers, keyed by :class:`~dashboard.navigation.Page`."""

from __future__ import annotations

from typing import Callable, Final, Sequence

from soc.models import Alert

from ..data.base import AlertDataSource
from ..navigation import PAGE_SUBTITLES, PAGE_TITLES, Page
from . import alerts as alerts_view
from . import overview as overview_view

PageRenderer = Callable[[Sequence[Alert], AlertDataSource], None]

PAGE_RENDERERS: Final[dict[Page, PageRenderer]] = {
    Page.OVERVIEW: overview_view.render,
    Page.ALERTS: alerts_view.render,
}

__all__ = ["PAGE_RENDERERS", "PAGE_SUBTITLES", "PAGE_TITLES", "Page", "PageRenderer"]
