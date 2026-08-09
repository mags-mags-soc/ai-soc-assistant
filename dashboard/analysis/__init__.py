"""AI analysis sources consumed by the dashboard."""

from __future__ import annotations

from .analyzer_source import AnalyzerAnalysisSource
from .base import AnalysisError, AnalysisSource
from .disabled import DisabledAnalysisSource
from .factory import available_analysis_sources, build_analysis_source

__all__ = [
    "AnalysisError",
    "AnalysisSource",
    "AnalyzerAnalysisSource",
    "DisabledAnalysisSource",
    "available_analysis_sources",
    "build_analysis_source",
]
