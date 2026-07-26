"""AI Engine – public API.

Imports are added here incrementally as each submodule is built.
Final state after Sprint 2:
    from soc.ai import AlertAnalyzer, AnalysisResult, AIValidationError
"""
# Sprint 2 – Step 1: only exceptions exist yet
from soc.ai.exceptions import (
    AIConfigError,
    AIEngineError,
    AIProviderError,
    AIResponseParseError,
    AITimeoutError,
    AIValidationError,
)

__all__ = [
    "AIEngineError",
    "AIConfigError",
    "AIProviderError",
    "AITimeoutError",
    "AIResponseParseError",
    "AIValidationError",
]
