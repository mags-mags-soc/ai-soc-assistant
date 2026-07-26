"""Custom exceptions for the AI engine module.

Hierarchy
---------
AIEngineError  (base)
├── AIConfigError          misconfiguration / missing env vars
├── AIProviderError        HTTP / network error from the provider
├── AITimeoutError         provider did not respond in time
├── AIResponseParseError   raw response is not valid JSON
└── AIValidationError      parsed JSON fails Pydantic schema  ← CRITICAL
"""
from __future__ import annotations

from typing import Any


class AIEngineError(Exception):
    """Base exception for all AI engine errors."""

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context or {}

    def __str__(self) -> str:
        if self.context:
            ctx = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{self.message} [{ctx}]"
        return self.message


class AIConfigError(AIEngineError):
    """Raised when the AI engine is misconfigured.

    Examples: unknown AI_PROVIDER value, missing API key env var.
    """


class AIProviderError(AIEngineError):
    """Raised when the AI provider returns an HTTP error or is unreachable."""


class AITimeoutError(AIEngineError):
    """Raised when the AI provider does not respond within the configured timeout."""


class AIResponseParseError(AIEngineError):
    """Raised when the raw AI response cannot be decoded as JSON.

    Attributes
    ----------
    raw_response:
        The unparseable text returned by the AI provider.
    """

    def __init__(
        self,
        message: str,
        *,
        raw_response: str = "",
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
        self.raw_response = raw_response


class AIValidationError(AIEngineError):
    """Raised when the parsed AI output fails Pydantic schema validation.

    CRITICAL CONTRACT
    -----------------
    Execution MUST NOT continue with invalid AI output.
    Any caller that catches this exception must either retry, escalate,
    or terminate the analysis — never silently ignore it.

    Attributes
    ----------
    raw_data:
        The dict that failed Pydantic validation.
    validation_errors:
        Pydantic error list; each entry is a dict with 'loc' and 'msg'.
    """

    def __init__(
        self,
        message: str,
        *,
        raw_data: dict[str, Any] | None = None,
        validation_errors: list[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context)
        self.raw_data: dict[str, Any] = raw_data or {}
        self.validation_errors: list[dict[str, Any]] = validation_errors or []

    def error_summary(self) -> str:
        """Return a human-readable summary of all validation failures."""
        if not self.validation_errors:
            return self.message
        lines = [self.message, "Validation errors:"]
        for err in self.validation_errors:
            loc = " -> ".join(str(x) for x in err.get("loc", []))
            msg = err.get("msg", "unknown error")
            lines.append(f"  \u2022 {loc}: {msg}")
        return "\n".join(lines)
