"""Pydantic schemas for validated AI analysis output.

Every AI response MUST pass validation here. Parsing/validation failures are
converted into AIValidationError by the caller so invalid AI output can never
propagate into the rest of the system.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(str, Enum):
    """Normalized risk levels the AI is allowed to return."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AIAnalysis(BaseModel):
    """Structured, validated result of analyzing a single alert.

    The model is strict: unknown fields are rejected and every field is
    range/'content' checked so malformed AI output fails fast.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    summary: str = Field(..., min_length=10, max_length=2000)
    risk_level: RiskLevel
    risk_assessment: str = Field(..., min_length=10, max_length=2000)
    investigation_steps: list[str] = Field(..., min_length=1, max_length=15)
    false_positive_probability: float = Field(..., ge=0.0, le=1.0)
    mitre_commentary: str = Field(default="", max_length=2000)
    confidence_score: int = Field(..., ge=0, le=100)

    @field_validator("investigation_steps")
    @classmethod
    def _steps_not_blank(cls, value: list[str]) -> list[str]:
        cleaned = [step.strip() for step in value if step and step.strip()]
        if not cleaned:
            raise ValueError("investigation_steps must contain at least one non-empty step")
        for step in cleaned:
            if len(step) > 500:
                raise ValueError("each investigation step must be <= 500 characters")
        return cleaned

    @property
    def false_positive_percent(self) -> int:
        """Convenience: false positive probability as an integer percentage."""
        return round(self.false_positive_probability * 100)

    def to_public_dict(self) -> dict[str, Any]:
        """Serialize for API/dashboard consumption (enum -> value)."""
        data = self.model_dump()
        data["risk_level"] = self.risk_level.value
        data["false_positive_percent"] = self.false_positive_percent
        return data
