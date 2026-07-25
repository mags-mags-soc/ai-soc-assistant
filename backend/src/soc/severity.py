"""Severity mapping from Wazuh rule levels to SOC severity bands."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """SOC-facing severity bands with associated hex colors for the dashboard."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def color(self) -> str:
        return _SEVERITY_COLORS[self]

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_COLORS = {
    Severity.INFO: "#3b82f6",
    Severity.LOW: "#22c55e",
    Severity.MEDIUM: "#eab308",
    Severity.HIGH: "#f97316",
    Severity.CRITICAL: "#ef4444",
}

_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_from_level(level: int) -> Severity:
    """Map a Wazuh rule.level (0-15) to a SOC severity band."""
    if level < 0:
        raise ValueError(f"rule.level cannot be negative: {level}")
    if level <= 3:
        return Severity.INFO
    if level <= 6:
        return Severity.LOW
    if level <= 9:
        return Severity.MEDIUM
    if level <= 12:
        return Severity.HIGH
    return Severity.CRITICAL
