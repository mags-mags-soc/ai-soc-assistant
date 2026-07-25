"""MITRE ATT&CK extraction helpers."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class MitreMapping(BaseModel):
    """Normalized MITRE ATT&CK mapping for an alert."""

    ids: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.ids or self.tactics or self.techniques)


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()]


def extract_mitre(rule: dict[str, Any]) -> MitreMapping:
    """Extract a MitreMapping from a Wazuh rule dict."""
    mitre = rule.get("mitre") or {}
    if not isinstance(mitre, dict):
        return MitreMapping()
    return MitreMapping(
        ids=_as_str_list(mitre.get("id")),
        tactics=_as_str_list(mitre.get("tactic")),
        techniques=_as_str_list(mitre.get("technique")),
    )
