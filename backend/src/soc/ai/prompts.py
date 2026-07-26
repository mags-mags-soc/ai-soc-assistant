"""Prompt construction for AI alert analysis.

The system prompt pins the model to a senior SOC analyst persona and forces a
strict JSON schema. The user prompt injects only sanitized, relevant alert
fields to keep the context tight and deterministic.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc.models import Alert

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst \
with deep expertise in threat detection, incident response, and the MITRE \
ATT&CK framework.

You analyze a single security alert and produce a concise, actionable triage.

You MUST respond with a single valid JSON object and nothing else. No markdown, \
no code fences, no commentary before or after the JSON.

The JSON object MUST have EXACTLY these keys:
- "summary": string. A clear 2-4 sentence explanation of what the alert means.
- "risk_level": one of "info", "low", "medium", "high", "critical".
- "risk_assessment": string. Why this risk level; potential impact.
- "investigation_steps": array of 1-10 short, concrete analyst actions.
- "false_positive_probability": number between 0.0 and 1.0.
- "mitre_commentary": string. Interpretation of any MITRE ATT&CK mapping (may be empty).
- "confidence_score": integer between 0 and 100 (your confidence in this analysis).

Do not invent facts not supported by the alert data. If information is missing, \
state the uncertainty and lower your confidence_score accordingly."""


def build_user_prompt(alert: "Alert") -> str:
    """Build the user prompt containing the sanitized alert context."""
    context = {
        "alert_id": alert.id,
        "timestamp": alert.timestamp.isoformat(),
        "severity": alert.severity.value,
        "rule": {
            "id": alert.rule.id,
            "level": alert.rule.level,
            "description": alert.rule.description,
            "groups": alert.rule.groups,
        },
        "agent": {
            "id": alert.agent.id,
            "name": alert.agent.name,
            "ip": alert.agent.ip,
        },
        "mitre": {
            "ids": alert.mitre.ids,
            "tactics": alert.mitre.tactics,
            "techniques": alert.mitre.techniques,
        },
        "location": alert.location,
        "full_log": _truncate(alert.full_log, 1500),
    }
    payload = json.dumps(context, ensure_ascii=False, indent=2)
    return (
        "Analyze the following security alert and respond with the required "
        "JSON object only.\n\n"
        f"ALERT DATA:\n{payload}"
    )


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + " …[truncated]"
