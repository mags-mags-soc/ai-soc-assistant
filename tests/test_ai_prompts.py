import json

from soc.ai.prompts import SYSTEM_PROMPT, build_user_prompt
from soc.models import Alert


def _alert():
    return Alert.from_wazuh({
        "id": "42",
        "timestamp": "2024-05-01T12:05:00.000+0000",
        "agent": {"id": "001", "name": "win-vm", "ip": "10.0.0.5"},
        "rule": {
            "id": "92052", "level": 12,
            "description": "Suspicious PowerShell",
            "groups": ["sysmon"],
            "mitre": {"id": ["T1059.001"], "tactic": ["Execution"],
                      "technique": ["PowerShell"]},
        },
        "full_log": "powershell.exe -enc SQBFAFgA",
        "location": "EventChannel",
    })


def test_system_prompt_mentions_json_and_keys():
    for key in ["summary", "risk_level", "investigation_steps",
                "false_positive_probability", "confidence_score"]:
        assert key in SYSTEM_PROMPT
    assert "JSON" in SYSTEM_PROMPT


def test_user_prompt_contains_valid_json_block():
    prompt = build_user_prompt(_alert())
    assert "ALERT DATA:" in prompt
    payload = prompt.split("ALERT DATA:", 1)[1].strip()
    data = json.loads(payload)
    assert data["alert_id"] == "42"
    assert data["rule"]["id"] == "92052"
    assert data["mitre"]["techniques"] == ["PowerShell"]


def test_user_prompt_truncates_long_log():
    alert = _alert()
    alert.full_log = "A" * 5000
    prompt = build_user_prompt(alert)
    assert "[truncated]" in prompt
    assert "A" * 5000 not in prompt
