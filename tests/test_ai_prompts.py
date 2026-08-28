import json

from soc.ai.prompts import SYSTEM_PROMPT, build_user_prompt, decoded_event_fields
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


def _sysmon_alert(**eventdata):
    """An EventChannel alert with no full_log, like a real Sysmon event."""
    fields = {
        "targetFilename": "C:\\Users\\magsu\\AppData\\Local\\Temp\\dropper.exe",
        "image": "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
        "user": "M313M\\magsu",
        "processId": "17768",
    }
    fields.update(eventdata)
    return Alert.from_wazuh({
        "id": "1786281753.128285",
        "timestamp": "2026-08-09T13:22:33.622+0000",
        "agent": {"id": "002", "name": "win11-lab", "ip": "10.0.0.77"},
        "rule": {
            "id": "92213", "level": 15,
            "description": "Executable file dropped in folder commonly used by malware",
            "groups": ["sysmon", "sysmon_eid11_detections", "windows"],
            "mitre": {"id": ["T1105"], "tactic": ["Command and Control"],
                      "technique": ["Ingress Tool Transfer"]},
        },
        "location": "EventChannel",
        "data": {"win": {"eventdata": fields}},
    })


def _payload(alert):
    """Return the JSON context the model receives."""
    prompt = build_user_prompt(alert)
    return json.loads(prompt.split("ALERT DATA:", 1)[1].strip())


def test_decoded_event_fields_read_the_sysmon_data_block():
    fields = decoded_event_fields(_sysmon_alert())
    assert fields["targetFilename"].endswith("dropper.exe")
    assert fields["user"] == "M313M\\magsu"


def test_decoded_event_fields_ignore_unknown_and_non_string_values():
    fields = decoded_event_fields(_sysmon_alert(ruleName="-", utcTime=12345))
    assert "ruleName" not in fields
    assert "utcTime" not in fields


def test_decoded_event_fields_empty_without_a_data_block():
    assert decoded_event_fields(_alert()) == {}


def test_decoded_event_fields_survive_a_malformed_data_block():
    alert = _alert()
    alert.raw = {"data": "not a mapping"}
    assert decoded_event_fields(alert) == {}


def test_sysmon_prompt_carries_the_file_name():
    """Without this the model triages a file-creation alert with no file name."""
    data = _payload(_sysmon_alert())
    assert data["event_data"]["targetFilename"].endswith("dropper.exe")
    assert "full_log" not in data


def test_full_log_alerts_are_unchanged():
    data = _payload(_alert())
    assert data["full_log"] == "powershell.exe -enc SQBFAFgA"
    assert "event_data" not in data


def test_prompt_reports_an_empty_log_when_there_is_nothing_to_send():
    alert = _alert()
    alert.full_log = ""
    alert.raw = {}
    assert _payload(alert)["full_log"] == ""


def test_decoded_event_field_values_are_truncated():
    alert = _sysmon_alert(commandLine="A" * 900)
    assert "[truncated]" in decoded_event_fields(alert)["commandLine"]
