from datetime import datetime

import pytest

from soc.models import Alert
from soc.severity import Severity


def test_from_wazuh_full_payload():
    data = {
        "id": "42",
        "timestamp": "2024-05-01T12:05:00.000+0000",
        "agent": {"id": "001", "name": "win-vm", "ip": "10.0.0.5"},
        "rule": {
            "id": "92052",
            "level": 12,
            "description": "Suspicious PowerShell",
            "groups": ["sysmon", "windows"],
            "mitre": {
                "id": ["T1059.001"],
                "tactic": ["Execution"],
                "technique": ["PowerShell"],
            },
        },
        "full_log": "powershell.exe -enc ...",
        "location": "EventChannel",
    }
    alert = Alert.from_wazuh(data)

    assert alert.id == "42"
    assert alert.severity is Severity.HIGH
    assert alert.agent.name == "win-vm"
    assert alert.rule.level == 12
    assert alert.mitre.techniques == ["PowerShell"]
    assert isinstance(alert.timestamp, datetime)


def test_from_wazuh_missing_fields_uses_defaults():
    alert = Alert.from_wazuh({"rule": {"level": 2}})
    assert alert.severity is Severity.INFO
    assert alert.agent.name == "unknown"
    assert alert.mitre.is_empty


def test_from_wazuh_rejects_non_dict():
    with pytest.raises(ValueError):
        Alert.from_wazuh(["not", "a", "dict"])


def test_timestamp_offset_normalization():
    alert = Alert.from_wazuh(
        {"timestamp": "2024-05-01T12:00:00.000+0000", "rule": {"level": 1}}
    )
    assert alert.timestamp.year == 2024 and alert.timestamp.month == 5
