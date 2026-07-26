from datetime import datetime, timezone

import pytest

from soc.models import Alert
from soc.ai.schemas import AIAnalysis, RiskLevel
from soc.report.markdown_report import (
    ReportError,
    build_markdown_report,
    write_markdown_report,
)


def _alert(alert_id="42"):
    return Alert.from_wazuh({
        "id": alert_id,
        "timestamp": "2024-05-01T12:05:00.000+0000",
        "agent": {"id": "001", "name": "win-vm", "ip": "10.0.0.5"},
        "rule": {"id": "92052", "level": 12, "description": "Suspicious PowerShell",
                 "groups": ["sysmon"],
                 "mitre": {"id": ["T1059.001"], "tactic": ["Execution"],
                           "technique": ["PowerShell"]}},
        "full_log": "powershell.exe -enc SQBFAFgA",
        "location": "EventChannel",
    })


def _analysis():
    return AIAnalysis(
        summary="Suspicious PowerShell execution detected on win-vm host system.",
        risk_level=RiskLevel.HIGH,
        risk_assessment="Encoded command suggests possible malware staging activity.",
        investigation_steps=["Isolate the host.", "Decode the base64 payload."],
        false_positive_probability=0.1,
        mitre_commentary="Maps to T1059.001 (PowerShell).",
        confidence_score=85,
    )


def test_report_contains_key_sections():
    md = build_markdown_report(_alert(), _analysis())
    assert "# 🛡️ Incident Report — Alert 42" in md
    assert "## 📋 Alert Details" in md
    assert "## 🤖 AI Analysis" in md
    assert "### 🔍 Investigation Steps" in md
    assert "## 📄 Raw Log" in md


def test_report_includes_analysis_values():
    md = build_markdown_report(_alert(), _analysis())
    assert "HIGH" in md
    assert "85/100" in md
    assert "10%" in md
    assert "T1059.001" in md
    assert "1. Isolate the host." in md
    assert "2. Decode the base64 payload." in md


def test_report_deterministic_with_fixed_time():
    ts = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    md1 = build_markdown_report(_alert(), _analysis(), generated_at=ts)
    md2 = build_markdown_report(_alert(), _analysis(), generated_at=ts)
    assert md1 == md2
    assert "2024-05-01 12:00:00 UTC" in md1


def test_empty_mitre_commentary_placeholder():
    analysis = _analysis()
    object.__setattr__(analysis, "mitre_commentary", "")
    md = build_markdown_report(_alert(), analysis)
    assert "_No MITRE commentary provided._" in md


def test_long_log_truncated():
    alert = _alert()
    alert.full_log = "A" * 5000
    md = build_markdown_report(alert, _analysis())
    assert "[truncated]" in md


def test_missing_inputs_raise():
    with pytest.raises(ReportError):
        build_markdown_report(None, _analysis())
    with pytest.raises(ReportError):
        build_markdown_report(_alert(), None)


def test_write_report_creates_file(tmp_path):
    path = write_markdown_report(_alert("7"), _analysis(), tmp_path / "reports")
    assert path.exists()
    assert path.name == "incident_7.md"
    assert "Incident Report" in path.read_text(encoding="utf-8")
