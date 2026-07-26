import pytest

from soc.ai.analyzer import AlertAnalyzer
from soc.ai.exceptions import AIValidationError
from soc.ai.schemas import AIAnalysis, RiskLevel
from soc.models import Alert
from conftest import make_settings


def _alert(alert_id="1"):
    return Alert.from_wazuh({
        "id": alert_id,
        "timestamp": "2024-05-01T12:05:00.000+0000",
        "agent": {"id": "001", "name": "win-vm", "ip": "10.0.0.5"},
        "rule": {"id": "92052", "level": 12, "description": "Suspicious PowerShell",
                 "groups": ["sysmon"]},
        "full_log": "powershell.exe -enc SQBFAFgA",
        "location": "EventChannel",
    })


def _analysis():
    return AIAnalysis(
        summary="Suspicious PowerShell execution detected on win-vm host.",
        risk_level=RiskLevel.HIGH,
        risk_assessment="Encoded command suggests possible malware staging here.",
        investigation_steps=["Isolate the host.", "Decode the payload."],
        false_positive_probability=0.1,
        mitre_commentary="Maps to T1059.001.",
        confidence_score=85,
    )


class _StubClient:
    def __init__(self, result=None, exc=None):
        self._result = result
        self._exc = exc
        self.calls = 0

    def analyze(self, system_prompt, user_prompt):
        self.calls += 1
        if self._exc is not None:
            raise self._exc
        return self._result


def _analyzer(client):
    return AlertAnalyzer(config=make_settings(ai_api_key="test-key"), client=client)


def test_analyze_returns_validated_result():
    stub = _StubClient(result=_analysis())
    analyzer = _analyzer(stub)
    result = analyzer.analyze(_alert())
    assert isinstance(result, AIAnalysis)
    assert result.risk_level is RiskLevel.HIGH
    assert stub.calls == 1


def test_analyze_propagates_validation_error():
    stub = _StubClient(exc=AIValidationError("bad output"))
    analyzer = _analyzer(stub)
    with pytest.raises(AIValidationError):
        analyzer.analyze(_alert())


def test_analyze_many_collects_results():
    stub = _StubClient(result=_analysis())
    analyzer = _analyzer(stub)
    pairs = analyzer.analyze_many([_alert("1"), _alert("2")])
    assert len(pairs) == 2
    assert all(a is not None for _, a in pairs)


def test_analyze_many_tolerates_errors():
    stub = _StubClient(exc=AIValidationError("bad"))
    analyzer = _analyzer(stub)
    pairs = analyzer.analyze_many([_alert("1"), _alert("2")])
    assert len(pairs) == 2
    assert all(a is None for _, a in pairs)


def test_analyze_many_stop_on_error():
    stub = _StubClient(exc=AIValidationError("bad"))
    analyzer = _analyzer(stub)
    with pytest.raises(AIValidationError):
        analyzer.analyze_many([_alert("1")], stop_on_error=True)
