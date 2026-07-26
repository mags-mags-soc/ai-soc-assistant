import pytest
from pydantic import ValidationError

from soc.ai.schemas import AIAnalysis, RiskLevel


def _valid_payload(**overrides):
    data = {
        "summary": "Suspicious PowerShell execution detected on win-vm.",
        "risk_level": "high",
        "risk_assessment": "Encoded command indicates possible malware staging.",
        "investigation_steps": [
            "Isolate the host win-vm from the network.",
            "Decode the base64 PowerShell payload.",
        ],
        "false_positive_probability": 0.1,
        "mitre_commentary": "Maps to T1059.001 (PowerShell).",
        "confidence_score": 85,
    }
    data.update(overrides)
    return data


def test_valid_payload_parses():
    a = AIAnalysis(**_valid_payload())
    assert a.risk_level is RiskLevel.HIGH
    assert a.false_positive_percent == 10
    assert len(a.investigation_steps) == 2


def test_to_public_dict():
    a = AIAnalysis(**_valid_payload())
    d = a.to_public_dict()
    assert d["risk_level"] == "high"
    assert d["false_positive_percent"] == 10


def test_extra_field_forbidden():
    with pytest.raises(ValidationError):
        AIAnalysis(**_valid_payload(unexpected="x"))


def test_invalid_risk_level():
    with pytest.raises(ValidationError):
        AIAnalysis(**_valid_payload(risk_level="super-bad"))


@pytest.mark.parametrize("prob", [-0.1, 1.5])
def test_false_positive_out_of_range(prob):
    with pytest.raises(ValidationError):
        AIAnalysis(**_valid_payload(false_positive_probability=prob))


@pytest.mark.parametrize("score", [-1, 101])
def test_confidence_out_of_range(score):
    with pytest.raises(ValidationError):
        AIAnalysis(**_valid_payload(confidence_score=score))


def test_empty_investigation_steps_rejected():
    with pytest.raises(ValidationError):
        AIAnalysis(**_valid_payload(investigation_steps=[]))


def test_blank_investigation_steps_rejected():
    with pytest.raises(ValidationError):
        AIAnalysis(**_valid_payload(investigation_steps=["   ", ""]))


def test_summary_too_short():
    with pytest.raises(ValidationError):
        AIAnalysis(**_valid_payload(summary="short"))


def test_mitre_commentary_optional():
    a = AIAnalysis(**_valid_payload(mitre_commentary=""))
    assert a.mitre_commentary == ""
