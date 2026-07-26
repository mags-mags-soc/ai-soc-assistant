import json
from types import SimpleNamespace

import pytest

from soc.ai.client import AIClient
from soc.ai.exceptions import (
    AIConfigError,
    AIProviderError,
    AIResponseParseError,
    AIValidationError,
)
from soc.ai.schemas import AIAnalysis
from conftest import make_settings


def _valid_json() -> str:
    return json.dumps({
        "summary": "Suspicious PowerShell execution detected on win-vm.",
        "risk_level": "high",
        "risk_assessment": "Encoded command indicates possible malware staging.",
        "investigation_steps": ["Isolate host.", "Decode the payload."],
        "false_positive_probability": 0.1,
        "mitre_commentary": "Maps to T1059.001.",
        "confidence_score": 85,
    })


class _FakeCompletions:
    def __init__(self, content=None, exc=None, sequence=None):
        self._content = content
        self._exc = exc
        self._sequence = list(sequence or [])
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        if self._sequence:
            item = self._sequence.pop(0)
            if isinstance(item, Exception):
                raise item
            content = item
        elif self._exc is not None:
            raise self._exc
        else:
            content = self._content
        msg = SimpleNamespace(content=content)
        choice = SimpleNamespace(message=msg)
        return SimpleNamespace(choices=[choice])


def _client_with(fake_completions) -> AIClient:
    cfg = make_settings(ai_api_key="test-key", ai_max_retries=3)
    client = AIClient(cfg)
    client._client = SimpleNamespace(
        chat=SimpleNamespace(completions=fake_completions)
    )
    return client


def test_missing_api_key_raises():
    client = AIClient(make_settings(ai_api_key=""))
    with pytest.raises(AIConfigError):
        client.analyze("sys", "user")


def test_valid_response_returns_analysis():
    client = _client_with(_FakeCompletions(content=_valid_json()))
    result = client.analyze("sys", "user")
    assert isinstance(result, AIAnalysis)
    assert result.risk_level.value == "high"


def test_invalid_schema_raises_validation_error():
    bad = json.dumps({"summary": "short", "risk_level": "high"})
    client = _client_with(_FakeCompletions(content=bad))
    with pytest.raises(AIValidationError):
        client.analyze("sys", "user")


def test_non_json_response_raises_parse_error():
    client = _client_with(_FakeCompletions(content="I cannot help with that."))
    with pytest.raises(AIResponseParseError):
        client.analyze("sys", "user")


def test_json_inside_code_fence_is_extracted():
    fenced = f"```json\n{_valid_json()}\n```"
    client = _client_with(_FakeCompletions(content=fenced))
    result = client.analyze("sys", "user")
    assert result.confidence_score == 85


def test_retry_then_success():
    seq = [RuntimeError("transient 500"), _valid_json()]
    fake = _FakeCompletions(sequence=seq)
    client = _client_with(fake)
    result = client.analyze("sys", "user")
    assert isinstance(result, AIAnalysis)
    assert fake.calls == 2


def test_provider_error_after_all_retries():
    fake = _FakeCompletions(exc=RuntimeError("boom"))
    client = _client_with(fake)
    with pytest.raises(AIProviderError):
        client.analyze("sys", "user")
    assert fake.calls == 3


def test_empty_response_raises_parse_error():
    fake = _FakeCompletions(content="   ")
    client = _client_with(fake)
    with pytest.raises(AIResponseParseError):
        client.analyze("sys", "user")
