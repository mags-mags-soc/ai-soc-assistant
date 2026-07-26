import pytest

from soc.models import Alert
from soc.ai.schemas import AIAnalysis, RiskLevel
from soc.notify.exceptions import (
    NotificationConfigError,
    NotificationDeliveryError,
)
from soc.notify.telegram import TelegramNotifier, build_telegram_message


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
        summary="Suspicious PowerShell execution detected on win-vm host.",
        risk_level=RiskLevel.HIGH,
        risk_assessment="Encoded command suggests malware staging.",
        investigation_steps=["Isolate host.", "Decode payload."],
        false_positive_probability=0.1,
        mitre_commentary="Maps to T1059.001.",
        confidence_score=85,
    )


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"ok": True, "result": {}}

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, response=None, exc=None):
        self._response = response or _FakeResponse()
        self._exc = exc
        self.calls = []

    def post(self, url, json=None, timeout=None):
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        if self._exc:
            raise self._exc
        return self._response


def test_message_contains_key_fields():
    msg = build_telegram_message(_alert(), _analysis())
    assert "HIGH" in msg
    assert "win-vm" in msg
    assert "T1059.001" in msg
    assert "85/100" in msg
    assert "10%" in msg


def test_missing_config_raises():
    with pytest.raises(NotificationConfigError):
        TelegramNotifier("", "123")
    with pytest.raises(NotificationConfigError):
        TelegramNotifier("token", "")


def test_send_success():
    session = _FakeSession(_FakeResponse(200, {"ok": True, "result": {"message_id": 1}}))
    notifier = TelegramNotifier("tok", "chat", session=session)
    data = notifier.send(_alert(), _analysis())
    assert data["ok"] is True
    assert len(session.calls) == 1
    call = session.calls[0]
    assert "bottok/sendMessage" in call["url"]
    assert call["json"]["chat_id"] == "chat"
    assert call["json"]["parse_mode"] == "HTML"


def test_send_http_error_raises():
    session = _FakeSession(_FakeResponse(403, {"ok": False}))
    notifier = TelegramNotifier("tok", "chat", session=session)
    with pytest.raises(NotificationDeliveryError) as exc:
        notifier.send(_alert(), _analysis())
    assert exc.value.status_code == 403


def test_send_api_error_raises():
    session = _FakeSession(_FakeResponse(200, {"ok": False, "description": "chat not found"}))
    notifier = TelegramNotifier("tok", "chat", session=session)
    with pytest.raises(NotificationDeliveryError) as exc:
        notifier.send(_alert(), _analysis())
    assert "chat not found" in str(exc.value)


def test_send_network_exception_raises():
    import requests
    session = _FakeSession(exc=requests.ConnectionError("boom"))
    notifier = TelegramNotifier("tok", "chat", session=session)
    with pytest.raises(NotificationDeliveryError):
        notifier.send(_alert(), _analysis())
