import smtplib

import pytest

from soc.models import Alert
from soc.ai.schemas import AIAnalysis, RiskLevel
from soc.notify.exceptions import NotificationConfigError, NotificationDeliveryError
from soc.notify.email import EmailNotifier, build_email_html


def _alert():
    return Alert.from_wazuh({
        "id": "42",
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
        summary="Suspicious PowerShell execution detected.",
        risk_level=RiskLevel.HIGH,
        risk_assessment="Encoded command suggests staging.",
        investigation_steps=["Isolate host.", "Decode payload."],
        false_positive_probability=0.1,
        mitre_commentary="Maps to T1059.001.",
        confidence_score=85,
    )


class _FakeSMTP:
    def __init__(self, fail_on=None):
        self.fail_on = fail_on
        self.events = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def starttls(self):
        self.events.append("starttls")
        if self.fail_on == "starttls":
            raise smtplib.SMTPException("tls failed")

    def login(self, user, pwd):
        self.events.append(("login", user))
        if self.fail_on == "login":
            raise smtplib.SMTPAuthenticationError(535, b"bad creds")

    def send_message(self, msg):
        self.events.append(("send", msg["To"], msg["Subject"]))
        if self.fail_on == "send":
            raise smtplib.SMTPException("send failed")


def _notifier(fake, **kw):
    return EmailNotifier(
        host="smtp.test", port=587, username="user", password="pw",
        sender="soc@test", recipients=["a@test", "b@test"],
        smtp_factory=lambda: fake, **kw,
    )


def test_html_contains_key_fields():
    html = build_email_html(_alert(), _analysis())
    assert "HIGH" in html
    assert "win-vm" in html
    assert "T1059.001" in html
    assert "Isolate host." in html


def test_config_validation():
    with pytest.raises(NotificationConfigError):
        EmailNotifier(host="", port=25, username="", password="",
                      sender="x@test", recipients=["a@test"])
    with pytest.raises(NotificationConfigError):
        EmailNotifier(host="h", port=25, username="", password="",
                      sender="x@test", recipients=[])


def test_send_success_with_tls_and_login():
    fake = _FakeSMTP()
    _notifier(fake).send(_alert(), _analysis())
    assert "starttls" in fake.events
    assert ("login", "user") in fake.events
    sent = [e for e in fake.events if e[0] == "send"][0]
    assert "a@test, b@test" == sent[1]
    assert sent[2].startswith("[SOC HIGH]")


def test_send_without_tls_or_login():
    fake = _FakeSMTP()
    _notifier(fake, use_tls=False).__dict__  # sanity
    notifier = EmailNotifier(
        host="h", port=25, username="", password="",
        sender="s@test", recipients=["a@test"],
        use_tls=False, smtp_factory=lambda: fake,
    )
    notifier.send(_alert(), _analysis())
    assert "starttls" not in fake.events
    assert all(not (isinstance(e, tuple) and e[0] == "login") for e in fake.events)


def test_login_failure_raises():
    fake = _FakeSMTP(fail_on="login")
    with pytest.raises(NotificationDeliveryError):
        _notifier(fake).send(_alert(), _analysis())


def test_send_failure_raises():
    fake = _FakeSMTP(fail_on="send")
    with pytest.raises(NotificationDeliveryError):
        _notifier(fake).send(_alert(), _analysis())
