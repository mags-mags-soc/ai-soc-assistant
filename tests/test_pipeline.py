from soc.models import Alert
from soc.ai.schemas import AIAnalysis, RiskLevel
from soc.ai.exceptions import AIEngineError
from soc.notify.exceptions import NotificationDeliveryError
from soc.pipeline import SOCPipeline


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
        summary="Suspicious PowerShell execution detected.",
        risk_level=RiskLevel.HIGH,
        risk_assessment="Encoded command suggests staging.",
        investigation_steps=["Isolate host."],
        false_positive_probability=0.1,
        mitre_commentary="Maps to T1059.001.",
        confidence_score=85,
    )


class _FakeAnalyzer:
    def __init__(self, analysis=None, exc=None):
        self._analysis = analysis
        self._exc = exc
        self.calls = 0

    def analyze(self, alert):
        self.calls += 1
        if self._exc:
            raise self._exc
        return self._analysis


class _FakeNotifier:
    def __init__(self, exc=None):
        self._exc = exc
        self.sent = 0

    def send(self, alert, analysis):
        self.sent += 1
        if self._exc:
            raise self._exc


def test_full_success_flow():
    analyzer = _FakeAnalyzer(analysis=_analysis())
    tg = _FakeNotifier()
    em = _FakeNotifier()
    written = {}

    def writer(alert, analysis):
        written["called"] = alert.id
        return f"/reports/{alert.id}.md"

    pipe = SOCPipeline(analyzer, telegram=tg, email=em, report_writer=writer)
    result = pipe.process(_alert())

    assert result.ok is True
    assert result.telegram_sent is True
    assert result.email_sent is True
    assert result.report_path == "/reports/42.md"
    assert written["called"] == "42"
    assert result.errors == {}


def test_analysis_failure_stops_pipeline():
    analyzer = _FakeAnalyzer(exc=AIEngineError("model down"))
    tg = _FakeNotifier()
    pipe = SOCPipeline(analyzer, telegram=tg)
    result = pipe.process(_alert())

    assert result.analysis is None
    assert result.ok is False
    assert "analysis" in result.errors
    assert tg.sent == 0  # never reached notification


def test_telegram_failure_is_resilient():
    analyzer = _FakeAnalyzer(analysis=_analysis())
    tg = _FakeNotifier(exc=NotificationDeliveryError("telegram down"))
    em = _FakeNotifier()
    pipe = SOCPipeline(analyzer, telegram=tg, email=em)
    result = pipe.process(_alert())

    assert result.telegram_sent is False
    assert result.email_sent is True          # email still ran
    assert "telegram" in result.errors
    assert result.ok is False                 # error recorded


def test_email_failure_is_resilient():
    analyzer = _FakeAnalyzer(analysis=_analysis())
    em = _FakeNotifier(exc=NotificationDeliveryError("smtp down"))
    pipe = SOCPipeline(analyzer, email=em)
    result = pipe.process(_alert())

    assert result.email_sent is False
    assert "email" in result.errors


def test_report_failure_is_resilient():
    analyzer = _FakeAnalyzer(analysis=_analysis())

    def bad_writer(alert, analysis):
        raise IOError("disk full")

    pipe = SOCPipeline(analyzer, report_writer=bad_writer)
    result = pipe.process(_alert())

    assert result.report_path is None
    assert "report" in result.errors


def test_optional_channels_skipped():
    analyzer = _FakeAnalyzer(analysis=_analysis())
    pipe = SOCPipeline(analyzer)  # no telegram, email or report
    result = pipe.process(_alert())

    assert result.ok is True
    assert result.telegram_sent is False
    assert result.email_sent is False
    assert result.report_path is None
