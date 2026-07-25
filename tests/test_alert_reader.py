import pytest

from soc.alert_reader import AlertReader, AlertReaderError
from soc.severity import Severity


def test_reads_valid_alerts_and_skips_corrupt(reader):
    alerts = reader.read_all()
    assert len(alerts) == 3
    assert {a.id for a in alerts} == {"1", "2", "3"}


def test_missing_file_raises(reader):
    with pytest.raises(AlertReaderError):
        reader.read_all("/nonexistent/path/alerts.json")


def test_filter_by_severity(reader):
    alerts = reader.read_all()
    high = AlertReader.filter_by_severity(alerts, Severity.HIGH)
    assert {a.id for a in high} == {"2", "3"}


def test_filter_by_agent(reader):
    alerts = reader.read_all()
    assert {a.id for a in AlertReader.filter_by_agent(alerts, "win-vm")} == {"1", "2"}
    assert {a.id for a in AlertReader.filter_by_agent(alerts, "002")} == {"3"}


def test_filter_by_mitre(reader):
    alerts = reader.read_all()
    assert {a.id for a in AlertReader.filter_by_mitre(alerts, "T1190")} == {"3"}
    assert {a.id for a in AlertReader.filter_by_mitre(alerts, "execution")} == {"2"}


def test_search(reader):
    alerts = reader.read_all()
    assert {a.id for a in AlertReader.search(alerts, "powershell")} == {"2"}
    assert len(AlertReader.search(alerts, "")) == 3


def test_sort_by_time_newest_first(reader):
    alerts = reader.sort_by_time(reader.read_all())
    ids = [a.id for a in alerts]
    assert ids == ["3", "2", "1"]
