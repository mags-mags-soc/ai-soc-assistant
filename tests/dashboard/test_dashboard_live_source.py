"""Tests for the live Wazuh alert source."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from dashboard.data import live as live_module
from dashboard.data.base import AlertDataSource, DataSourceError
from dashboard.data.factory import available_sources, build_data_source
from dashboard.data.live import LiveAlertDataSource, _tail_lines, fingerprint
from dashboard.settings import DashboardSettings
from soc.models import Alert

_BASE = datetime(2026, 8, 9, 12, 0, tzinfo=timezone.utc)


def wazuh_line(index: int, level: int, rule_id: str, description: str,
               agent: str = "win11-lab") -> str:
    """Build one raw Wazuh NDJSON alert line."""
    stamp = (_BASE + timedelta(seconds=index)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    return json.dumps({
        "timestamp": stamp,
        "rule": {"level": level, "description": description, "id": rule_id,
                 "groups": ["sysmon"]},
        "agent": {"id": "001", "name": agent},
        "id": f"1786{index}.0",
        "full_log": "raw log line",
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel",
    })


@pytest.fixture()
def alerts_file(tmp_path: Path) -> Path:
    """A Wazuh file with repeated noise, one high alert and sub-threshold rows."""
    lines = [wazuh_line(i, 15, "92213", "Executable file dropped") for i in range(20)]
    lines += [wazuh_line(50 + i, 5, "60106", "Windows logon success") for i in range(10)]
    lines.append(wazuh_line(80, 12, "5720", "Multiple SSH authentication failures"))
    lines.append(wazuh_line(90, 9, "92205", "Powershell created an executable", "ubuntu-wazuh"))
    path = tmp_path / "alerts.json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_source_satisfies_protocol(alerts_file: Path) -> None:
    source = LiveAlertDataSource(alerts_file)
    assert isinstance(source, AlertDataSource)
    assert source.is_live is True
    assert source.name


def test_alerts_are_backend_objects(alerts_file: Path) -> None:
    alerts = LiveAlertDataSource(alerts_file).fetch_alerts(50)
    assert alerts
    assert all(isinstance(alert, Alert) for alert in alerts)


def test_repeats_collapse_into_one_row(alerts_file: Path) -> None:
    source = LiveAlertDataSource(alerts_file, min_level=7)
    alerts = source.fetch_alerts(50)
    rule_ids = [alert.rule.id for alert in alerts]
    assert sorted(rule_ids) == ["5720", "92205", "92213"]
    assert len(rule_ids) == len(set(rule_ids))


def test_occurrence_counts_reflect_the_window(alerts_file: Path) -> None:
    source = LiveAlertDataSource(alerts_file, min_level=7)
    alerts = source.fetch_alerts(50)
    counts = source.occurrences
    noisy = next(alert for alert in alerts if alert.rule.id == "92213")
    quiet = next(alert for alert in alerts if alert.rule.id == "5720")
    assert counts[noisy.id] == 20
    assert counts[quiet.id] == 1


def test_min_level_filters_out_noise(alerts_file: Path) -> None:
    below = LiveAlertDataSource(alerts_file, min_level=13).fetch_alerts(50)
    assert {alert.rule.id for alert in below} == {"92213"}


def test_alerts_are_newest_first(alerts_file: Path) -> None:
    alerts = LiveAlertDataSource(alerts_file, min_level=7).fetch_alerts(50)
    timestamps = [alert.timestamp for alert in alerts]
    assert timestamps == sorted(timestamps, reverse=True)


def test_limit_is_respected(alerts_file: Path) -> None:
    assert len(LiveAlertDataSource(alerts_file, min_level=7).fetch_alerts(2)) == 2


def test_invalid_limit_raises(alerts_file: Path) -> None:
    with pytest.raises(DataSourceError):
        LiveAlertDataSource(alerts_file).fetch_alerts(0)


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(DataSourceError):
        LiveAlertDataSource(tmp_path / "nope.json").fetch_alerts(10)


def test_corrupt_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    path.write_text(
        "not json at all\n"
        + wazuh_line(1, 12, "5720", "Multiple SSH authentication failures") + "\n"
        + "{broken\n",
        encoding="utf-8",
    )
    alerts = LiveAlertDataSource(path, min_level=7).fetch_alerts(10)
    assert len(alerts) == 1
    assert alerts[0].rule.id == "5720"


def test_invalid_utf8_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / "alerts.json"
    good = wazuh_line(1, 12, "5720", "Multiple SSH authentication failures")
    path.write_bytes(b"\xc4\xff garbage\n" + good.encode("utf-8") + b"\n")
    alerts = LiveAlertDataSource(path, min_level=7).fetch_alerts(10)
    assert len(alerts) == 1


def test_fingerprint_identity_fields(alerts_file: Path) -> None:
    alert = LiveAlertDataSource(alerts_file, min_level=7).fetch_alerts(1)[0]
    assert fingerprint(alert) == (alert.rule.id, alert.rule.description, alert.agent.name)


def test_tail_reads_only_the_end(tmp_path: Path) -> None:
    path = tmp_path / "lines.txt"
    path.write_text("\n".join(str(i) for i in range(1000)) + "\n", encoding="utf-8")
    assert _tail_lines(path, 3) == ["997", "998", "999"]


def test_tail_rejects_invalid_count(tmp_path: Path) -> None:
    path = tmp_path / "lines.txt"
    path.write_text("a\n", encoding="utf-8")
    with pytest.raises(DataSourceError):
        _tail_lines(path, 0)


def test_factory_builds_the_live_source(alerts_file: Path) -> None:
    settings = DashboardSettings(source="live", alerts_path=str(alerts_file), min_level=7)
    source = build_data_source(settings)
    assert isinstance(source, LiveAlertDataSource)
    assert source.min_level == 7
    assert "live" in available_sources()


def test_sample_source_reports_no_occurrences() -> None:
    from dashboard.data.sample import SampleAlertDataSource

    assert SampleAlertDataSource().occurrences == {}


def test_settings_read_live_config_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DASHBOARD_SOURCE", "LIVE")
    monkeypatch.setenv("DASHBOARD_MIN_LEVEL", "11")
    monkeypatch.setenv("DASHBOARD_ALERTS_PATH", "/tmp/x.json")
    settings = DashboardSettings.load()
    assert settings.source == "live"
    assert settings.min_level == 11
    assert settings.alerts_path == "/tmp/x.json"


# --- Sprint 4.3b: group expansion ---------------------------------------------

def test_fetch_group_returns_every_member(alerts_file: Path) -> None:
    source = LiveAlertDataSource(alerts_file, min_level=7)
    alerts = source.fetch_alerts(50)
    noisy = next(alert for alert in alerts if alert.rule.id == "92213")
    assert len(source.fetch_group(noisy.id)) == 20


def test_group_members_share_the_fingerprint(alerts_file: Path) -> None:
    source = LiveAlertDataSource(alerts_file, min_level=7)
    noisy = next(a for a in source.fetch_alerts(50) if a.rule.id == "92213")
    members = source.fetch_group(noisy.id)
    assert {fingerprint(alert) for alert in members} == {fingerprint(noisy)}


def test_group_members_are_distinct_events(alerts_file: Path) -> None:
    """Each member is a real event with its own id and raw payload."""
    source = LiveAlertDataSource(alerts_file, min_level=7)
    noisy = next(a for a in source.fetch_alerts(50) if a.rule.id == "92213")
    members = source.fetch_group(noisy.id)
    assert len({alert.id for alert in members}) == len(members)
    assert all(alert.raw for alert in members)


def test_group_is_newest_first_and_led_by_the_representative(alerts_file: Path) -> None:
    source = LiveAlertDataSource(alerts_file, min_level=7)
    noisy = next(a for a in source.fetch_alerts(50) if a.rule.id == "92213")
    members = source.fetch_group(noisy.id)
    timestamps = [alert.timestamp for alert in members]
    assert timestamps == sorted(timestamps, reverse=True)
    assert members[0].id == noisy.id


def test_single_occurrence_group_has_one_member(alerts_file: Path) -> None:
    source = LiveAlertDataSource(alerts_file, min_level=7)
    quiet = next(a for a in source.fetch_alerts(50) if a.rule.id == "5720")
    assert [alert.id for alert in source.fetch_group(quiet.id)] == [quiet.id]


def test_fetch_group_before_fetch_alerts_is_empty(alerts_file: Path) -> None:
    assert LiveAlertDataSource(alerts_file).fetch_group("1786000.0") == []


def test_fetch_group_unknown_id_is_empty(alerts_file: Path) -> None:
    source = LiveAlertDataSource(alerts_file, min_level=7)
    source.fetch_alerts(50)
    assert source.fetch_group("does-not-exist") == []


def test_groups_are_rebuilt_on_every_fetch(alerts_file: Path) -> None:
    """A representative from an earlier window must not linger."""
    source = LiveAlertDataSource(alerts_file, min_level=7)
    everything = source.fetch_alerts(50)
    survivors = {alert.id for alert in source.fetch_alerts(1)}
    dropped = [alert for alert in everything if alert.id not in survivors]
    assert dropped, "the narrowed window must drop at least one group"
    assert all(source.fetch_group(alert.id) == [] for alert in dropped)


def test_group_retention_limit_keeps_the_count_honest(
    alerts_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Truncating retained members must not distort the occurrence count."""
    monkeypatch.setattr(live_module, "MAX_GROUP_MEMBERS", 5)
    source = LiveAlertDataSource(alerts_file, min_level=7)
    noisy = next(a for a in source.fetch_alerts(50) if a.rule.id == "92213")
    assert len(source.fetch_group(noisy.id)) == 5
    assert source.occurrences[noisy.id] == 20
