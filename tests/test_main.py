"""Tests for the command-line entry point.

The AI provider is never called: selection is tested directly and the run
path is exercised with --dry-run.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main as entry  # noqa: E402
from soc.alert_reader import AlertReader  # noqa: E402
from soc.state import ProcessedAlerts  # noqa: E402

_BASE = datetime(2026, 8, 27, 11, 0, tzinfo=timezone.utc)


def _line(index: int, level: int, rule_id: str = "92213") -> str:
    stamp = (_BASE + timedelta(seconds=index)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    return json.dumps({
        "timestamp": stamp,
        "id": f"1787{index}.0",
        "rule": {"id": rule_id, "level": level, "description": "Test alert"},
        "agent": {"id": "002", "name": "win11-lab"},
        "location": "EventChannel",
        "full_log": "test log line",
    })


@pytest.fixture()
def alerts_file(tmp_path: Path) -> Path:
    lines = [_line(i, 15) for i in range(5)]
    lines += [_line(50 + i, 5, "60106") for i in range(3)]
    lines.append(_line(90, 9, "92205"))
    path = tmp_path / "alerts.json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_min_level_excludes_low_severity(alerts_file: Path) -> None:
    selected = entry.select_alerts(
        AlertReader(), None, min_level=7, limit=100, alerts_path=str(alerts_file)
    )
    assert len(selected) == 6
    assert all(a.rule.level >= 7 for a in selected)


def test_selection_is_newest_first(alerts_file: Path) -> None:
    selected = entry.select_alerts(
        AlertReader(), None, min_level=7, limit=100, alerts_path=str(alerts_file)
    )
    stamps = [a.timestamp for a in selected]
    assert stamps == sorted(stamps, reverse=True)


def test_limit_keeps_the_newest_alerts(alerts_file: Path) -> None:
    """The limit must not hand back an arbitrary slice of a busy window."""
    everything = entry.select_alerts(
        AlertReader(), None, min_level=7, limit=100, alerts_path=str(alerts_file)
    )
    limited = entry.select_alerts(
        AlertReader(), None, min_level=7, limit=2, alerts_path=str(alerts_file)
    )
    assert [a.id for a in limited] == [a.id for a in everything[:2]]


def test_processed_alerts_are_skipped(alerts_file: Path, tmp_path: Path) -> None:
    store = ProcessedAlerts(tmp_path / "state")
    first = entry.select_alerts(
        AlertReader(), store, min_level=7, limit=1, alerts_path=str(alerts_file)
    )
    store.mark(first[0].id)

    second = entry.select_alerts(
        AlertReader(), store, min_level=7, limit=1, alerts_path=str(alerts_file)
    )
    assert second
    assert second[0].id != first[0].id


def test_everything_processed_yields_nothing(alerts_file: Path, tmp_path: Path) -> None:
    store = ProcessedAlerts(tmp_path / "state")
    for alert in entry.select_alerts(
        AlertReader(), store, min_level=7, limit=100, alerts_path=str(alerts_file)
    ):
        store.mark(alert.id)
    assert entry.select_alerts(
        AlertReader(), store, min_level=7, limit=100, alerts_path=str(alerts_file)
    ) == []


def test_invalid_limit_raises(alerts_file: Path) -> None:
    with pytest.raises(ValueError):
        entry.select_alerts(
            AlertReader(), None, min_level=7, limit=0, alerts_path=str(alerts_file)
        )


def test_default_limit_is_one() -> None:
    """An accidental bare run must bill a single analysis at most."""
    assert entry.DEFAULT_LIMIT == 1
    assert entry.build_parser().parse_args([]).limit == 1


def test_parser_reads_the_flags() -> None:
    args = entry.build_parser().parse_args(
        ["--limit", "3", "--min-level", "12", "--dry-run", "--no-state"]
    )
    assert (args.limit, args.min_level) == (3, 12)
    assert args.dry_run is True and args.no_state is True


def test_dry_run_calls_no_provider(alerts_file: Path, capsys) -> None:
    args = entry.build_parser().parse_args(
        ["--dry-run", "--no-state", "--limit", "2", "--alerts-path", str(alerts_file)]
    )
    assert entry.run(args) == 0
    assert "Would process 2 alert(s)" in capsys.readouterr().out


def test_missing_alerts_file_exits_nonzero(tmp_path: Path) -> None:
    args = entry.build_parser().parse_args(
        ["--dry-run", "--no-state", "--alerts-path", str(tmp_path / "nope.json")]
    )
    assert entry.run(args) == 1


def test_no_new_alerts_is_success(alerts_file: Path) -> None:
    args = entry.build_parser().parse_args(
        ["--dry-run", "--no-state", "--min-level", "99", "--alerts-path", str(alerts_file)]
    )
    assert entry.run(args) == 0
