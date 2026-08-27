"""Tests for the processed-alert store."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc.state import STATE_FILENAME, ProcessedAlerts, StateError


def test_new_store_is_empty(tmp_path: Path) -> None:
    store = ProcessedAlerts(tmp_path)
    assert len(store) == 0
    assert store.is_processed("anything") is False


def test_marked_ids_survive_a_reload(tmp_path: Path) -> None:
    store = ProcessedAlerts(tmp_path)
    store.mark("1786281753.128285")
    store.mark("1786281753.128286")
    store.save()

    reloaded = ProcessedAlerts(tmp_path)
    assert len(reloaded) == 2
    assert reloaded.is_processed("1786281753.128285") is True
    assert reloaded.is_processed("never-seen") is False


def test_save_creates_the_directory(tmp_path: Path) -> None:
    target = tmp_path / "does" / "not" / "exist"
    store = ProcessedAlerts(target)
    store.mark("a")
    store.save()
    assert (target / STATE_FILENAME).is_file()


def test_entries_past_retention_are_forgotten(tmp_path: Path) -> None:
    store = ProcessedAlerts(tmp_path, retention_days=30)
    store.mark("fresh")
    store.mark("ancient", when=datetime.now(timezone.utc) - timedelta(days=90))
    store.save()

    reloaded = ProcessedAlerts(tmp_path, retention_days=30)
    assert reloaded.is_processed("fresh") is True
    assert reloaded.is_processed("ancient") is False


def test_retention_boundary_is_inclusive(tmp_path: Path) -> None:
    store = ProcessedAlerts(tmp_path, retention_days=30)
    store.mark("edge", when=datetime.now(timezone.utc) - timedelta(days=29))
    store.save()
    assert ProcessedAlerts(tmp_path, retention_days=30).is_processed("edge") is True


def test_naive_timestamps_are_treated_as_utc(tmp_path: Path) -> None:
    store = ProcessedAlerts(tmp_path)
    store.mark("naive", when=datetime.now())
    store.save()
    assert ProcessedAlerts(tmp_path).is_processed("naive") is True


def test_corrupt_state_file_does_not_raise(tmp_path: Path) -> None:
    """A damaged file costs a repeat analysis, not a failed run."""
    (tmp_path / STATE_FILENAME).write_text("{not json", encoding="utf-8")
    store = ProcessedAlerts(tmp_path)
    assert len(store) == 0


def test_non_object_state_file_is_ignored(tmp_path: Path) -> None:
    (tmp_path / STATE_FILENAME).write_text('["a", "b"]', encoding="utf-8")
    assert len(ProcessedAlerts(tmp_path)) == 0


def test_unparseable_timestamp_entry_is_dropped(tmp_path: Path) -> None:
    (tmp_path / STATE_FILENAME).write_text(
        json.dumps({"good": datetime.now(timezone.utc).isoformat(), "bad": "nope"}),
        encoding="utf-8",
    )
    store = ProcessedAlerts(tmp_path)
    assert store.is_processed("good") is True
    assert store.is_processed("bad") is False


def test_invalid_retention_rejected(tmp_path: Path) -> None:
    with pytest.raises(StateError):
        ProcessedAlerts(tmp_path, retention_days=0)


def test_save_leaves_no_temporary_files(tmp_path: Path) -> None:
    """Writes are atomic; a partial file must never remain."""
    store = ProcessedAlerts(tmp_path)
    store.mark("a")
    store.save()
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".state-")]
    assert leftovers == []
