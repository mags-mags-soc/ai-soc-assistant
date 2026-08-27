"""Remembering which alerts have already been through the pipeline.

Without this, a scheduled run would re-analyze every alert still inside the
read window: the same alert would be billed to the AI provider again and the
same notification would be delivered again. The store answers one question -
"have I handled this alert id before?" - and nothing else. Whether a *rule*
is too noisy is a detection tuning problem, not a state problem.

Entries older than the retention period are dropped on load so the file
cannot grow without bound.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Final

logger = logging.getLogger(__name__)

#: File name created inside the configured state directory.
STATE_FILENAME: Final[str] = "processed_alerts.json"

#: How long a processed alert id is remembered.
DEFAULT_RETENTION_DAYS: Final[int] = 30


class StateError(RuntimeError):
    """Raised when the state file cannot be read or written."""


class ProcessedAlerts:
    """Tracks alert ids that the pipeline has already handled."""

    def __init__(
        self,
        state_dir: Path | str,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        """Args:
        state_dir: Directory holding the state file. Created if missing.
        retention_days: Entries older than this are forgotten on load.
        """
        if retention_days < 1:
            raise StateError(f"retention_days must be >= 1, got {retention_days}")
        self.path = Path(state_dir).expanduser() / STATE_FILENAME
        self.retention_days = retention_days
        self._entries: dict[str, str] = self._load()

    def _load(self) -> dict[str, str]:
        """Read the state file, dropping entries past the retention window."""
        if not self.path.is_file():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # A corrupt state file must not stop the pipeline: the worst case
            # is that some alerts are processed a second time.
            logger.warning("ignoring unreadable state file %s: %s", self.path, exc)
            return {}
        if not isinstance(raw, dict):
            logger.warning("state file %s is not an object; ignoring", self.path)
            return {}

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        kept: dict[str, str] = {}
        for alert_id, stamp in raw.items():
            try:
                when = datetime.fromisoformat(str(stamp))
            except ValueError:
                continue
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when >= cutoff:
                kept[str(alert_id)] = when.isoformat()
        return kept

    def __len__(self) -> int:
        """Number of remembered alert ids."""
        return len(self._entries)

    def is_processed(self, alert_id: str) -> bool:
        """Return ``True`` if this alert id was handled before."""
        return alert_id in self._entries

    def mark(self, alert_id: str, when: datetime | None = None) -> None:
        """Record an alert id as handled. Call :meth:`save` to persist."""
        stamp = when or datetime.now(timezone.utc)
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        self._entries[alert_id] = stamp.isoformat()

    def save(self) -> None:
        """Write the state file atomically.

        Raises:
            StateError: If the directory or file cannot be written.
        """
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle, tmp_name = tempfile.mkstemp(
                dir=self.path.parent, prefix=".state-", suffix=".tmp"
            )
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(self._entries, fh, indent=2, sort_keys=True)
            os.replace(tmp_name, self.path)
        except OSError as exc:
            raise StateError(f"Cannot write state file {self.path}: {exc}") from exc
