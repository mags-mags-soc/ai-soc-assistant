"""Live alert source backed by the Wazuh alerts file.

Reads the *tail* of ``alerts.json`` rather than the whole file: Wazuh appends
indefinitely, so a full parse would slow the dashboard down as the file grows.
Parsing itself is delegated to ``soc.models.Alert.from_wazuh`` so the live and
sample sources produce identical objects.

Repeated alerts are collapsed on the same identity the backend uses -
rule id, description and agent name - and the occurrence count is reported
separately so the table can show it.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Final

from soc.models import Alert

from .base import DataSourceError

#: How many raw lines to scan from the end of the file before filtering.
SCAN_LINES: Final[int] = 5000

#: Bytes read per seek when walking the file backwards.
_BLOCK: Final[int] = 65536


def _tail_lines(path: Path, count: int) -> list[str]:
    """Return the last ``count`` non-empty lines of a file.

    Reads backwards in blocks so the cost stays constant as the file grows.
    Invalid bytes are replaced rather than raising: Wazuh writes raw agent
    data and Windows logs are not always valid UTF-8.
    """
    if count < 1:
        raise DataSourceError(f"count must be >= 1, got {count}")

    lines: list[bytes] = []
    remainder = b""
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            while position > 0 and len(lines) <= count:
                read_size = min(_BLOCK, position)
                position -= read_size
                handle.seek(position)
                chunk = handle.read(read_size) + remainder
                parts = chunk.split(b"\n")
                remainder = parts.pop(0)
                lines = parts + lines
            if remainder:
                lines = [remainder] + lines
    except OSError as exc:
        raise DataSourceError(f"Cannot read {path}: {exc}") from exc

    decoded = [line.decode("utf-8", errors="replace") for line in lines]
    return [line for line in decoded if line.strip()][-count:]


def fingerprint(alert: Alert) -> tuple[str, str, str]:
    """Identity used to collapse repeated alerts."""
    return (alert.rule.id, alert.rule.description, alert.agent.name)


class LiveAlertDataSource:
    """Serves recent alerts from the Wazuh alerts file."""

    name = "Wazuh alerts.json"
    is_live = True

    def __init__(
        self,
        path: Path | str,
        min_level: int = 7,
        scan_lines: int = SCAN_LINES,
    ) -> None:
        """Args:
        path: Location of the Wazuh NDJSON alerts file.
        min_level: Lowest Wazuh rule level to surface.
        scan_lines: How many trailing lines to read before filtering.
        """
        self.path = Path(path).expanduser()
        self.min_level = min_level
        self.scan_lines = scan_lines
        self._counts: dict[str, int] = {}

    @property
    def occurrences(self) -> dict[str, int]:
        """Alert id to number of times its fingerprint appeared in the window."""
        return dict(self._counts)

    def fetch_alerts(self, limit: int) -> list[Alert]:
        """Return up to ``limit`` deduplicated alerts, newest first.

        Raises:
            DataSourceError: If the file is missing or unreadable.
        """
        if limit < 1:
            raise DataSourceError(f"limit must be >= 1, got {limit}")
        if not self.path.is_file():
            raise DataSourceError(f"Wazuh alerts file not found: {self.path}")

        parsed: list[Alert] = []
        for line in _tail_lines(self.path, self.scan_lines):
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if int(raw.get("rule", {}).get("level", 0)) < self.min_level:
                continue
            try:
                parsed.append(Alert.from_wazuh(raw))
            except ValueError:
                continue

        parsed.sort(key=lambda alert: alert.timestamp, reverse=True)

        counter: Counter[tuple[str, str, str]] = Counter(
            fingerprint(alert) for alert in parsed
        )

        seen: set[tuple[str, str, str]] = set()
        unique: list[Alert] = []
        counts: dict[str, int] = {}
        for alert in parsed:
            key = fingerprint(alert)
            if key in seen:
                continue
            seen.add(key)
            counts[alert.id] = counter[key]
            unique.append(alert)
            if len(unique) >= limit:
                break

        self._counts = counts
        return unique
