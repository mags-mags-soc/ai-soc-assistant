"""Alert Reader Engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Iterator

from .config import Settings, settings as default_settings
from .logging_setup import setup_logging
from .models import Alert
from .severity import Severity


class AlertReaderError(Exception):
    """Raised for unrecoverable reader errors (e.g. missing file)."""


class AlertReader:
    """Reads and queries Wazuh alerts from an NDJSON file."""

    def __init__(self, config: Settings | None = None) -> None:
        self._settings = config or default_settings
        self._log = setup_logging(self._settings.logs_dir, self._settings.log_level)

    def _resolve_path(self, path: str | Path | None) -> Path:
        target = Path(path) if path is not None else self._settings.alerts_path
        target = target.expanduser()
        if not target.exists():
            raise AlertReaderError(f"Alerts file not found: {target}")
        if not target.is_file():
            raise AlertReaderError(f"Alerts path is not a file: {target}")
        return target

    def iter_alerts(self, path: str | Path | None = None) -> Iterator[Alert]:
        """Yield normalized Alerts from the file, skipping corrupt lines."""
        target = self._resolve_path(path)
        size = target.stat().st_size
        if size > self._settings.max_read_bytes:
            self._log.warning(
                "alerts file %s is %d bytes, exceeds max_read_bytes=%d; "
                "reading anyway line-by-line (streaming)",
                target, size, self._settings.max_read_bytes,
            )

        parsed = 0
        skipped = 0
        with target.open("r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    skipped += 1
                    self._log.debug("skip line %d (bad JSON): %s", line_no, exc)
                    continue
                try:
                    yield Alert.from_wazuh(data)
                    parsed += 1
                except ValueError as exc:
                    skipped += 1
                    self._log.debug("skip line %d (bad alert): %s", line_no, exc)

        self._log.info("parsed %d alerts, skipped %d lines from %s", parsed, skipped, target)

    def read_all(self, path: str | Path | None = None) -> list[Alert]:
        """Read every alert into a list."""
        return list(self.iter_alerts(path))

    @staticmethod
    def filter_by_severity(alerts: Iterable[Alert], minimum: Severity) -> list[Alert]:
        """Return alerts at or above the given severity rank."""
        return [a for a in alerts if a.severity.rank >= minimum.rank]

    @staticmethod
    def filter_by_agent(alerts: Iterable[Alert], agent: str) -> list[Alert]:
        """Filter by agent name or id (case-insensitive)."""
        needle = agent.strip().lower()
        return [
            a for a in alerts
            if needle in a.agent.name.lower() or needle == a.agent.id.lower()
        ]

    @staticmethod
    def filter_by_mitre(alerts: Iterable[Alert], token: str) -> list[Alert]:
        """Filter by a MITRE id, tactic or technique substring (case-insensitive)."""
        needle = token.strip().lower()
        result = []
        for a in alerts:
            haystack = " ".join(a.mitre.ids + a.mitre.tactics + a.mitre.techniques).lower()
            if needle in haystack:
                result.append(a)
        return result

    @staticmethod
    def search(alerts: Iterable[Alert], term: str) -> list[Alert]:
        """Full-text search across description, full_log, agent and rule id."""
        needle = term.strip().lower()
        if not needle:
            return list(alerts)
        result = []
        for a in alerts:
            blob = " ".join([
                a.rule.description,
                a.full_log,
                a.agent.name,
                a.agent.id,
                a.rule.id,
                a.location,
            ]).lower()
            if needle in blob:
                result.append(a)
        return result

    @staticmethod
    def sort_by_time(alerts: Iterable[Alert], newest_first: bool = True) -> list[Alert]:
        return sorted(alerts, key=lambda a: a.timestamp, reverse=newest_first)


def main() -> None:
    """CLI smoke test: print a summary of the configured alerts file."""
    reader = AlertReader()
    alerts = reader.sort_by_time(reader.read_all())
    print(f"Total alerts: {len(alerts)}")
    for sev in Severity:
        count = len(AlertReader.filter_by_severity(alerts, sev))
        print(f"  >= {sev.value:8s}: {count}")
    print("\nMost recent 5:")
    for a in alerts[:5]:
        mitre = ",".join(a.mitre.techniques) or "-"
        print(f"  [{a.severity.value:8s}] {a.timestamp.isoformat()} "
              f"{a.agent.name} | {a.rule.description} | MITRE: {mitre}")


if __name__ == "__main__":
    main()
