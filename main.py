#!/usr/bin/env python3
"""Command-line entry point: run new alerts through the SOC pipeline.

Designed to be called by a scheduler (cron or a systemd timer). Each run reads
the configured Wazuh alerts file, skips everything already handled in an
earlier run, and pushes what is left through analysis, notification and
reporting.

    python main.py --dry-run          # show what would be processed
    python main.py --limit 1          # process a single alert
    python main.py --min-level 12     # only high-severity alerts

Exit code is 0 when every processed alert succeeded and 1 otherwise, so a
scheduler can detect failures.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_SRC = PROJECT_ROOT / "backend" / "src"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from soc.ai.analyzer import AlertAnalyzer  # noqa: E402
from soc.alert_reader import AlertReader, AlertReaderError  # noqa: E402
from soc.config import settings as default_settings  # noqa: E402
from soc.models import Alert  # noqa: E402
from soc.notify.email import EmailNotifier  # noqa: E402
from soc.notify.exceptions import NotificationConfigError  # noqa: E402
from soc.notify.telegram import TelegramNotifier  # noqa: E402
from soc.pipeline import SOCPipeline  # noqa: E402
from soc.report.markdown_report import write_markdown_report  # noqa: E402
from soc.state import ProcessedAlerts, StateError  # noqa: E402

#: Alerts processed in one run unless --limit says otherwise. One by default:
#: every alert costs an AI call, so an accidental run bills the minimum.
DEFAULT_LIMIT = 1

#: Lowest Wazuh rule level considered worth a pipeline run.
DEFAULT_MIN_LEVEL = 7

log = logging.getLogger("soc.main")


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Run new Wazuh alerts through the SOC pipeline.",
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help=f"max alerts to process (default: {DEFAULT_LIMIT})")
    parser.add_argument("--min-level", type=int, default=DEFAULT_MIN_LEVEL,
                        help=f"lowest rule level (default: {DEFAULT_MIN_LEVEL})")
    parser.add_argument("--alerts-path", default=None,
                        help="override the configured alerts file")
    parser.add_argument("--dry-run", action="store_true",
                        help="list what would be processed, call no provider")
    parser.add_argument("--no-state", action="store_true",
                        help="ignore and do not update the processed-alert store")
    parser.add_argument("--verbose", action="store_true",
                        help="log at DEBUG level")
    return parser


def select_alerts(
    reader: AlertReader,
    state: ProcessedAlerts | None,
    min_level: int,
    limit: int,
    alerts_path: str | None = None,
) -> list[Alert]:
    """Return the alerts this run should handle, newest first.

    Selection is: level threshold, then already-processed ids, then the limit.
    Ordering happens before the limit so a busy window still yields the most
    recent alerts rather than an arbitrary slice.
    """
    if limit < 1:
        raise ValueError(f"limit must be >= 1, got {limit}")

    alerts = reader.read_all(alerts_path)
    candidates = [a for a in alerts if a.rule.level >= min_level]
    if state is not None:
        candidates = [a for a in candidates if not state.is_processed(a.id)]
    return AlertReader.sort_by_time(candidates)[:limit]


def build_pipeline(config=default_settings) -> SOCPipeline:
    """Construct the pipeline with whichever channels are configured.

    Every channel is optional and the pipeline treats a missing one as "skip
    this step", so an unconfigured lab still gets analysis and reports.
    """
    telegram = None
    if config.telegram_token and config.telegram_chat_id:
        try:
            telegram = TelegramNotifier(config.telegram_token, config.telegram_chat_id)
        except NotificationConfigError as exc:
            log.warning("Telegram is configured but unusable: %s", exc)

    email = None
    if config.smtp_host and config.smtp_sender and config.smtp_recipients:
        try:
            email = EmailNotifier(
                host=config.smtp_host,
                port=config.smtp_port,
                username=config.smtp_username,
                password=config.smtp_password,
                sender=config.smtp_sender,
                recipients=config.smtp_recipients,
                use_tls=config.smtp_use_tls,
            )
        except NotificationConfigError as exc:
            log.warning("SMTP is configured but unusable: %s", exc)

    def write_report(alert: Alert, analysis) -> str:
        return str(write_markdown_report(alert, analysis, config.reports_dir))

    log.info(
        "pipeline channels: telegram=%s email=%s reports=%s",
        "on" if telegram else "off",
        "on" if email else "off",
        config.reports_dir,
    )
    return SOCPipeline(
        analyzer=AlertAnalyzer(),
        telegram=telegram,
        email=email,
        report_writer=write_report,
    )


def run(args: argparse.Namespace) -> int:
    """Execute one pipeline run. Returns the process exit code."""
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    state = None if args.no_state else ProcessedAlerts(default_settings.state_dir)

    try:
        selected = select_alerts(
            reader=AlertReader(),
            state=state,
            min_level=args.min_level,
            limit=args.limit,
            alerts_path=args.alerts_path,
        )
    except (AlertReaderError, ValueError) as exc:
        log.error("cannot read alerts: %s", exc)
        return 1

    if not selected:
        log.info("no new alerts at level >= %d", args.min_level)
        return 0

    if args.dry_run:
        print(f"Would process {len(selected)} alert(s):")
        for alert in selected:
            print(f"  [{alert.severity.value:8s}] lvl{alert.rule.level:>3} "
                  f"{alert.timestamp.isoformat()} {alert.agent.name} "
                  f"| {alert.rule.description}")
        return 0

    pipeline = build_pipeline()
    succeeded = 0
    failed = 0

    for alert in selected:
        result = pipeline.process(alert)
        if result.ok:
            succeeded += 1
            if state is not None:
                state.mark(alert.id)
        else:
            failed += 1
            log.error("alert %s finished with errors: %s", alert.id, result.errors)

    if state is not None:
        try:
            state.save()
        except StateError as exc:
            # The work is already done; failing to persist means some alerts
            # may be handled twice, which is worth reporting but not fatal.
            log.error("could not persist state: %s", exc)
            return 1

    log.info("processed %d alert(s): %d ok, %d failed", len(selected), succeeded, failed)
    return 1 if failed else 0


def main() -> int:
    """Parse arguments and run."""
    return run(build_parser().parse_args())


if __name__ == "__main__":
    sys.exit(main())
