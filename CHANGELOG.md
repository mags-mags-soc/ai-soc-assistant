# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Wazuh REST API ingestion, to replace reading `alerts.json` directly
- Alert correlation: group related alerts into one incident
- Digest notifications instead of one message per alert
- Analyst feedback loop on AI assessments

## [0.5.0] - 2026-08-27

### Added
- `main.py` entry point: reads new alerts, runs them through the pipeline,
  exits 0/1 so a scheduler can detect failure.
- `soc/state.py` — processed-alert store with atomic writes and 30-day
  retention, so repeat runs never re-bill the provider or re-send a
  notification.
- Telegram, SMTP and report-directory settings; `build_pipeline()` constructs
  each channel only when its configuration is complete.
- Decoded Sysmon fields now appear in incident reports, Telegram messages and
  emails, which previously showed an empty log section for EventChannel alerts.

### Changed
- `decoded_event_fields` moved from `ai/prompts.py` to `models.py`, where the
  report and both notifiers reach it without depending on the AI layer.
- Telegram delivery: HTML escaping, the 4096-character API limit, and retries
  on transport errors and rate limiting.
- AI defaults now name the provider actually in use instead of a dead
  RouteLLM endpoint.

## [0.4.5] - 2026-08-22

### Added
- Sidebar filters: minimum severity, agent, MITRE token and free text, all
  delegating to the existing `AlertReader` query helpers.
- A caption stating how many of the loaded alerts survived the filter, so an
  empty table is never mistaken for missing data.

## [0.4.4] - 2026-08-22

### Added
- `AlertDataSource.fetch_group()` — a deduplicated row expands into the
  individual events behind it, each analysable on its own.
- Sysmon field extraction for Windows EventChannel alerts.

### Fixed
- The AI prompt only carried `full_log`, which EventChannel alerts leave empty;
  the model was asked to triage a file-creation alert without the file name.
  On a live alert this moved the false-positive estimate from 45% to 65%.

## [0.4.3] - 2026-08-09

### Added
- Live Wazuh alert source reading the tail of `alerts.json`, with
  fingerprint-based deduplication and occurrence counts.
- Anthropic provider support via `AI_JSON_MODE`, for endpoints that reject
  OpenAI's `json_object` mode.

## [0.4.2] - 2026-08-09

### Added
- Alert details panel, AI analysis panel and incident report viewer.

## [0.4.1] - 2026-08-09

### Added
- Streamlit dashboard shell with sidebar navigation, page header, severity
  distribution bar, metric cards and a sortable alerts table.
- `AlertDataSource` protocol with a sample source, so the live Wazuh source
  could be registered later without touching any view.
- Dark theme whose severity colours are read from `soc.severity.Severity.color`.

### Fixed
- `requirements.txt` now declares `requests`, previously satisfied only
  incidentally by the local venv.

## [0.3.0] - 2026-07-24

### Added
- Markdown incident report generator.
- Telegram notification channel, verified against the live Bot API.
- Email notification module.
- `SOCPipeline` orchestration with a critical/resilient step split.

## [0.2.0]

### Added
- AI engine: provider-agnostic client, analyzer, prompt system.
- Pydantic v2 validation of structured AI output.
- Retry, timeout and exception handling around AI calls.

## [0.1.0]

### Added
- Alert reader and Wazuh alert parser.
- Severity mapping from Wazuh rule levels.
- MITRE ATT&CK mapping extraction.
- Domain models and environment-driven configuration.

[Unreleased]: https://github.com/mags-mags-soc/ai-soc-assistant/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/mags-mags-soc/ai-soc-assistant/releases/tag/v0.5.0
[0.4.5]: https://github.com/mags-mags-soc/ai-soc-assistant/releases/tag/v0.4.5
[0.4.4]: https://github.com/mags-mags-soc/ai-soc-assistant/releases/tag/v0.4.4
[0.4.3]: https://github.com/mags-mags-soc/ai-soc-assistant/releases/tag/v0.4.3
[0.4.1]: https://github.com/mags-mags-soc/ai-soc-assistant/releases/tag/v0.4.1
[0.3.0]: https://github.com/mags-mags-soc/ai-soc-assistant/releases/tag/v0.3.0
