# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Sprint 4.2 — Alert Details Panel, AI Analysis Panel, Incident Report Viewer
- Sprint 4.3 — Live pipeline integration, search, filtering, MITRE visualization

## [0.4.1] - 2026-08-09

### Added
- Streamlit dashboard shell (`dashboard/`) with sidebar navigation, page header,
  severity distribution bar, metric cards and a sortable alerts table.
- `AlertDataSource` protocol with a sample source, so the live Wazuh source can
  be registered in Sprint 4.3 without touching any view.
- Dark theme whose severity colours are read from `soc.severity.Severity.color`,
  keeping backend and dashboard in sync by construction.
- 36 dashboard tests, including a headless Streamlit smoke test.

### Changed
- `pytest.ini`: added the repository root to `pythonpath` so the `dashboard`
  package resolves alongside `backend/src`.

### Fixed
- `requirements.txt` now declares `requests`, which `soc/notify/telegram.py`
  imports. It was previously satisfied only incidentally by the local venv.

## [0.3.0] - 2026-07-24

### Added
- Markdown incident report generator.
- Telegram notification channel, verified against the live Bot API.
- Email notification module (SMTP not yet configured).
- Notification exception hierarchy.
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

[Unreleased]: https://github.com/mags-mags-soc/ai-soc-assistant/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/mags-mags-soc/ai-soc-assistant/releases/tag/v0.4.1
[0.3.0]: https://github.com/mags-mags-soc/ai-soc-assistant/releases/tag/v0.3.0
