# Roadmap

AI SOC Assistant is built in small, testable sprints. Every sprint ends with a
green test suite and a tagged commit.

## Status

| Sprint | Scope | State |
|--------|-------|-------|
| 1 | Alert reader, parser, severity mapping, MITRE mapping, models, config | Done |
| 2 | AI engine: client, analyzer, prompts, validated structured output | Done |
| 3 | Markdown reports, Telegram, email, notification pipeline | Done (`v0.3.0`) |
| 4.1 | Streamlit dashboard shell: navigation, metrics, alerts table | Done (`v0.4.1`) |
| 4.2 | Alert details panel, AI analysis panel, incident report viewer | Next |
| 4.3 | Live pipeline integration, search, filtering, MITRE visualization | Planned |
| 5 | FastAPI REST API | Planned |
| 6 | Docker deployment | Planned |
| 7 | CI/CD pipeline | Planned |
| 8 | Threat intelligence integration | Planned |
| 9 | Database and Redis | Planned |
| 10 | Production release (`v1.0.0`) | Planned |

## Architecture principles

The backend (`backend/src/soc/`) owns all domain logic. The dashboard is a
read-only presentation layer: it consumes `soc.models.Alert` objects and reads
severity colours from `soc.severity.Severity`, so the two can never drift apart.

Data reaches the dashboard through the `AlertDataSource` protocol. Sprint 4.1
ships a sample source for UI work; Sprint 4.3 registers a live Wazuh source in
`dashboard/data/factory.py` and no view changes.

The AI layer is provider-agnostic. Enabling a provider changes configuration
only — never the client architecture. No API key is required to run the
dashboard or the test suite.

## Known gaps

- SMTP is implemented but not configured against a live server.
- OpenAI is not yet wired up; the AI layer currently targets an
  OpenAI-compatible endpoint via `AI_BASE_URL`.
- `main.py` runs the pipeline once; scheduling it is Sprint 5.
