# Roadmap

AI SOC Assistant is built in small, testable sprints. Every sprint ends with a
green test suite and a tagged commit.

For the longer view — what gap this fills, the design rules it holds itself to
and its known limitations — see [docs/PURPOSE_AND_ROADMAP.md](docs/PURPOSE_AND_ROADMAP.md).

## Status

| Sprint | Scope | State |
|--------|-------|-------|
| 1 | Alert reader, parser, severity, MITRE, models, config | Done |
| 2 | AI engine: client, analyzer, prompts, validated output | Done |
| 3 | Markdown reports, Telegram, email, pipeline | Done (`v0.3.0`) |
| 4.1 | Streamlit dashboard shell | Done (`v0.4.1`) |
| 4.2 | Alert details, AI analysis panel, report viewer | Done (`v0.4.2`) |
| 4.3a | Live Wazuh alert source | Done (`v0.4.3`) |
| 4.3b | Group expansion, per-event analysis, Sysmon fields | Done (`v0.4.4`) |
| 4.3c | Filtering and search | Done (`v0.4.5`) |
| 5 | Entry point, state store, notification channels | Done (`v0.5.0`) |
| 6 | Wazuh REST API ingestion | Planned |
| 7 | Alert correlation and digest notifications | Planned |
| 8 | Analyst feedback loop and enrichment | Planned |

## Architecture principles

The backend (`backend/src/soc/`) owns all domain logic. The dashboard is a
read-only presentation layer over `soc.models.Alert` objects, and the
dependency runs one way — `soc` never imports from `dashboard`.

Data reaches the dashboard through the `AlertDataSource` protocol. Registering
the live Wazuh source touched one factory function and no view.

The AI layer is provider-agnostic: enabling a provider changes configuration
only. No API key is required to run the dashboard or the test suite.

Every AI call costs money, so the boundaries are explicit — analyses are cached
per alert id, duplicates are collapsed before analysis, the runner defaults to
one alert, and `--dry-run` shows the selection without contacting the provider.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for diagrams.

## Known gaps

- The live source reads the last 5000 lines of `alerts.json`; filters and
  search apply to that window, not to history.
- Reading the file directly means the assistant runs on the manager host.
- Alerts are analysed one at a time — no correlation, so a multi-stage attack
  appears as unrelated events.
- No feedback loop: an analyst who disagrees with an assessment cannot record
  it, so the system cannot improve from its own mistakes.
- SMTP is implemented and tested but not configured against a live server.
- No scheduler ships with the project. `main.py` is scheduler-ready, but
  automation multiplies alert volume, so rule tuning comes first.
