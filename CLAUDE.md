# CLAUDE.md — AI SOC Assistant

Production-quality AI-powered SOC Analyst Assistant for blue team operations.
Portfolio project targeting the German cybersecurity job market (SOC Analyst L1).

## Communication

- Explain everything to the user in **Turkish**.
- Code, identifiers, docstrings, comments, UI labels, commit messages: **English**.

## Hard rules

1. The architecture exists. Do not redesign it.
2. Never rewrite a working file. Modify only the lines that must change.
3. No placeholders, no `TODO`, no `...continue here...`, no fake implementations.
4. Reuse existing modules. Never duplicate logic that already lives in `soc/`.
5. Keep backward compatibility.
6. Every sprint ships with tests and ends green.
7. Explain the plan before writing code. Wait for the user's test results before
   moving to the next sprint step.
8. Never commit secrets. `.env` stays local; only `.env.example` is tracked.

## Before changing code

Inspect the real files you are about to touch. Never assume the project structure
or a module's API from this document — it can lag behind the repository.
`README.md` and `ROADMAP.md` hold the sprint context: read them when a task's
scope is unclear, not on every turn.

## Layout

```
backend/src/soc/     config · logging_setup · severity · mitre · models
                     alert_reader · pipeline · ai/ · report/ · notify/
dashboard/           Streamlit presentation layer (Sprint 4)
tests/               backend suite
tests/dashboard/     dashboard suite
scripts/             live integration scripts
```

`pytest.ini` sets `pythonpath = backend/src`, so `soc` imports without extra setup.

## Commands

```bash
source .venv/bin/activate
pytest -q                                  # full suite
pytest tests/dashboard -q                  # dashboard suite
streamlit run dashboard/app.py             # local dashboard
streamlit run dashboard/app.py --server.address 0.0.0.0 --server.port 8501
```

## Coding style

Python 3.14 · PEP8 · type hints on every signature · docstrings · small modules ·
Pydantic v2 · exception-based error handling · retry and timeout on network calls ·
logging through `soc.logging_setup` · dependency injection where it helps testing.

## Sprint status

- **Sprint 1** Alert Reader, parser, severity, MITRE, models, config — done
- **Sprint 2** AI Engine: client, analyzer, prompts, Pydantic validation — done
- **Sprint 3** Markdown report, Telegram, email, pipeline, live Telegram test — done, tag `v0.3.0`
- **Sprint 4.1** Streamlit shell: navigation, header, metric cards, alerts table,
  dark theme, responsive layout — done, 36 tests
- **Sprint 4.2** next: Alert Details Panel, AI Analysis Panel, Incident Report Viewer
- **Sprint 4.3** Pipeline integration, live updates, search, filtering, MITRE visualization

## Dashboard rules (Sprint 4)

- The dashboard is **read-only** and must never change the backend.
- Severity colors and ranks come from `soc.severity.Severity`. Never redefine them.
- Alerts are `soc.models.Alert` objects. No parallel view models.
- All canned data lives only in `dashboard/data/sample.py`. Register the live
  source in `dashboard/data/factory.py` at Sprint 4.3; no other module changes.
- Every view depends on the `AlertDataSource` protocol, not on a concrete source.

## AI provider

OpenAI is not configured yet. The AI layer stays provider-agnostic and must not
be redesigned: when a provider is enabled, only its configuration changes. Never require an API key to run
the dashboard or the test suite. External services (AI, Telegram, SMTP) are mocked
in tests.

## Definition of done

`pytest -q` green → `git status` reviewed → suggested commit message → push.

Never run `git commit` or `git push` without the user's explicit confirmation.
Stable releases carry a git tag; `v0.3.0` is the latest.
