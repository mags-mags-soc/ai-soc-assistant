# AI SOC Assistant — Purpose and Roadmap

**Status:** `v0.5.0` · 254 tests · 92% coverage
**Stack:** Python 3.14 · Pydantic v2 · Streamlit · Wazuh 4.14 · provider-agnostic LLM layer

---

## 1. What this is

A triage assistant that sits on top of a Wazuh deployment and answers the
question Wazuh does not: **"what does this alert mean, and what should I do
about it right now?"**

Wazuh already does detection, correlation, log collection and search, and does
them better than any layer built on top of it. This project does not compete
with any of that. It fills one narrow but real gap.

A worked example from this lab. Wazuh produced:

```
Rule 92034, level 15 — Credential dumping: LSASS memory access
GrantedAccess: 0x1010
```

That is accurate and useless to a Tier 1 analyst who has not memorised
Windows process access masks. The assistant returned, in eight seconds:

- `0x1010` decoded as `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`
- risk CRITICAL, confidence 94/100, false positive 2%
- ten investigation steps in incident-response order
- a downloadable Markdown incident report

A Tier 1 analyst doing that by hand takes 15–20 minutes. The assistant does
not replace the analyst's judgement — it removes the lookup work that stands
between the alert and that judgement.

---

## 2. The second purpose

This is a portfolio project targeting the German SOC Analyst (L1) market.
That shapes the engineering as much as the features do: sprint methodology,
a test suite that stays green, documented architectural decisions, and
detection-engineering writeups backed by real telemetry from a home lab.

Plenty of candidates can say "I installed Wazuh." Fewer can say "I wrote a
modular Python application on top of it with 254 tests, a provider-agnostic AI
layer, and a tuning writeup showing why one rule was firing 175 times a day on
benign activity."

---

## 3. What it does today

### Alert ingestion

- Reads the tail of `alerts.json` in fixed-size blocks, so cost stays constant
  as the file grows
- Parses through the same `Alert.from_wazuh()` used everywhere else, so the
  live source and the sample source produce identical objects
- Handles invalid UTF-8 (Windows agents emit it) and malformed lines without
  aborting
- Collapses repeats on `(rule_id, description, agent_name)` and reports the
  true occurrence count separately

### Triage dashboard (Streamlit)

- Three pages: queue overview, full alert list, single-alert detail
- Severity colours and MITRE mappings come from the backend, never redefined
- A deduplicated row expands into the individual events behind it; each event
  can be inspected and analysed on its own
- Filters on severity, agent, MITRE token and free text — all delegating to
  the backend's existing query helpers
- Honest counts: "showing 50 of 304 occurrences seen in the current window",
  never a total the data cannot support

### AI analysis

- Provider-agnostic: any OpenAI-compatible endpoint, currently Anthropic
  Haiku 4.5 at roughly $0.004 per alert
- Strict JSON schema validated by Pydantic; invalid model output never becomes
  a result
- Results cached per alert id, so re-rendering a page never re-bills
- Windows EventChannel alerts carry no `full_log`; their decoded Sysmon fields
  are extracted and sent instead, so the model is not asked to triage a
  file-creation alert without the file name

### Notification and reporting

- Markdown incident reports with the decoded event data
- Telegram delivery with HTML escaping, the 4096-character API limit and
  retries on transport errors and rate limiting
- SMTP email with the same evidence, agent name in the subject line
- Every channel is optional; a missing one is skipped rather than failing

### Command-line runner

- `main.py` reads new alerts, skips what an earlier run already handled, and
  pushes the rest through analysis, notification and reporting
- A processed-alert store prevents re-billing and repeat notifications
- `--limit` defaults to 1, `--dry-run` shows the selection without contacting
  the provider
- Exit code 0/1 so a scheduler can detect failures

---

## 4. Design principles

These are enforced, not aspirational.

**The dashboard never changes the backend.** It is a read-only presentation
layer over `soc.models.Alert` objects. No parallel view models.

**No invented data.** When no provider is configured, the analysis source says
so. It does not produce a plausible-looking result.

**Protocols, not concrete types.** `AlertDataSource` and `AnalysisSource` are
`Protocol` definitions. Adding the live Wazuh source in Sprint 4.3a required
registering it in one factory function; no view changed. Adding group
expansion in 4.3b added one method to the protocol and created no new data
type — the truncation flag is derived from data that already existed.

**Layer direction is one-way.** The backend never imports from the dashboard.
When both needed the same Sysmon field extraction, the function moved into
`models.py` rather than being imported upward or duplicated.

**Costs are visible and bounded.** Every AI call is money. Analysis is cached,
duplicates are collapsed, the runner defaults to one alert, and `--dry-run`
exists so the selection can be inspected for free.

**Backward compatibility is a rule, not a preference.** Every behavioural
change ships with a test asserting the old path still works.

---

## 5. Known limitations

Stated plainly, because a portfolio project that hides its edges is less
credible than one that names them.

- **The read window is finite.** The live source scans the last 5000 lines.
  Filters and searches apply to that window, not to history.
- **File-based ingestion.** Reading `alerts.json` directly means the assistant
  must run on the manager host. The Wazuh API would remove that constraint.
- **`parentImage` is often absent.** Sysmon Event ID 11 (FileCreate) does not
  carry parent process data — that lives in Event ID 1. The model will keep
  asking "what spawned this process?" because the answer genuinely is not in
  the alert.
- **One alert at a time.** There is no correlation across alerts; a multi-stage
  attack is analysed as separate unrelated events.
- **No feedback loop.** An analyst who disagrees with an assessment has no way
  to record that, so the system cannot improve from its own mistakes.
- **Free-text search misses decoded fields.** `AlertReader.search` covers
  `full_log`, which Sysmon alerts leave empty.

---

## 6. Roadmap

### Near term

**Scheduled execution.** A systemd timer running `main.py` on an interval.
Deliberately deferred: automation multiplies whatever the alert volume happens
to be, so rule tuning has to come first. The tuning of rule 92213 removed 175
benign alerts a day; more of that work should land before a scheduler does.

**Detection tuning and writeups.** `92213` is done. `rootcheck` noise and the
`Agent event queue is full` infrastructure alert are next. Each one gets a
short writeup: what fired, why it was noise, what the rule now does, and how
that was verified.

**Repository documentation.** Architecture diagram, detection writeups, and a
README that shows the dashboard rather than describing it.

### Medium term

**Wazuh API ingestion.** Replace the file tail with the manager's REST API.
Removes the same-host constraint, gives access to history beyond the read
window, and makes filtering server-side.

**Alert correlation.** Group related alerts into a single incident rather than
deduplicating identical ones. A credential-dumping alert followed by an
outbound connection from the same host is one story, not two alerts.

**Digest notifications.** Per-alert delivery is itself a source of alert
fatigue. A scheduled digest — "12 alerts in the last hour, 2 need attention" —
matches how a real shift works better than a message per event.

**Enrichment before analysis.** Hash reputation, IP reputation, and whether
the file path is a known-good location. Giving the model verified external
context should improve confidence scores the same way giving it the file name
did.

**Analyst feedback loop.** A thumbs up/down on each analysis, stored with the
alert. Two uses: measuring whether the assistant is actually right, and
building a local set of confirmed false positives that feeds tuning.

### Longer term

**MITRE ATT&CK coverage view.** Which techniques the current ruleset can
detect, and which it cannot. This is a detection-engineering artifact as much
as a dashboard feature.

**Case export.** Push a triaged incident into TheHive or a ticket system, so
the assistant sits in a workflow rather than beside one.

**Multi-model comparison.** Run the same alert through two models and surface
disagreement. Disagreement is a useful signal on its own: it marks the alerts
where human judgement matters most.

**Measured impact.** Time from alert to triaged report, share of alerts closed
as false positive, analyst time saved. A portfolio claim of "saves 15 minutes"
is worth more with a number behind it.

---

## 7. Explicit non-goals

- **Not a SIEM.** Detection, correlation and search belong to Wazuh.
- **Not automated response.** The assistant recommends investigation steps; it
  does not isolate hosts or kill processes. Automated response on an
  AI-generated risk assessment is not a defensible design at this maturity.
- **Not a replacement for the analyst.** The output is a starting point with a
  stated confidence and a false-positive estimate, not a verdict.

---

## 8. Sprint history

| Tag | Scope |
|---|---|
| `v0.3.0` | Alert reader, AI engine, Markdown report, Telegram, pipeline |
| `v0.4.1` | Streamlit dashboard shell |
| `v0.4.2` | Alert detail, AI analysis panel, report viewer |
| `v0.4.3` | Live Wazuh data source |
| `v0.4.4` | Group expansion, per-event analysis, Sysmon field extraction |
| `v0.4.5` | Filtering and search |
| `v0.5.0` | Pipeline entry point, processed-alert store, notification channels |
