# Architecture

Diagrams are Mermaid; GitHub renders them inline.

---

## 1. End to end

```mermaid
flowchart LR
    subgraph endpoints["Endpoints"]
        WIN["Windows<br/>Sysmon agent"]
        LNX["Linux<br/>Wazuh agent"]
    end

    subgraph wazuh["Wazuh manager"]
        RULES["Ruleset<br/>+ local tuning"]
        FILE[("alerts.json")]
    end

    subgraph app["AI SOC Assistant"]
        READER["AlertReader<br/>parse · filter · search"]
        AI["AI engine<br/>provider-agnostic"]
        DASH["Streamlit dashboard"]
        CLI["main.py"]
    end

    subgraph out["Output"]
        REPORT["Markdown<br/>incident report"]
        TG["Telegram"]
        MAIL["Email"]
    end

    WIN --> RULES
    LNX --> RULES
    RULES --> FILE
    FILE --> READER
    READER --> DASH
    READER --> CLI
    DASH --> AI
    CLI --> AI
    AI --> REPORT
    AI --> TG
    AI --> MAIL
```

The assistant reads what Wazuh has already detected. It adds no detection of
its own — the ruleset decides what becomes an alert, and local tuning decides
what reaches triage.

---

## 2. Module layout

```mermaid
flowchart TB
    subgraph backend["backend/src/soc — domain layer"]
        MODELS["models.py<br/>Alert · decoded_event_fields"]
        SEV["severity.py · mitre.py"]
        READER["alert_reader.py<br/>parse · query helpers"]
        STATE["state.py<br/>processed-alert store"]
        PIPE["pipeline.py<br/>orchestration"]

        subgraph ailayer["ai/"]
            CLIENT["client.py"]
            PROMPTS["prompts.py"]
            SCHEMAS["schemas.py<br/>Pydantic validation"]
            ANALYZER["analyzer.py"]
        end

        subgraph outlayer["report/ · notify/"]
            MD["markdown_report.py"]
            TGM["telegram.py"]
            EM["email.py"]
        end
    end

    subgraph dashboard["dashboard — presentation layer"]
        DATA["data/<br/>AlertDataSource"]
        ANALYSIS["analysis/<br/>AnalysisSource"]
        VIEWS["views/ · components/"]
        FILTERS["filters.py"]
    end

    ENTRY["main.py"]

    MODELS --> READER
    MODELS --> PROMPTS
    MODELS --> MD
    MODELS --> TGM
    MODELS --> EM
    SEV --> MODELS
    PROMPTS --> ANALYZER
    CLIENT --> ANALYZER
    SCHEMAS --> ANALYZER
    ANALYZER --> PIPE
    MD --> PIPE
    TGM --> PIPE
    EM --> PIPE

    READER --> DATA
    READER --> FILTERS
    ANALYZER --> ANALYSIS
    DATA --> VIEWS
    ANALYSIS --> VIEWS
    FILTERS --> VIEWS

    READER --> ENTRY
    STATE --> ENTRY
    PIPE --> ENTRY
```

**Dependency direction is one-way.** The dashboard imports from `soc`; `soc`
never imports from the dashboard. When the prompt builder, the report and both
notifiers all needed the same Sysmon field extraction, the function moved into
`models.py` rather than being imported upward or duplicated.

---

## 3. Swappable layers

Two `Protocol` definitions isolate the dashboard from concrete implementations.

```mermaid
flowchart LR
    subgraph p1["AlertDataSource"]
        SAMPLE["SampleAlertDataSource<br/>canned Wazuh payloads"]
        LIVE["LiveAlertDataSource<br/>tail of alerts.json"]
    end

    subgraph p2["AnalysisSource"]
        DISABLED["DisabledAnalysisSource<br/>says so, invents nothing"]
        ANALYZER2["AnalyzerAnalysisSource<br/>real AI engine, cached"]
    end

    FACTORY1["data/factory.py"]
    FACTORY2["analysis/factory.py"]
    VIEWS2["views/"]

    SAMPLE --> FACTORY1
    LIVE --> FACTORY1
    DISABLED --> FACTORY2
    ANALYZER2 --> FACTORY2
    FACTORY1 --> VIEWS2
    FACTORY2 --> VIEWS2
```

Adding the live Wazuh source in Sprint 4.3a meant registering it in one
factory function. No view changed.

The `AlertDataSource` surface:

```python
name: str
is_live: bool
occurrences: dict[str, int]
fetch_alerts(limit: int) -> list[Alert]
fetch_group(alert_id: str) -> list[Alert]
```

---

## 4. Deduplication and group expansion

```mermaid
flowchart TB
    TAIL["Read last 5000 lines"]
    PARSE["Alert.from_wazuh()<br/>skip malformed"]
    LEVEL["Drop below min_level"]
    FP["Group by fingerprint<br/>rule_id · description · agent"]
    REP["Representative row<br/>+ true occurrence count"]
    MEMBERS["Retained members<br/>max 500 per group"]
    TABLE["Alert table"]
    DETAIL["Detail page<br/>one event at a time"]

    TAIL --> PARSE --> LEVEL --> FP
    FP --> REP --> TABLE
    FP --> MEMBERS --> DETAIL
```

A row in the table stands for a group. The occurrence count is the **true**
number seen in the window, not the number retained — which is why the UI says
"showing 50 of 304 occurrences seen in the current window" rather than
implying a total the read window cannot support.

Filters run on the representatives, after the counts are built. Filtering
earlier would make the count mean "times seen matching this filter".

---

## 5. Command-line run

```mermaid
flowchart TB
    START["main.py"]
    READ["AlertReader.read_all()"]
    MINLVL["Drop below --min-level"]
    SEEN{"Already in<br/>state store?"}
    SKIP["Skip"]
    LIMIT["Newest first, take --limit"]
    DRY{"--dry-run?"}
    LIST["Print selection<br/>no provider call"]
    ANALYZE["AI analysis"]
    OK{"Succeeded?"}
    CHANNELS["Telegram · email · report<br/>configured channels only"]
    MARK["Mark processed"]
    ERR["Record error<br/>exit 1"]

    START --> READ --> MINLVL --> SEEN
    SEEN -- yes --> SKIP
    SEEN -- no --> LIMIT --> DRY
    DRY -- yes --> LIST
    DRY -- no --> ANALYZE --> OK
    OK -- yes --> CHANNELS --> MARK
    OK -- no --> ERR
```

The state store answers one question: *have I handled this alert id before?*
Without it, a scheduled run would re-analyse everything still inside the read
window — paying the provider again and re-sending the same notification.

Whether a *rule* is too noisy is a detection tuning problem, deliberately kept
out of the state layer.

---

## 6. Cost controls

Every analysis is a paid API call, so the boundaries are explicit:

| Control | Where | Effect |
|---|---|---|
| Result cache keyed by alert id | `analysis/analyzer_source.py` | Re-rendering a page never re-bills |
| Fingerprint deduplication | `data/live.py` | 304 identical alerts, one analysis |
| Processed-alert store | `soc/state.py` | Repeat runs skip handled alerts |
| `--limit` defaults to 1 | `main.py` | An accidental run bills the minimum |
| `--dry-run` | `main.py` | Inspect the selection for free |
| Rule tuning | `local_rules.xml` | Noise never reaches the pipeline |

At roughly $0.004 per alert, an untuned rule firing 175 times a day would cost
more than the analysis is worth — which is why tuning precedes automation.

---

## 7. Deployment

```mermaid
flowchart LR
    subgraph proxmox["Proxmox host"]
        subgraph vm["Ubuntu VM"]
            MGR["Wazuh manager<br/>+ indexer + dashboard"]
            APP["soc-dashboard.service<br/>Streamlit :8501"]
            CLI2["main.py<br/>run by hand"]
        end
        WINVM["Windows VM<br/>agent"]
        KALI["Kali<br/>attacker"]
        OPN["OPNsense<br/>router · Suricata"]
    end

    HOST["Windows host<br/>Sysmon agent"]

    WINVM --> MGR
    HOST --> MGR
    MGR --> APP
    MGR --> CLI2
```

The assistant reads `alerts.json` directly, so it runs on the manager host.
Moving to the Wazuh REST API would remove that constraint — it is on the
roadmap.

Systemd runs the dashboard:

```
Environment="DASHBOARD_SOURCE=live"
Environment="DASHBOARD_ANALYSIS_SOURCE=analyzer"
SupplementaryGroups=wazuh
```

No timer ships with the project. `main.py` is scheduler-ready — it skips
handled alerts and signals failure through its exit code — but automation
multiplies alert volume, so tuning comes first.
