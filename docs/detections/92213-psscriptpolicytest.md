# Rule 92213 — PowerShell execution policy probe

**Type:** False positive · tuning
**Rules involved:** `92213`, `92205` (upstream) → `100010`, `100011` (local)
**Platform:** Windows 11, Sysmon Event ID 11 (FileCreate)
**Date:** August 2026
**Outcome:** ~175 benign level-15 alerts per day removed from triage; the
events are still recorded

---

## Summary

Wazuh rule `92213` fires whenever an executable-like file is written to a
user's `AppData\Local\Temp` directory, at level 15 (critical). PowerShell
writes a randomly-named `.ps1` file to that directory every time it evaluates
its execution policy — roughly every 30 seconds on this host. The rule was
therefore firing constantly on benign activity, and a real detection in the
same folder would have been buried in it.

The rule was not disabled. A local rule matching that specific pattern
reduces the level to 3, which is below the triage threshold but still logged.

---

## What was observed

The dashboard's occurrence column made the imbalance obvious. Over one read
window:

```
lvl 15  seen 304  Executable file dropped in folder commonly used by malware
lvl  7  seen  40  Host-based anomaly detection event (rootcheck)
lvl 10  seen   9  Value added to registry key has Base64-like pattern
lvl  9  seen  19  Powershell process created an executable file in Windows root
lvl 12  seen   3  Application Compatibility Database launched
lvl  8  seen   3  User account changed
```

One rule accounted for more alerts than every other rule combined, and all
304 came from a single agent.

The individual events arrived about 30 seconds apart:

```
2026-08-22 19:12:50  win11-lab  C:\Users\magsu\AppData\Local\Temp\__PSScriptPolicyTest_dvqsnsoz.vdr.ps1
2026-08-22 19:12:20  win11-lab  C:\Users\magsu\AppData\Local\Temp\__PSScriptPolicyTest_llndga3u.2bd.ps1
2026-08-22 19:11:50  win11-lab  C:\Users\magsu\AppData\Local\Temp\__PSScriptPolicyTest_yyus4qii.ijf.ps1
2026-08-22 19:11:20  win11-lab  C:\Users\magsu\AppData\Local\Temp\__PSScriptPolicyTest_ll4ua0zn.z51.ps1
```

---

## Why it fires

The upstream rule matches any file with an executable-like extension written
under a user Temp directory:

```xml
<rule id="92213" level="15">
  <if_group>sysmon_event_11</if_group>
  <field name="win.eventdata.targetFilename" type="pcre2">
    (?i)[c-z]:\\\\Users\\\\.+\\\\AppData\\\\Local\\\\Temp\\\\.+\.(exe|com|dll|vbs|js|bat|cmd|pif|wsh|ps1|msi|vbe)
  </field>
  <description>Executable file dropped in folder commonly used by malware</description>
  <mitre><id>T1105</id></mitre>
</rule>
```

`.ps1` is in that extension list, and `__PSScriptPolicyTest_*.ps1` is a file
PowerShell creates itself. When PowerShell needs to know whether script
execution is permitted in a given directory, it writes a probe script there
and checks whether it can run it. The file is created and deleted in the same
moment, and the name is randomised on every run.

The writing process is always PowerShell:

```
image:          C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
targetFilename: C:\Users\magsu\AppData\Local\Temp\__PSScriptPolicyTest_lyj32qkq.a0q.ps1
user:           M313M\magsu
```

---

## Why deduplication does not solve it

The dashboard collapses repeats on `(rule_id, description, agent_name)`, which
is why the queue showed one row rather than 304. That helps a human reading a
list, but it does not reduce the underlying volume: the pipeline, the
notification channels and any scheduled automation still see 304 distinct
alerts.

More importantly, **every occurrence has a different random filename**, so no
identity-based deduplication can recognise them as the same thing. Only a
pattern can.

This is worth stating plainly because the instinctive fix — "count repeats and
suppress" — would not have worked here.

---

## What the AI triage contributed

Running one of these alerts through the assistant produced a false-positive
estimate of 65% and this observation:

> The filename pattern (`__PSScriptPolicyTest`) suggests this may be legitimate
> PowerShell policy testing rather than adversarial tool transfer.

That assessment was only possible after a separate fix: Windows EventChannel
alerts leave `full_log` empty, so the model had originally been asked to
triage a file-creation alert without the filename. Before that fix the same
alert returned a 45% false-positive estimate and complained three times that
the file name was not provided.

The triage did not make the tuning decision. It shortened the path to it.

---

## Options considered

| Option | Effect | Decision |
|---|---|---|
| Disable rule 92213 | Removes the noise and every real detection the rule would catch | Rejected |
| `<options>no_log</options>` on the pattern | Removes the noise but destroys the evidence | Rejected |
| Rewrite 92213 to exclude the pattern | Editing an upstream ruleset file; a Wazuh update overwrites it | Rejected |
| Local rule with `if_sid`, reduced level | Noise leaves triage, evidence stays, survives updates | **Selected** |

---

## The rule

`/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="local,sysmon,windows,">

  <rule id="100010" level="3">
    <if_sid>92213</if_sid>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\\\__PSScriptPolicyTest_[a-z0-9]+\.[a-z0-9]+\.ps1$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\\\powershell\.exe$</field>
    <description>PowerShell execution policy test file in Temp - benign, tuned down from rule 92213</description>
    <group>tuned,false_positive,</group>
  </rule>

</group>
```

### Why level 3 and not `no_log`

The dashboard and the pipeline both filter at level 7. Level 3 is below that
threshold, so these events no longer reach triage. It is above
`log_alert_level` (3), so they are still written to `alerts.json` and remain
available for an investigation asking "what happened on this host that day".

**Prioritised, not suppressed.**

### Why two conditions

Matching on the filename alone would have created a bypass: an attacker who
named a payload `__PSScriptPolicyTest_evil.ps1` would inherit the reduced
level. Requiring the writing process to be `powershell.exe` raises that bar.

This is not a complete defence — an attacker with the ability to run
PowerShell can satisfy both conditions. It is a deliberate trade: the
alternative was 175 benign critical alerts a day drowning out everything else.
A stronger version would also check the process signature or the parent
process; Sysmon Event ID 11 does not carry parent data, so that would need a
correlation across event types.

### Why `if_sid`

`92213` lives in `/var/ossec/ruleset/rules/0830-sysmon_id_11.xml`, which Wazuh
overwrites on update. A local rule chained with `if_sid` leaves the upstream
file untouched and survives upgrades.

---

## Verification

The pattern was tested against a real event before the rule was loaded:

```bash
sudo grep -a '"92213"' /var/ossec/logs/alerts/alerts.json | tail -1 > /tmp/sample.json

python3 -c "
import json, re
e = json.load(open('/tmp/sample.json'))['data']['win']['eventdata']
print(bool(re.search(r'(?i)\\\\\\\\__PSScriptPolicyTest_[a-z0-9]+\.[a-z0-9]+\.ps1\$', e['targetFilename'])))
print(bool(re.search(r'(?i)\\\\\\\\powershell\.exe\$', e['image'])))
"
```

Both returned `True`. Note the doubled backslashes: the decoded path arrives
escaped, which is why rule `92213` itself is written the same way. A pattern
using single backslashes silently matches nothing.

After reloading:

```bash
sudo systemctl restart wazuh-manager
sudo grep -a '"100010"' /var/ossec/logs/alerts/alerts.json | tail -3
```

```
2026-08-27T11:27:54  lvl 3  PowerShell execution policy test file in Temp - benign
2026-08-27T11:28:24  lvl 3  PowerShell execution policy test file in Temp - benign
2026-08-27T11:28:54  lvl 3  PowerShell execution policy test file in Temp - benign
```

Level 15 → 3, arriving at the same 30-second cadence, no longer in triage.

> **Note on grepping `alerts.json`:** the file contains invalid UTF-8 bytes
> from Windows agents, so `grep` treats it as binary and suppresses output.
> Use `grep -a`.

---

## Follow-up: rule 92205

The same probe is also written to `C:\Windows\SystemTemp\`, which triggers
rule `92205` ("Powershell process created an executable file in Windows root
folder") at level 9. Rule `100011` applies the identical pattern to that rule.

```xml
<rule id="100011" level="3">
  <if_sid>92205</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)\\\\__PSScriptPolicyTest_[a-z0-9]+\.[a-z0-9]+\.ps1$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\\\powershell\.exe$</field>
  <description>PowerShell execution policy test file in Windows root - benign, tuned down from rule 92205</description>
  <group>tuned,false_positive,</group>
</rule>
```

---

## What this changed

- One rule that produced more alerts than every other rule combined no longer
  reaches triage
- The events remain in `alerts.json` for investigation
- A real detection in the same folder is now visible instead of buried
- The tuning survives Wazuh upgrades

## What it did not change

The rule still fires. A file matching the pattern but written by something
other than PowerShell still alerts at level 15. Nothing was deleted.

---

## Remaining noise

Still to be worked through, in the order they matter:

- **`rootcheck` (rule 510)** — reports `/bin/cat`, `/bin/date` and similar as
  "trojaned" because the signature strings appear in normal modern binaries.
  A textbook rootcheck false positive.
- **SCA / CIS benchmark results (level 9)** — configuration audit output, not
  security events. These belong in a compliance view, not the triage queue.
- **`Value added to registry key has Base64-like pattern` (level 10)** —
  needs investigation before any tuning; Base64-looking registry values are
  common in legitimate software but are also a real persistence technique.
- **`Agent event queue is full`** — infrastructure, not security. Signals that
  the agent cannot keep up with event production, which risks data loss.
