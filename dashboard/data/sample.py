"""Sample alert source used while the UI is being built (Sprint 4.1).

This module is the **only** place in the dashboard that contains canned data.
It holds raw Wazuh-shaped dictionaries and feeds them through the real
``Alert.from_wazuh`` parser, so severity bands, MITRE mappings and timestamps
are produced by the backend exactly as they are in production. Sprint 4.3
replaces this source with a live one; no other module changes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Final

from soc.models import Alert

from .base import DataSourceError

#: Raw Wazuh alerts: (minutes in the past, alert payload without a timestamp).
_RAW_ALERTS: Final[tuple[tuple[int, dict[str, Any]], ...]] = (
    (
        4,
        {
            "id": "1755194001.1180121",
            "agent": {"id": "003", "name": "win10-ws01", "ip": "192.168.10.31"},
            "rule": {
                "id": "92034",
                "level": 15,
                "description": "Credential dumping: LSASS memory access by unsigned process",
                "groups": ["sysmon", "windows", "credential_access"],
                "mitre": {
                    "id": ["T1003.001"],
                    "tactic": ["Credential Access"],
                    "technique": ["LSASS Memory"],
                },
            },
            "location": "EventChannel",
            "decoder": {"name": "windows_eventchannel"},
            "full_log": "SourceImage: C:\\Users\\svc_backup\\AppData\\Local\\Temp\\pd.exe "
                        "TargetImage: C:\\Windows\\system32\\lsass.exe GrantedAccess: 0x1010",
        },
    ),
    (
        11,
        {
            "id": "1755193702.1179433",
            "agent": {"id": "003", "name": "win10-ws01", "ip": "192.168.10.31"},
            "rule": {
                "id": "92052",
                "level": 13,
                "description": "PowerShell encoded command executed",
                "groups": ["sysmon", "windows", "execution"],
                "mitre": {
                    "id": ["T1059.001"],
                    "tactic": ["Execution"],
                    "technique": ["PowerShell"],
                },
            },
            "location": "EventChannel",
            "decoder": {"name": "windows_eventchannel"},
            "full_log": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        },
    ),
    (
        19,
        {
            "id": "1755193260.1178904",
            "agent": {"id": "001", "name": "ubuntu-soc", "ip": "192.168.10.20"},
            "rule": {
                "id": "5720",
                "level": 12,
                "description": "Multiple SSH authentication failures from a single source",
                "groups": ["sshd", "authentication_failures"],
                "mitre": {
                    "id": ["T1110.001"],
                    "tactic": ["Credential Access"],
                    "technique": ["Password Guessing"],
                },
            },
            "location": "/var/log/auth.log",
            "decoder": {"name": "sshd"},
            "full_log": "Failed password for invalid user admin from 192.168.10.77 port 51234 ssh2",
        },
    ),
    (
        27,
        {
            "id": "1755192780.1178220",
            "agent": {"id": "002", "name": "opnsense-fw", "ip": "192.168.10.1"},
            "rule": {
                "id": "86601",
                "level": 12,
                "description": "Suricata: ET SCAN Nmap scripting engine detected",
                "groups": ["ids", "suricata", "recon"],
                "mitre": {
                    "id": ["T1046"],
                    "tactic": ["Discovery"],
                    "technique": ["Network Service Discovery"],
                },
            },
            "location": "/var/log/suricata/eve.json",
            "decoder": {"name": "suricata"},
            "full_log": "[1:2009358:7] ET SCAN Nmap Scripting Engine User-Agent Detected "
                        "192.168.10.77 -> 192.168.10.20:80",
        },
    ),
    (
        38,
        {
            "id": "1755192120.1177544",
            "agent": {"id": "003", "name": "win10-ws01", "ip": "192.168.10.31"},
            "rule": {
                "id": "60122",
                "level": 11,
                "description": "User added to the local Administrators group",
                "groups": ["windows", "policy_changed", "privilege_escalation"],
                "mitre": {
                    "id": ["T1098"],
                    "tactic": ["Persistence"],
                    "technique": ["Account Manipulation"],
                },
            },
            "location": "EventChannel",
            "decoder": {"name": "windows_eventchannel"},
            "full_log": "EventID 4732: Member SOC\\svc_backup added to group Administrators",
        },
    ),
    (
        52,
        {
            "id": "1755191280.1176801",
            "agent": {"id": "001", "name": "ubuntu-soc", "ip": "192.168.10.20"},
            "rule": {
                "id": "31151",
                "level": 10,
                "description": "Multiple web server 400 error codes from same source ip",
                "groups": ["web", "attack"],
                "mitre": {
                    "id": ["T1595"],
                    "tactic": ["Reconnaissance"],
                    "technique": ["Active Scanning"],
                },
            },
            "location": "/var/log/nginx/access.log",
            "decoder": {"name": "web-accesslog"},
            "full_log": '192.168.10.77 - - "GET /admin/config.php HTTP/1.1" 404 162',
        },
    ),
    (
        66,
        {
            "id": "1755190440.1176011",
            "agent": {"id": "003", "name": "win10-ws01", "ip": "192.168.10.31"},
            "rule": {
                "id": "92213",
                "level": 9,
                "description": "Process created from a user temp directory",
                "groups": ["sysmon", "windows"],
                "mitre": {
                    "id": ["T1204.002"],
                    "tactic": ["Execution"],
                    "technique": ["Malicious File"],
                },
            },
            "location": "EventChannel",
            "decoder": {"name": "windows_eventchannel"},
            "full_log": "Image: C:\\Users\\magsud\\AppData\\Local\\Temp\\update_helper.exe",
        },
    ),
    (
        81,
        {
            "id": "1755189540.1175230",
            "agent": {"id": "002", "name": "opnsense-fw", "ip": "192.168.10.1"},
            "rule": {
                "id": "86610",
                "level": 8,
                "description": "Suricata: ET POLICY curl user agent outbound",
                "groups": ["ids", "suricata", "policy"],
                "mitre": {
                    "id": ["T1071.001"],
                    "tactic": ["Command and Control"],
                    "technique": ["Web Protocols"],
                },
            },
            "location": "/var/log/suricata/eve.json",
            "decoder": {"name": "suricata"},
            "full_log": "[1:2013028:7] ET POLICY curl User-Agent Outbound 192.168.10.31 -> 8.8.8.8:80",
        },
    ),
    (
        104,
        {
            "id": "1755188160.1174118",
            "agent": {"id": "001", "name": "ubuntu-soc", "ip": "192.168.10.20"},
            "rule": {
                "id": "2902",
                "level": 7,
                "description": "New package installed with dpkg",
                "groups": ["syslog", "package_management"],
            },
            "location": "/var/log/dpkg.log",
            "decoder": {"name": "dpkg"},
            "full_log": "status installed tcpdump:amd64 4.99.4-3",
        },
    ),
    (
        137,
        {
            "id": "1755186180.1172604",
            "agent": {"id": "003", "name": "win10-ws01", "ip": "192.168.10.31"},
            "rule": {
                "id": "60106",
                "level": 5,
                "description": "Windows logon success",
                "groups": ["windows", "authentication_success"],
            },
            "location": "EventChannel",
            "decoder": {"name": "windows_eventchannel"},
            "full_log": "EventID 4624: An account was successfully logged on. User: SOC\\magsud",
        },
    ),
    (
        168,
        {
            "id": "1755184320.1171188",
            "agent": {"id": "001", "name": "ubuntu-soc", "ip": "192.168.10.20"},
            "rule": {
                "id": "5715",
                "level": 3,
                "description": "sshd: authentication success",
                "groups": ["sshd", "authentication_success"],
            },
            "location": "/var/log/auth.log",
            "decoder": {"name": "sshd"},
            "full_log": "Accepted publickey for magsud from 192.168.10.5 port 49812 ssh2",
        },
    ),
    (
        205,
        {
            "id": "1755182100.1169470",
            "agent": {"id": "004", "name": "kali-attack", "ip": "192.168.10.77"},
            "rule": {
                "id": "530",
                "level": 2,
                "description": "Ossec agent started",
                "groups": ["ossec"],
            },
            "location": "ossec-monitord",
            "decoder": {"name": "ossec"},
            "full_log": "ossec: Agent started: 'kali-attack->192.168.10.77'",
        },
    ),
)


class SampleAlertDataSource:
    """Serves a fixed set of Wazuh-shaped alerts parsed by the real backend."""

    name = "Sample data"
    is_live = False

    def __init__(self, reference_time: datetime | None = None) -> None:
        """Args:
        reference_time: Anchor for the generated timestamps. Defaults to now
            (UTC), which keeps the sample queue looking current.
        """
        self._reference_time = reference_time or datetime.now(timezone.utc)

    def fetch_alerts(self, limit: int) -> list[Alert]:
        """Return at most ``limit`` sample alerts, newest first."""
        if limit < 1:
            raise DataSourceError(f"limit must be >= 1, got {limit}")

        alerts: list[Alert] = []
        for minutes_ago, payload in _RAW_ALERTS[:limit]:
            raw = dict(payload)
            raw["timestamp"] = (
                self._reference_time - timedelta(minutes=minutes_ago)
            ).isoformat()
            try:
                alerts.append(Alert.from_wazuh(raw))
            except ValueError as exc:  # pragma: no cover - guards static data
                raise DataSourceError(f"Invalid sample alert {raw.get('id')!r}: {exc}") from exc
        return alerts
