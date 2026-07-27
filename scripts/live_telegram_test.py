"""Live Telegram delivery test — sends one real message to your chat."""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend" / "src"))

from soc.models import Alert
from soc.ai.schemas import AIAnalysis, RiskLevel
from soc.notify.telegram import TelegramNotifier

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

token = os.environ["TELEGRAM_BOT_TOKEN"]
chat_id = os.environ["TELEGRAM_CHAT_ID"]

alert = Alert.from_wazuh({
    "id": "LIVE-001",
    "timestamp": "2026-07-26T15:00:00.000+0000",
    "agent": {"id": "001", "name": "win-vm", "ip": "10.0.0.5"},
    "rule": {"id": "92052", "level": 12, "description": "Suspicious PowerShell",
             "groups": ["sysmon"],
             "mitre": {"id": ["T1059.001"], "tactic": ["Execution"],
                       "technique": ["PowerShell"]}},
    "full_log": "powershell.exe -enc SQBFAFgA",
    "location": "EventChannel",
})

analysis = AIAnalysis(
    summary="Encoded PowerShell command detected on win-vm — possible malware staging.",
    risk_level=RiskLevel.HIGH,
    risk_assessment="Base64-encoded command is a common attacker technique.",
    investigation_steps=["Isolate the host.", "Decode the payload.", "Check parent process."],
    false_positive_probability=0.1,
    mitre_commentary="Maps to T1059.001 (PowerShell).",
    confidence_score=85,
)

notifier = TelegramNotifier(token, chat_id)
resp = notifier.send(alert, analysis)
print("✅ Telegram delivery OK:", resp.get("ok"))
