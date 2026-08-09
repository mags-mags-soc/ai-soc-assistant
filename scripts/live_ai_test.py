"""Send one real alert through the AI engine and print the validated result."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend" / "src"))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from dashboard.data.sample import SampleAlertDataSource
from soc.ai.analyzer import AlertAnalyzer
from soc.config import settings


def main() -> int:
    """Analyze the newest sample alert and print the result."""
    print("model:", settings.ai_model)
    print("key  :", "set" if settings.ai_api_key else "MISSING")

    alert = SampleAlertDataSource().fetch_alerts(limit=1)[0]
    print("alert:", alert.rule.description)
    print("\ncalling provider...\n")

    a = AlertAnalyzer().analyze(alert)

    print("RISK      :", a.risk_level.value.upper())
    print("CONFIDENCE:", a.confidence_score)
    print("FALSE POS :", f"{a.false_positive_percent}%")
    print("\nSUMMARY\n" + a.summary)
    print("\nASSESSMENT\n" + a.risk_assessment)
    print("\nSTEPS")
    for i, s in enumerate(a.investigation_steps, 1):
        print(f"  {i}. {s}")
    if a.mitre_commentary:
        print("\nMITRE\n" + a.mitre_commentary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
