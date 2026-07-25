"""Application configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _env_path(name: str, default: Path) -> Path:
    value = os.getenv(name)
    return Path(value).expanduser().resolve() if value else default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings."""

    alerts_path: Path
    logs_dir: Path
    state_dir: Path
    log_level: str
    max_read_bytes: int

    @classmethod
    def load(cls) -> "Settings":
        return cls(
            alerts_path=_env_path(
                "SOC_ALERTS_PATH",
                Path("/var/ossec/logs/alerts/alerts.json"),
            ),
            logs_dir=_env_path("SOC_LOGS_DIR", PROJECT_ROOT / "logs"),
            state_dir=_env_path("SOC_STATE_DIR", PROJECT_ROOT / "state"),
            log_level=os.getenv("SOC_LOG_LEVEL", "INFO").upper(),
            max_read_bytes=_env_int("SOC_MAX_READ_BYTES", 50 * 1024 * 1024),
        )


settings = Settings.load()
