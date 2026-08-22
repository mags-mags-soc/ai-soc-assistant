"""Immutable runtime configuration loaded from environment variables."""

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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Environment variable {name} must be a boolean, got {raw!r}")


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"Environment variable {name} must be a float, got {raw!r}") from exc


#: Default AI provider. Any OpenAI-compatible endpoint works; the client is
#: provider-agnostic and only the configuration changes when switching.
DEFAULT_AI_BASE_URL = "https://api.anthropic.com/v1/"
DEFAULT_AI_MODEL = "claude-haiku-4-5-20251001"


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings."""

    alerts_path: Path
    logs_dir: Path
    state_dir: Path
    log_level: str
    max_read_bytes: int

    # AI engine settings
    ai_api_key: str
    ai_base_url: str
    ai_model: str
    ai_timeout: float
    ai_max_retries: int
    ai_temperature: float
    ai_json_mode: bool = True

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
            ai_api_key=os.getenv("AI_API_KEY", ""),
            ai_base_url=os.getenv("AI_BASE_URL", DEFAULT_AI_BASE_URL),
            ai_model=os.getenv("AI_MODEL", DEFAULT_AI_MODEL),
            ai_timeout=_env_float("AI_TIMEOUT", 60.0),
            ai_max_retries=_env_int("AI_MAX_RETRIES", 3),
            ai_temperature=_env_float("AI_TEMPERATURE", 0.2),
            ai_json_mode=_env_bool("AI_JSON_MODE", True),
        )


settings = Settings.load()
