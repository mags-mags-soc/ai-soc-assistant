"""OpenAI-compatible AI client with strict validation.

Sends chat-completion requests to any OpenAI-compatible endpoint (OpenAI,
RouteLLM, etc.), retries transient failures, extracts the JSON body, and
validates it against AIAnalysis. Invalid output ALWAYS raises — it never
propagates downstream.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from pydantic import ValidationError

from ..config import Settings, settings as default_settings
from ..logging_setup import setup_logging
from .exceptions import (
    AIConfigError,
    AIProviderError,
    AIResponseParseError,
    AITimeoutError,
    AIValidationError,
)
from .schemas import AIAnalysis

_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


class AIClient:
    """Thin, defensive wrapper around an OpenAI-compatible chat API."""

    def __init__(self, config: Settings | None = None) -> None:
        self._settings = config or default_settings
        self._log = setup_logging(self._settings.logs_dir, self._settings.log_level)
        self._client: Any | None = None

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self._settings.ai_api_key:
            raise AIConfigError("AI_API_KEY is not set; cannot call the AI provider")
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise AIConfigError("openai package is not installed") from exc
        self._client = OpenAI(
            api_key=self._settings.ai_api_key,
            base_url=self._settings.ai_base_url or None,
            timeout=self._settings.ai_timeout,
        )
        return self._client

    def analyze(self, system_prompt: str, user_prompt: str) -> AIAnalysis:
        """Run one analysis request and return a validated AIAnalysis."""
        raw = self._chat_with_retry(system_prompt, user_prompt)
        data = self._extract_json(raw)
        return self._validate(data)

    def _chat_with_retry(self, system_prompt: str, user_prompt: str) -> str:
        client = self._ensure_client()
        attempts = max(1, self._settings.ai_max_retries)
        last_exc: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                kwargs: dict[str, Any] = {
                    "model": self._settings.ai_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": self._settings.ai_temperature,
                }
                # OpenAI's json_object mode is not accepted by every
                # OpenAI-compatible endpoint. When disabled, _extract_json and
                # the AIAnalysis schema still guarantee valid structured output.
                if self._settings.ai_json_mode:
                    kwargs["response_format"] = {"type": "json_object"}
                resp = client.chat.completions.create(**kwargs)
                content = resp.choices[0].message.content
                if not content or not content.strip():
                    raise AIResponseParseError("AI returned an empty response")
                return content
            except (AIResponseParseError,) as exc:
                last_exc = exc
            except Exception as exc:  # noqa: BLE001 - normalize provider errors
                last_exc = exc
                if _is_timeout(exc):
                    last_exc = AITimeoutError(str(exc))

            self._log.warning("AI request attempt %d/%d failed: %s",
                              attempt, attempts, last_exc)
            if attempt < attempts:
                time.sleep(min(2 ** (attempt - 1), 8))

        if isinstance(last_exc, (AITimeoutError, AIResponseParseError)):
            raise last_exc
        raise AIProviderError(f"AI request failed after {attempts} attempts: {last_exc}")

    @staticmethod
    def _extract_json(raw: str) -> dict[str, Any]:
        text = raw.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        match = _JSON_FENCE.search(text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
        raise AIResponseParseError("Could not extract valid JSON from AI response")

    def _validate(self, data: dict[str, Any]) -> AIAnalysis:
        try:
            return AIAnalysis(**data)
        except ValidationError as exc:
            self._log.error("AI output failed schema validation: %s", exc)
            raise AIValidationError(f"AI output failed validation: {exc}") from exc


def _is_timeout(exc: Exception) -> bool:
    name = exc.__class__.__name__.lower()
    return "timeout" in name or "timeout" in str(exc).lower()
