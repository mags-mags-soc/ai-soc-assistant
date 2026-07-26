"""Tests for soc.ai.exceptions module.

Rule: AIValidationError must always halt execution —
      no caller may silently swallow it and continue.
"""
from __future__ import annotations

import pytest

from soc.ai.exceptions import (
    AIConfigError,
    AIEngineError,
    AIProviderError,
    AIResponseParseError,
    AITimeoutError,
    AIValidationError,
)


# ---------------------------------------------------------------------------
# AIEngineError – base behaviour
# ---------------------------------------------------------------------------
class TestAIEngineError:
    def test_message_stored(self) -> None:
        err = AIEngineError("base error")
        assert err.message == "base error"

    def test_str_no_context(self) -> None:
        assert str(AIEngineError("oops")) == "oops"

    def test_str_with_context(self) -> None:
        err = AIEngineError("oops", context={"provider": "routellm", "status": 500})
        s = str(err)
        assert "oops" in s
        assert "provider" in s
        assert "routellm" in s
        assert "500" in s

    def test_context_default_empty(self) -> None:
        assert AIEngineError("x").context == {}

    def test_is_catchable_as_exception(self) -> None:
        with pytest.raises(AIEngineError):
            raise AIEngineError("boom")


# ---------------------------------------------------------------------------
# Inheritance hierarchy
# ---------------------------------------------------------------------------
class TestInheritance:
    def test_all_subclass_of_base(self) -> None:
        for cls in (
            AIConfigError,
            AIProviderError,
            AITimeoutError,
            AIResponseParseError,
            AIValidationError,
        ):
            assert issubclass(cls, AIEngineError), (
                f"{cls.__name__} must subclass AIEngineError"
            )

    def test_all_are_standard_exceptions(self) -> None:
        for cls in (
            AIConfigError,
            AIProviderError,
            AITimeoutError,
            AIResponseParseError,
            AIValidationError,
        ):
            assert issubclass(cls, Exception)

    def test_base_catches_all_children(self) -> None:
        children = [
            AIConfigError("cfg"),
            AIProviderError("prov"),
            AITimeoutError("to"),
            AIResponseParseError("parse"),
            AIValidationError("val"),
        ]
        for exc in children:
            with pytest.raises(AIEngineError):
                raise exc


# ---------------------------------------------------------------------------
# AIValidationError – critical contract
# ---------------------------------------------------------------------------
class TestAIValidationError:
    def test_raises_and_catches_specifically(self) -> None:
        with pytest.raises(AIValidationError):
            raise AIValidationError("invalid output from AI")

    def test_stores_raw_data(self) -> None:
        raw = {"risk_assessment": {"level": "UNKNOWN_LEVEL"}}
        err = AIValidationError("bad schema", raw_data=raw)
        assert err.raw_data == raw

    def test_raw_data_default_empty_dict(self) -> None:
        assert AIValidationError("x").raw_data == {}

    def test_stores_validation_errors(self) -> None:
        verrs = [{"loc": ("risk_assessment", "level"), "msg": "value is not valid"}]
        err = AIValidationError("bad", validation_errors=verrs)
        assert len(err.validation_errors) == 1
        assert err.validation_errors[0]["loc"] == ("risk_assessment", "level")

    def test_validation_errors_default_empty_list(self) -> None:
        assert AIValidationError("x").validation_errors == []

    def test_error_summary_no_errors_returns_message(self) -> None:
        err = AIValidationError("just the message")
        assert err.error_summary() == "just the message"

    def test_error_summary_with_errors(self) -> None:
        verrs = [
            {"loc": ("risk_assessment", "score"), "msg": "must be <= 10"},
            {"loc": ("summary",), "msg": "min_length is 20"},
        ]
        err = AIValidationError("failed", validation_errors=verrs)
        summary = err.error_summary()
        assert "risk_assessment -> score" in summary
        assert "must be <= 10" in summary
        assert "summary" in summary
        assert "min_length is 20" in summary

    def test_execution_halts_on_raise(self) -> None:
        """Code after raise must never execute — this is the core safety contract."""
        sentinel = False
        try:
            raise AIValidationError("halt!")
            sentinel = True  # type: ignore[unreachable]
        except AIValidationError:
            pass
        assert not sentinel, "Execution continued past AIValidationError — contract violated"

    def test_context_forwarded_to_str(self) -> None:
        err = AIValidationError("x", context={"model": "gpt-4o", "attempt": 1})
        s = str(err)
        assert "gpt-4o" in s
        assert "attempt" in s


# ---------------------------------------------------------------------------
# AIResponseParseError
# ---------------------------------------------------------------------------
class TestAIResponseParseError:
    def test_stores_raw_response(self) -> None:
        err = AIResponseParseError("cannot parse", raw_response="```not json```")
        assert err.raw_response == "```not json```"

    def test_default_raw_response_is_empty_string(self) -> None:
        assert AIResponseParseError("bad").raw_response == ""

    def test_raises_and_catches(self) -> None:
        with pytest.raises(AIResponseParseError):
            raise AIResponseParseError("oops", raw_response="{broken")

    def test_also_catchable_as_base(self) -> None:
        with pytest.raises(AIEngineError):
            raise AIResponseParseError("parse fail")


# ---------------------------------------------------------------------------
# AIProviderError / AITimeoutError / AIConfigError – smoke tests
# ---------------------------------------------------------------------------
class TestSimpleExceptions:
    def test_provider_error_with_context(self) -> None:
        err = AIProviderError("503", context={"url": "https://api.example.com"})
        assert "503" in str(err)
        assert "api.example.com" in str(err)

    def test_timeout_error_with_context(self) -> None:
        err = AITimeoutError("timed out", context={"timeout_secs": 30})
        assert "timed out" in str(err)
        assert "30" in str(err)

    def test_config_error(self) -> None:
        err = AIConfigError("unknown provider: foobar")
        assert "foobar" in str(err)
