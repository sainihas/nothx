"""Tests for AI response JSON extraction robustness."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db
from nothx.classifier.ai import AI_RETRY_CONFIG, AIClassifier, _extract_json_value
from nothx.classifier.providers.base import ProviderError, ProviderErrorType
from nothx.config import Config
from nothx.models import Action, SenderStats


class TestExtractJsonValue:
    def test_plain_array(self):
        assert _extract_json_value('[{"a": 1}]', "[") == [{"a": 1}]

    def test_array_in_markdown_fence(self):
        text = 'Here you go:\n```json\n[{"domain": "x.com"}]\n```\nDone.'
        assert _extract_json_value(text, "[") == [{"domain": "x.com"}]

    def test_array_with_trailing_prose(self):
        text = '[{"domain": "x.com"}]\n\nLet me know if you need more.'
        assert _extract_json_value(text, "[") == [{"domain": "x.com"}]

    def test_first_of_multiple_arrays(self):
        """rfind-based slicing would merge two arrays into invalid JSON."""
        text = '[{"a": 1}]\nand also\n[{"b": 2}]'
        assert _extract_json_value(text, "[") == [{"a": 1}]

    def test_object_extraction(self):
        text = 'Result:\n```json\n{"insights": []}\n```'
        assert _extract_json_value(text, "{") == {"insights": []}

    def test_bracket_in_prose_before_json(self):
        """A stray '[' in prose must not derail extraction."""
        text = 'Consider [this] example: [{"domain": "x.com"}]'
        assert _extract_json_value(text, "[") == [{"domain": "x.com"}]

    def test_no_json_returns_none(self):
        assert _extract_json_value("no json here", "[") is None

    def test_truncated_json_returns_none(self):
        assert _extract_json_value('[{"domain": "x.com"', "[") is None


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            yield db_path


class _FakeProvider:
    """Deterministic provider double with a scriptable response sequence."""

    name = "fake"
    default_model = "fake-model"

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls: list[str] = []

    def is_available(self) -> bool:
        return True

    def complete(self, prompt, max_tokens=4096):
        self.calls.append(prompt)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome

        class _Response:
            text = outcome

        return _Response()


def _classifier(provider) -> AIClassifier:
    config = Config()
    config.ai.enabled = True
    config.ai.api_key = "test-key"
    classifier = AIClassifier(config)
    classifier._provider = provider
    classifier._provider_initialized = True
    return classifier


def _sender(domain: str = "mailer.example") -> SenderStats:
    return SenderStats(
        domain=domain,
        total_emails=8,
        seen_emails=0,
        first_seen=datetime(2026, 6, 1, tzinfo=UTC),
        last_seen=datetime(2026, 8, 1, tzinfo=UTC),
        sample_subjects=["Mega SALE", "50% OFF", "Last chance", "Deals", "Sale again"],
        sample_senders=[f"promo@{domain}"],
        has_unsubscribe=True,
    )


class TestParseResponseRobustness:
    def test_null_fields_degrade_to_item_errors_not_crashes(self, temp_db):
        classifier = _classifier(_FakeProvider([]))
        text = (
            '[{"domain": null, "type": "marketing", "action": "unsub"},'
            ' {"domain": "ok.example", "type": null, "action": null,'
            ' "confidence": 0.9, "reasoning": null}]'
        )
        results, errors = classifier._parse_response(text)

        assert "ok.example" in results
        assert results["ok.example"].action is Action.REVIEW
        assert results["ok.example"].reasoning == ""
        assert any("missing or empty domain" in e for e in errors)

    def test_numeric_fields_do_not_crash(self, temp_db):
        classifier = _classifier(_FakeProvider([]))
        text = '[{"domain": "ok.example", "type": 3, "action": 7, "confidence": "x"}]'
        results, errors = classifier._parse_response(text)

        assert "ok.example" in results
        assert results["ok.example"].action is Action.REVIEW
        assert errors


class TestProviderRetry:
    def test_retryable_provider_error_is_retried(self, temp_db, monkeypatch):
        monkeypatch.setattr(AI_RETRY_CONFIG, "base_delay", 0.0)
        monkeypatch.setattr(AI_RETRY_CONFIG, "max_delay", 0.0)
        rate_limited = ProviderError(
            error_type=ProviderErrorType.RATE_LIMIT_ERROR,
            message="429",
            provider="fake",
            retryable=True,
        )
        ok = (
            '[{"key": "mailer.example", "domain": "mailer.example", "type": "marketing",'
            ' "action": "unsub", "confidence": 0.95, "reasoning": "promo"}]'
        )
        provider = _FakeProvider([rate_limited, ok])
        classifier = _classifier(provider)

        results = classifier.classify_batch([_sender()])

        assert len(provider.calls) == 2
        assert results["mailer.example"].action is Action.UNSUB

    def test_non_retryable_provider_error_fails_immediately(self, temp_db, monkeypatch):
        monkeypatch.setattr(AI_RETRY_CONFIG, "base_delay", 0.0)
        auth_error = ProviderError(
            error_type=ProviderErrorType.AUTHENTICATION_ERROR,
            message="bad key",
            provider="fake",
            retryable=False,
        )
        provider = _FakeProvider([auth_error])
        classifier = _classifier(provider)

        results = classifier.classify_batch([_sender()])

        assert results == {}
        assert len(provider.calls) == 1

    def test_exhausted_retries_surface_as_empty_result(self, temp_db, monkeypatch):
        monkeypatch.setattr(AI_RETRY_CONFIG, "base_delay", 0.0)
        monkeypatch.setattr(AI_RETRY_CONFIG, "max_delay", 0.0)
        rate_limited = ProviderError(
            error_type=ProviderErrorType.RATE_LIMIT_ERROR,
            message="429",
            provider="fake",
            retryable=True,
        )
        provider = _FakeProvider([rate_limited] * AI_RETRY_CONFIG.max_attempts)
        classifier = _classifier(provider)

        results = classifier.classify_batch([_sender()])

        assert results == {}
        assert len(provider.calls) == AI_RETRY_CONFIG.max_attempts


class TestPromptPayload:
    def test_payload_includes_new_evidence_fields(self, temp_db):
        ok = (
            '[{"key": "mailer.example", "domain": "mailer.example", "type": "marketing",'
            ' "action": "unsub", "confidence": 0.95, "reasoning": "promo"}]'
        )
        provider = _FakeProvider([ok])
        classifier = _classifier(provider)

        classifier.classify_batch([_sender()])

        prompt = provider.calls[0]
        assert "sample_senders" in prompt
        assert "promo@mailer.example" in prompt
        assert "provider_signals" in prompt
        assert "junk_marked_emails" in prompt
        assert "first_seen" in prompt
        assert '"2026-06-01"' in prompt
        # All five available subjects are forwarded, not just three.
        assert "Sale again" in prompt
