"""Tests for the classification engine integration."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db
from nothx.classifier.engine import ClassificationEngine
from nothx.config import Config
from nothx.models import Action, EmailType, SenderStats


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            yield db_path


@pytest.fixture
def config_no_ai():
    """Create a config with AI disabled."""
    config = Config()
    config.ai.enabled = False
    return config


@pytest.fixture
def config_with_ai():
    """Create a config with AI enabled (mocked)."""
    config = Config()
    config.ai.enabled = True
    config.ai.api_key = "test-key"
    return config


class TestClassificationEngine:
    """Tests for the ClassificationEngine class."""

    def test_classify_user_rule_highest_priority(self, temp_db, config_no_ai):
        """Test that user rules take highest priority."""
        # Add a user rule
        db.add_rule("*.test.com", "keep")

        engine = ClassificationEngine(config_no_ai)
        sender = SenderStats(
            domain="marketing.test.com",  # Would normally be unsubbed
            total_emails=50,
            seen_emails=0,
            sample_subjects=["SALE!", "50% OFF!"],
            has_unsubscribe=True,
        )

        result = engine.classify(sender)

        assert result.action == Action.KEEP
        assert result.source == "user_rule"
        assert result.confidence == 1.0

    def test_classify_preset_pattern(self, temp_db, config_no_ai):
        """Test classification via preset patterns."""
        engine = ClassificationEngine(config_no_ai)

        # Government domain should be kept
        sender = SenderStats(
            domain="irs.gov",
            total_emails=5,
        )

        result = engine.classify(sender)

        assert result.action == Action.KEEP
        assert result.source == "preset"

    def test_classify_marketing_pattern(self, temp_db, config_no_ai):
        """Test marketing domains are classified for unsubscribe."""
        engine = ClassificationEngine(config_no_ai)

        sender = SenderStats(
            domain="marketing.somecompany.com",
            total_emails=20,
            seen_emails=0,
            has_unsubscribe=True,
        )

        result = engine.classify(sender)

        assert result.action == Action.UNSUB
        assert result.source == "preset"

    def test_classify_heuristics_fallback(self, temp_db, config_no_ai):
        """Test heuristics are used when no pattern matches."""
        engine = ClassificationEngine(config_no_ai)

        # High spam score: never opened, many emails, spam subjects
        sender = SenderStats(
            domain="unknownsender.io",
            total_emails=30,
            seen_emails=0,
            sample_subjects=["FINAL SALE!", "Limited Time Only!!!", "Act Now!"],
            has_unsubscribe=True,
        )

        result = engine.classify(sender)

        # Should be classified by heuristics
        assert result.source in ("heuristics", "uncertain")
        if result.source == "heuristics":
            assert result.action in (Action.UNSUB, Action.BLOCK)

    def test_classify_review_queue(self, temp_db, config_no_ai):
        """Test uncertain cases go to review queue."""
        engine = ClassificationEngine(config_no_ai)

        # Ambiguous sender - moderate engagement, unclear patterns
        sender = SenderStats(
            domain="newsletter.randomsite.io",
            total_emails=5,
            seen_emails=2,  # 40% open rate - not clearly spam or not
            sample_subjects=["Weekly digest", "New content"],
        )

        result = engine.classify(sender)

        # Could go to review or be classified by heuristics
        assert result.action in (Action.REVIEW, Action.KEEP, Action.UNSUB)

    def test_classify_batch(self, temp_db, config_no_ai):
        """Test batch classification."""
        engine = ClassificationEngine(config_no_ai)

        senders = [
            SenderStats(domain="irs.gov", total_emails=3),
            SenderStats(domain="marketing.spam.com", total_emails=50, seen_emails=0),
            SenderStats(domain="unknown.io", total_emails=5, seen_emails=3),
        ]

        results = engine.classify_batch(senders)

        assert len(results) == 3
        assert "irs.gov" in results
        assert "marketing.spam.com" in results
        assert "unknown.io" in results

        # Gov domain should be kept
        assert results["irs.gov"].action == Action.KEEP

    def test_classify_batch_empty(self, temp_db, config_no_ai):
        """Test batch classification with empty list."""
        engine = ClassificationEngine(config_no_ai)

        results = engine.classify_batch([])

        assert results == {}


class TestShouldAutoAct:
    """Tests for auto-action decision logic."""

    def test_should_auto_act_confirm_mode(self, temp_db):
        """Test that confirm mode never auto-acts."""
        config = Config()
        config.ai.enabled = False
        config.operation_mode = "confirm"

        engine = ClassificationEngine(config)

        from nothx.models import Classification

        classification = Classification(
            email_type=EmailType.MARKETING,
            action=Action.UNSUB,
            confidence=0.95,
            reasoning="High confidence",
            source="preset",
        )

        assert engine.should_auto_act(classification) is False

    def test_should_auto_act_review(self, temp_db, config_no_ai):
        """Test that review actions never auto-act."""
        engine = ClassificationEngine(config_no_ai)

        from nothx.models import Classification

        classification = Classification(
            email_type=EmailType.UNKNOWN,
            action=Action.REVIEW,
            confidence=0.5,
            reasoning="Uncertain",
            source="uncertain",
        )

        assert engine.should_auto_act(classification) is False

    def test_should_auto_act_high_confidence(self, temp_db, config_no_ai):
        """Test auto-action with high confidence."""
        engine = ClassificationEngine(config_no_ai)

        from nothx.models import Classification

        classification = Classification(
            email_type=EmailType.MARKETING,
            action=Action.UNSUB,
            confidence=0.90,
            reasoning="High confidence",
            source="preset",
        )

        assert engine.should_auto_act(classification) is True

    def test_should_auto_act_low_confidence(self, temp_db, config_no_ai):
        """Test no auto-action with low confidence."""
        config = Config()
        config.ai.enabled = False
        config.thresholds.unsub_confidence = 0.90

        engine = ClassificationEngine(config)

        from nothx.models import Classification

        classification = Classification(
            email_type=EmailType.MARKETING,
            action=Action.UNSUB,
            confidence=0.70,  # Below threshold
            reasoning="Low confidence",
            source="heuristics",
        )

        assert engine.should_auto_act(classification) is False
