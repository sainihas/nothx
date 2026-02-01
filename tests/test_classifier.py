"""Tests for the classification system."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db
from nothx.classifier import reset_learner
from nothx.classifier.heuristics import HeuristicScorer
from nothx.classifier.patterns import PatternMatcher
from nothx.models import Action, SenderStats


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            reset_learner()  # Reset learner to use fresh DB
            yield db_path
            reset_learner()  # Clean up after test


class TestPatternMatcher:
    """Tests for preset pattern matching."""

    def setup_method(self):
        self.matcher = PatternMatcher()

    def test_marketing_domain_pattern(self):
        """Test that marketing@ prefix is matched."""
        sender = SenderStats(
            domain="marketing.company.com",
            total_emails=10,
        )
        result = self.matcher.match(sender)
        assert result is not None
        assert result.action == Action.UNSUB

    def test_gov_domain_kept(self):
        """Test that .gov domains are kept."""
        sender = SenderStats(
            domain="irs.gov",
            total_emails=5,
        )
        result = self.matcher.match(sender)
        assert result is not None
        assert result.action == Action.KEEP

    def test_bank_domain_kept(self):
        """Test that bank-related domains are kept."""
        sender = SenderStats(
            domain="notifications.bankofamerica.com",
            total_emails=10,
        )
        result = self.matcher.match(sender)
        assert result is not None
        assert result.action == Action.KEEP

    def test_unknown_domain_no_match(self):
        """Test that unknown domains don't match patterns."""
        sender = SenderStats(
            domain="randomcompany.io",
            total_emails=5,
        )
        result = self.matcher.match(sender)
        assert result is None


class TestHeuristicScorer:
    """Tests for heuristic scoring."""

    def test_never_opened_high_score(self, temp_db):
        """Test that never-opened emails get high spam score."""
        scorer = HeuristicScorer()
        sender = SenderStats(
            domain="promo.store.com",
            total_emails=20,
            seen_emails=0,
            sample_subjects=["50% OFF SALE!", "Limited Time Offer"],
        )
        score = scorer.score(sender)
        assert score >= 70  # High spam score

    def test_high_engagement_low_score(self, temp_db):
        """Test that high engagement leads to low spam score."""
        scorer = HeuristicScorer()
        sender = SenderStats(
            domain="newsletter.goodsite.com",
            total_emails=10,
            seen_emails=8,  # 80% open rate
            sample_subjects=["Weekly Update", "New Article Published"],
        )
        score = scorer.score(sender)
        assert score <= 40  # Low spam score

    def test_transactional_subjects_low_score(self, temp_db):
        """Test that transactional subject lines lower spam score."""
        scorer = HeuristicScorer()
        sender = SenderStats(
            domain="notifications.store.com",
            total_emails=5,
            seen_emails=3,
            sample_subjects=["Your order #12345 has shipped", "Receipt for your purchase"],
        )
        score = scorer.score(sender)
        assert score <= 50

    def test_cold_outreach_detected(self, temp_db):
        """Test that cold outreach patterns are detected."""
        scorer = HeuristicScorer()
        sender = SenderStats(
            domain="sales.company.io",
            total_emails=3,
            seen_emails=0,
            sample_subjects=["Quick question about your company", "Following up on my last email"],
        )
        result = scorer.classify(sender)
        # Should either be high score or detected as cold outreach
        assert result is None or result.action in (Action.UNSUB, Action.BLOCK)


class TestSenderStats:
    """Tests for SenderStats model."""

    def test_open_rate_calculation(self):
        """Test open rate is calculated correctly."""
        sender = SenderStats(
            domain="test.com",
            total_emails=100,
            seen_emails=25,
        )
        assert sender.open_rate == 25.0

    def test_open_rate_zero_emails(self):
        """Test open rate with zero emails."""
        sender = SenderStats(
            domain="test.com",
            total_emails=0,
            seen_emails=0,
        )
        assert sender.open_rate == 0.0


class TestEmailHeader:
    """Tests for EmailHeader model."""

    def test_domain_extraction_simple(self):
        """Test domain extraction from simple email."""
        from nothx.models import EmailHeader

        header = EmailHeader(
            sender="test@example.com",
            subject="Test",
            date=datetime.now(),
            message_id="123",
        )
        assert header.domain == "example.com"

    def test_domain_extraction_with_name(self):
        """Test domain extraction from email with display name."""
        from nothx.models import EmailHeader

        header = EmailHeader(
            sender="John Doe <john@company.org>",
            subject="Test",
            date=datetime.now(),
            message_id="123",
        )
        assert header.domain == "company.org"

    def test_unsubscribe_url_extraction(self):
        """Test List-Unsubscribe URL extraction."""
        from nothx.models import EmailHeader

        header = EmailHeader(
            sender="test@example.com",
            subject="Test",
            date=datetime.now(),
            message_id="123",
            list_unsubscribe="<https://example.com/unsub?id=123>, <mailto:unsub@example.com>",
        )
        assert header.list_unsubscribe_url == "https://example.com/unsub?id=123"
        assert header.list_unsubscribe_mailto == "mailto:unsub@example.com"
