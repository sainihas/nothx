"""Regression tests for heuristic signal fixes.

These cover signals that were previously dead: sender-address patterns matched
against a bare domain (never containing '@'), and the excessive-caps pattern
neutralized by lowercasing + IGNORECASE.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db
from nothx.classifier.heuristics import HeuristicScorer
from nothx.classifier.learner import reset_learner
from nothx.config import ThresholdConfig
from nothx.models import Action, SenderStats


@pytest.fixture
def scorer():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            reset_learner()
            yield HeuristicScorer()


class TestSenderPatterns:
    def test_marketing_sender_raises_score(self, scorer):
        """A 'marketing@' sender must now trigger the spam sender weight."""
        with_pattern = scorer.score(
            SenderStats(
                domain="brand.com",
                total_emails=10,
                seen_emails=5,
                sample_subjects=["Newsletter"],
                sample_senders=["marketing@brand.com"],
            )
        )
        without_pattern = scorer.score(
            SenderStats(
                domain="brand.com",
                total_emails=10,
                seen_emails=5,
                sample_subjects=["Newsletter"],
                sample_senders=["jane.smith@brand.com"],
            )
        )
        assert with_pattern > without_pattern

    def test_security_sender_lowers_score(self, scorer):
        """A 'security@' sender must trigger the safe sender weight."""
        safe = scorer.score(
            SenderStats(
                domain="brand.com",
                total_emails=10,
                seen_emails=5,
                sample_subjects=["Notice"],
                sample_senders=["security@brand.com"],
            )
        )
        neutral = scorer.score(
            SenderStats(
                domain="brand.com",
                total_emails=10,
                seen_emails=5,
                sample_subjects=["Notice"],
                sample_senders=["jane@brand.com"],
            )
        )
        assert safe < neutral

    def test_empty_sample_senders_is_safe(self, scorer):
        """No sender addresses must not crash and must not fire sender weights."""
        score = scorer.score(SenderStats(domain="brand.com", total_emails=10, seen_emails=5))
        assert 0 <= score <= 100


class TestCapsPattern:
    def test_all_caps_subject_scores_higher_than_normal(self, scorer):
        """Excessive caps is a spam signal; lowercase text must not trigger it."""
        shouty = scorer.score(
            SenderStats(
                domain="brand.com",
                total_emails=10,
                seen_emails=5,
                sample_subjects=["LIMITED TIME MEGA DEALS INSIDE"],
                sample_senders=["news@brand.com"],
            )
        )
        calm = scorer.score(
            SenderStats(
                domain="brand.com",
                total_emails=10,
                seen_emails=5,
                sample_subjects=["a short lowercase note about your account"],
                sample_senders=["news@brand.com"],
            )
        )
        assert shouty > calm


class TestScoreConfidenceAlignment:
    def test_unsub_at_threshold_meets_confidence(self, scorer):
        """A score exactly at the unsub threshold must clear unsub_confidence."""
        thresholds = ThresholdConfig()
        # Force a score at the threshold via a spammy, never-opened sender
        sender = SenderStats(
            domain="spam.com",
            total_emails=100,
            seen_emails=0,
            sample_subjects=["SALE 90% OFF ACT NOW", "LAST CHANCE DEALS"],
            sample_senders=["promo@spam.com"],
        )
        result = scorer.classify(sender)
        assert result is not None
        assert result.action in (Action.UNSUB, Action.BLOCK)
        # Any heuristic unsub must be actionable under the confidence gate
        assert result.confidence >= thresholds.unsub_confidence

    def test_guarantee_holds_for_high_confidence_config(self):
        """The confidence gate must be met even when configured above 0.95."""
        from nothx.classifier.heuristics import HeuristicScorer

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            with patch("nothx.db.get_db_path", return_value=db_path):
                db.init_db()
                reset_learner()
                thresholds = ThresholdConfig(unsub_confidence=0.99, keep_confidence=0.99)
                scorer = HeuristicScorer(threshold_config=thresholds)
                sender = SenderStats(
                    domain="spam.com",
                    total_emails=100,
                    seen_emails=0,
                    sample_subjects=["SALE 90% OFF ACT NOW", "LAST CHANCE DEALS"],
                    sample_senders=["promo@spam.com"],
                )
                result = scorer.classify(sender)
                assert result is not None
                assert result.action in (Action.UNSUB, Action.BLOCK)
                assert result.confidence >= 0.99
