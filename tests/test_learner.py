"""Tests for the preference learning system."""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db
from nothx.classifier.learner import PreferenceLearner, get_learner, reset_learner
from nothx.models import Action, SenderStats, UserAction, UserPreference


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            reset_learner()  # Reset global learner state
            yield db_path


@pytest.fixture
def learner(temp_db):
    """Create a fresh PreferenceLearner for testing."""
    return PreferenceLearner()


class TestDatabaseTablesExist:
    """Tests that new learning tables exist."""

    def test_user_actions_table_exists(self, temp_db):
        """Test that user_actions table is created."""
        with db.get_db() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            assert "user_actions" in tables

    def test_user_preferences_table_exists(self, temp_db):
        """Test that user_preferences table is created."""
        with db.get_db() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            assert "user_preferences" in tables


class TestUserActionLogging:
    """Tests for user action logging."""

    def test_log_user_action(self, temp_db):
        """Test logging a user action."""
        action = UserAction(
            domain="example.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
            ai_recommendation=Action.UNSUB,
            heuristic_score=75,
            open_rate=45.0,
            email_count=20,
        )
        db.log_user_action(action)

        actions = db.get_user_actions(limit=10)
        assert len(actions) == 1
        assert actions[0].domain == "example.com"
        assert actions[0].action == Action.KEEP
        assert actions[0].ai_recommendation == Action.UNSUB
        assert actions[0].open_rate == 45.0

    def test_get_user_actions_with_days_filter(self, temp_db):
        """Test filtering actions by recency."""
        # Log an action
        action = UserAction(
            domain="recent.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
        )
        db.log_user_action(action)

        # Get actions from last 7 days
        actions = db.get_user_actions(days=7)
        assert len(actions) == 1

    def test_get_user_actions_with_action_filter(self, temp_db):
        """Test filtering actions by action type."""
        db.log_user_action(UserAction("keep.com", Action.KEEP, datetime.now()))
        db.log_user_action(UserAction("unsub.com", Action.UNSUB, datetime.now()))

        keep_actions = db.get_user_actions(action_filter=Action.KEEP)
        assert len(keep_actions) == 1
        assert keep_actions[0].domain == "keep.com"

    def test_get_action_count(self, temp_db):
        """Test counting total actions."""
        assert db.get_action_count() == 0

        db.log_user_action(UserAction("a.com", Action.KEEP, datetime.now()))
        db.log_user_action(UserAction("b.com", Action.UNSUB, datetime.now()))

        assert db.get_action_count() == 2

    def test_user_action_was_correction(self, temp_db):
        """Test the was_correction property."""
        correction = UserAction(
            domain="test.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
            ai_recommendation=Action.UNSUB,
        )
        assert correction.was_correction is True

        not_correction = UserAction(
            domain="test.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
            ai_recommendation=Action.KEEP,
        )
        assert not_correction.was_correction is False

        no_ai = UserAction(
            domain="test.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
        )
        assert no_ai.was_correction is False


class TestUserPreferences:
    """Tests for user preference storage."""

    def test_set_and_get_preference(self, temp_db):
        """Test setting and getting a preference."""
        pref = UserPreference(
            feature="test_feature",
            value=0.75,
            confidence=0.8,
            sample_count=5,
            last_updated=datetime.now(),
            source="learned",
        )
        db.set_user_preference(pref)

        retrieved = db.get_user_preference("test_feature")
        assert retrieved is not None
        assert retrieved.feature == "test_feature"
        assert retrieved.value == 0.75
        assert retrieved.confidence == 0.8
        assert retrieved.sample_count == 5

    def test_update_existing_preference(self, temp_db):
        """Test updating an existing preference."""
        pref1 = UserPreference(
            feature="update_test",
            value=0.5,
            confidence=0.5,
            sample_count=1,
            last_updated=datetime.now(),
        )
        db.set_user_preference(pref1)

        pref2 = UserPreference(
            feature="update_test",
            value=0.8,
            confidence=0.7,
            sample_count=3,
            last_updated=datetime.now(),
        )
        db.set_user_preference(pref2)

        retrieved = db.get_user_preference("update_test")
        assert retrieved.value == 0.8
        assert retrieved.sample_count == 3

    def test_get_nonexistent_preference(self, temp_db):
        """Test getting a preference that doesn't exist."""
        pref = db.get_user_preference("nonexistent")
        assert pref is None

    def test_get_all_preferences(self, temp_db):
        """Test getting all preferences."""
        db.set_user_preference(UserPreference("a", 0.5, 0.5, 1, datetime.now()))
        db.set_user_preference(UserPreference("b", 0.6, 0.6, 2, datetime.now()))

        all_prefs = db.get_all_preferences()
        assert len(all_prefs) == 2

    def test_get_preferences_by_prefix(self, temp_db):
        """Test getting preferences by prefix."""
        db.set_user_preference(UserPreference("keyword:bank", 0.9, 0.8, 5, datetime.now()))
        db.set_user_preference(UserPreference("keyword:promo", 0.1, 0.7, 4, datetime.now()))
        db.set_user_preference(UserPreference("open_rate_weight", 0.8, 0.6, 10, datetime.now()))

        keyword_prefs = db.get_preferences_by_prefix("keyword:")
        assert len(keyword_prefs) == 2

    def test_delete_preference(self, temp_db):
        """Test deleting a preference."""
        db.set_user_preference(UserPreference("to_delete", 0.5, 0.5, 1, datetime.now()))

        assert db.delete_user_preference("to_delete") is True
        assert db.get_user_preference("to_delete") is None

    def test_delete_nonexistent_preference(self, temp_db):
        """Test deleting a preference that doesn't exist."""
        assert db.delete_user_preference("nonexistent") is False


class TestLearningStats:
    """Tests for learning statistics."""

    def test_get_learning_stats_empty(self, temp_db):
        """Test stats with no data."""
        stats = db.get_learning_stats()
        assert stats["total_actions"] == 0
        assert stats["total_preferences"] == 0
        assert stats["total_corrections"] == 0

    def test_get_learning_stats_with_data(self, temp_db):
        """Test stats with data."""
        # Add actions
        db.log_user_action(UserAction("a.com", Action.KEEP, datetime.now()))
        db.log_user_action(UserAction("b.com", Action.UNSUB, datetime.now()))
        db.log_user_action(
            UserAction(
                "c.com",
                Action.KEEP,
                datetime.now(),
                ai_recommendation=Action.UNSUB,  # This is a correction
            )
        )

        # Add preferences
        db.set_user_preference(UserPreference("pref1", 0.5, 0.5, 1, datetime.now()))

        stats = db.get_learning_stats()
        assert stats["total_actions"] == 3
        assert stats["total_preferences"] == 1
        assert stats["total_corrections"] == 1
        assert stats["keep_actions"] == 2
        assert stats["unsub_actions"] == 1


class TestPreferenceLearnerKeywords:
    """Tests for keyword learning."""

    def test_extract_keywords_simple(self, learner):
        """Test keyword extraction from simple domains."""
        keywords = learner._extract_keywords("example.com")
        assert "example" in keywords
        assert "com" not in keywords  # TLD removed

    def test_extract_keywords_with_subdomain(self, learner):
        """Test keyword extraction with subdomains."""
        keywords = learner._extract_keywords("marketing.example.com")
        assert "marketing" in keywords
        assert "example" in keywords

    def test_extract_keywords_hyphenated(self, learner):
        """Test keyword extraction from hyphenated domains."""
        keywords = learner._extract_keywords("my-awesome-service.io")
        assert "awesome" in keywords
        assert "service" in keywords

    def test_extract_keywords_skips_short(self, learner):
        """Test that short parts are skipped."""
        keywords = learner._extract_keywords("a.bc.example.com")
        assert "a" not in keywords
        assert "bc" not in keywords
        assert "example" in keywords

    def test_extract_keywords_skips_common(self, learner):
        """Test that common non-meaningful parts are skipped."""
        keywords = learner._extract_keywords("www.mail.example.com")
        assert "www" not in keywords
        assert "mail" not in keywords
        assert "example" in keywords

    def test_update_keyword_preferences_new(self, temp_db, learner):
        """Test creating new keyword preference."""
        action = UserAction(
            domain="chase.bank.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
        )
        learner.update_from_action(action)

        # Should have created preferences for 'chase' and 'bank'
        bank_pref = db.get_user_preference("keyword:bank")
        assert bank_pref is not None
        assert bank_pref.value == 1.0  # KEEP = 1.0
        assert bank_pref.sample_count == 1

    def test_update_keyword_preferences_existing(self, temp_db, learner):
        """Test updating existing keyword preference."""
        # First action: KEEP
        learner.update_from_action(
            UserAction(
                domain="chase.bank.com",
                action=Action.KEEP,
                timestamp=datetime.now(),
            )
        )

        # Second action: UNSUB on different bank domain
        learner.update_from_action(
            UserAction(
                domain="promo.bank.net",
                action=Action.UNSUB,
                timestamp=datetime.now(),
            )
        )

        bank_pref = db.get_user_preference("keyword:bank")
        assert bank_pref is not None
        assert bank_pref.sample_count == 2
        # Value should be between 0 and 1 (averaged)
        assert 0 < bank_pref.value < 1


class TestPreferenceLearnerOpenRate:
    """Tests for open rate preference learning."""

    def test_open_rate_preference_created(self, temp_db, learner):
        """Test that open rate preference is created."""
        action = UserAction(
            domain="example.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
            open_rate=45.0,
        )
        learner.update_from_action(action)

        pref = db.get_user_preference("open_rate_weight")
        assert pref is not None

    def test_open_rate_decreases_when_keeping_low_open_rate(self, temp_db, learner):
        """Test that weight decreases when user keeps low-open-rate senders."""
        # Keep a sender with very low open rate (goes against heuristics)
        action = UserAction(
            domain="example.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
            open_rate=5.0,  # Very low
        )
        learner.update_from_action(action)

        pref = db.get_user_preference("open_rate_weight")
        assert pref.value < 1.0  # Should decrease from default

    def test_open_rate_skipped_when_none(self, temp_db, learner):
        """Test that open rate learning is skipped when rate is None."""
        action = UserAction(
            domain="example.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
            open_rate=None,
        )
        learner.update_from_action(action)

        pref = db.get_user_preference("open_rate_weight")
        assert pref is None  # Should not be created


class TestPreferenceLearnerVolume:
    """Tests for volume preference learning."""

    def test_volume_preference_created(self, temp_db, learner):
        """Test that volume preference is created."""
        action = UserAction(
            domain="example.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
            email_count=20,
        )
        learner.update_from_action(action)

        pref = db.get_user_preference("volume_weight")
        assert pref is not None

    def test_volume_decreases_when_keeping_high_volume(self, temp_db, learner):
        """Test that weight decreases when user keeps high-volume senders."""
        action = UserAction(
            domain="example.com",
            action=Action.KEEP,
            timestamp=datetime.now(),
            email_count=100,  # Very high
        )
        learner.update_from_action(action)

        pref = db.get_user_preference("volume_weight")
        assert pref.value < 1.0  # Should decrease from default


class TestPreferenceAdjustments:
    """Tests for getting preference adjustments."""

    def test_default_adjustments(self, temp_db, learner):
        """Test default adjustments with no learned preferences."""
        sender = SenderStats(domain="example.com", total_emails=10)
        adjustments = learner.get_preference_adjustments(sender)

        assert adjustments["open_rate_weight"] == 1.0
        assert adjustments["volume_weight"] == 1.0
        assert adjustments["keyword_boost"] == 0

    def test_keyword_boost_positive(self, temp_db, learner):
        """Test positive keyword boost (toward unsub)."""
        # Learn that 'promo' domains should be unsubbed
        for i in range(5):
            learner.update_from_action(
                UserAction(
                    domain=f"promo{i}.marketing.com",
                    action=Action.UNSUB,
                    timestamp=datetime.now(),
                )
            )

        sender = SenderStats(domain="promo.sale.com", total_emails=10)
        adjustments = learner.get_preference_adjustments(sender)

        # Should have positive boost (increase spam score)
        assert adjustments["keyword_boost"] > 0

    def test_keyword_boost_negative(self, temp_db, learner):
        """Test negative keyword boost (toward keep)."""
        # Learn that 'bank' domains should be kept
        for i in range(5):
            learner.update_from_action(
                UserAction(
                    domain=f"notifications{i}.bank.com",
                    action=Action.KEEP,
                    timestamp=datetime.now(),
                )
            )

        sender = SenderStats(domain="alerts.bank.com", total_emails=10)
        adjustments = learner.get_preference_adjustments(sender)

        # Should have negative boost (decrease spam score)
        assert adjustments["keyword_boost"] < 0

    def test_keyword_boost_requires_confidence(self, temp_db, learner):
        """Test that keyword boost requires minimum samples."""
        # Only 1 sample - not enough for confidence
        learner.update_from_action(
            UserAction(
                domain="example.bank.com",
                action=Action.KEEP,
                timestamp=datetime.now(),
            )
        )

        sender = SenderStats(domain="other.bank.com", total_emails=10)
        adjustments = learner.get_preference_adjustments(sender)

        # Should be 0 - not enough samples
        assert adjustments["keyword_boost"] == 0


class TestLearningSummary:
    """Tests for learning summary."""

    def test_empty_summary(self, temp_db, learner):
        """Test summary with no data."""
        summary = learner.get_learning_summary()

        assert summary["total_actions"] == 0
        assert summary["total_corrections"] == 0
        assert summary["open_rate_importance"] == "normal"
        assert summary["volume_sensitivity"] == "normal"
        assert summary["keyword_patterns"] == []

    def test_summary_with_keyword_patterns(self, temp_db, learner):
        """Test summary includes learned keyword patterns."""
        # Learn a keyword pattern with enough samples
        for i in range(5):
            learner.update_from_action(
                UserAction(
                    domain=f"alerts{i}.bank.com",
                    action=Action.KEEP,
                    timestamp=datetime.now(),
                )
            )

        summary = learner.get_learning_summary()

        # Should have detected 'bank' pattern
        bank_patterns = [p for p in summary["keyword_patterns"] if p["keyword"] == "bank"]
        assert len(bank_patterns) == 1
        assert bank_patterns[0]["tendency"] == "keep"


class TestRecencyWeight:
    """Tests for recency weighting."""

    def test_recent_action_has_higher_weight(self, learner):
        """Test that recent actions have higher weight."""
        now = datetime.now()
        old = now - timedelta(days=60)

        recent_weight = learner._recency_weight(now)
        old_weight = learner._recency_weight(old)

        assert recent_weight > old_weight

    def test_same_day_weight_is_near_one(self, learner):
        """Test that same-day actions have weight near 1.0."""
        weight = learner._recency_weight(datetime.now())
        assert 0.9 < weight <= 1.0


class TestConfidenceCalculation:
    """Tests for confidence calculation."""

    def test_single_sample_low_confidence(self, learner):
        """Test that 1 sample gives low confidence."""
        confidence = learner._calculate_confidence(1)
        assert confidence < 0.5

    def test_many_samples_high_confidence(self, learner):
        """Test that many samples give high confidence."""
        confidence = learner._calculate_confidence(10)
        assert confidence > 0.9

    def test_confidence_increases_with_samples(self, learner):
        """Test that confidence increases with sample count."""
        conf1 = learner._calculate_confidence(1)
        conf3 = learner._calculate_confidence(3)
        conf10 = learner._calculate_confidence(10)

        assert conf1 < conf3 < conf10


class TestGlobalLearner:
    """Tests for global learner management."""

    def test_get_learner_returns_same_instance(self, temp_db):
        """Test that get_learner returns the same instance."""
        reset_learner()
        learner1 = get_learner()
        learner2 = get_learner()
        assert learner1 is learner2

    def test_reset_learner_clears_instance(self, temp_db):
        """Test that reset_learner clears the instance."""
        learner1 = get_learner()
        reset_learner()
        learner2 = get_learner()
        assert learner1 is not learner2


class TestResetDatabaseClearsLearning:
    """Tests that database reset clears learning data."""

    def test_reset_clears_user_actions(self, temp_db):
        """Test that reset clears user actions."""
        db.log_user_action(UserAction("test.com", Action.KEEP, datetime.now()))
        assert db.get_action_count() == 1

        db.reset_database()
        assert db.get_action_count() == 0

    def test_reset_clears_preferences(self, temp_db):
        """Test that reset clears preferences."""
        db.set_user_preference(UserPreference("test", 0.5, 0.5, 1, datetime.now()))
        assert len(db.get_all_preferences()) == 1

        db.reset_database()
        assert len(db.get_all_preferences()) == 0
