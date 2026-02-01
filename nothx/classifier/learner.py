"""Preference learning system that adapts to user behavior."""

import math
import re
import threading
from datetime import datetime

from .. import db
from ..models import Action, SenderStats, UserAction, UserPreference


class PreferenceLearner:
    """Learns and applies user preferences from their email decisions."""

    # Default weights (neutral starting point)
    DEFAULT_OPEN_RATE_WEIGHT = 1.0
    DEFAULT_VOLUME_WEIGHT = 1.0

    # Learning parameters
    RECENCY_HALF_LIFE_DAYS = 30  # Recent actions count more
    MIN_SAMPLES_FOR_CONFIDENCE = 3  # Need at least 3 examples to trust a pattern
    KEYWORD_CONFIDENCE_THRESHOLD = 0.7  # 70% consistency to create keyword preference

    # Domain parsing constants (class-level for performance)
    _TLDS = frozenset(
        {
            "com",
            "org",
            "net",
            "io",
            "co",
            "ai",
            "app",
            "dev",
            "edu",
            "gov",
            "mil",
            "us",
            "uk",
            "ca",
            "au",
            "de",
            "fr",
        }
    )
    _SKIP_PARTS = frozenset({"www", "mail", "email", "smtp", "mx"})

    def __init__(self) -> None:
        """Initialize the learner."""
        self._preference_cache: dict[str, UserPreference] | None = None

    def _invalidate_cache(self) -> None:
        """Invalidate the preference cache after updates."""
        self._preference_cache = None

    def _get_cached_preferences(self) -> dict[str, UserPreference]:
        """Get cached preferences, loading from DB if needed."""
        if self._preference_cache is None:
            prefs = db.get_all_preferences()
            self._preference_cache = {p.feature: p for p in prefs}
        return self._preference_cache

    def update_from_action(self, action: UserAction) -> None:
        """Update preference model after a user decision.

        This is the main learning entry point. Called after each user action
        to incrementally update learned preferences.
        """
        # Update keyword preferences based on domain
        self._update_keyword_preferences(action)

        # Update open rate correlation (does user care about open rates?)
        self._update_open_rate_preference(action)

        # Update volume preference (at what count does user unsub?)
        self._update_volume_preference(action)

        # Invalidate cache AFTER all DB operations complete
        self._invalidate_cache()

    def _update_keyword_preferences(self, action: UserAction) -> None:
        """Learn keyword associations from domain patterns."""
        keywords = self._extract_keywords(action.domain)

        for keyword in keywords:
            feature = f"keyword:{keyword}"
            existing = db.get_user_preference(feature)

            if existing:
                # Update existing preference with new data point
                # Value is the "keep rate" (1.0 = always keep, 0.0 = always unsub)
                new_value = 1.0 if action.action == Action.KEEP else 0.0
                weight = self._recency_weight(action.timestamp)

                # Weighted moving average
                total_weight = existing.sample_count + weight
                updated_value = (
                    existing.value * existing.sample_count + new_value * weight
                ) / total_weight

                updated_pref = UserPreference(
                    feature=feature,
                    value=updated_value,
                    confidence=self._calculate_confidence(existing.sample_count + 1),
                    sample_count=existing.sample_count + 1,
                    last_updated=datetime.now(),
                    source="learned",
                )
                db.set_user_preference(updated_pref)
            else:
                # Create new preference
                value = 1.0 if action.action == Action.KEEP else 0.0
                new_pref = UserPreference(
                    feature=feature,
                    value=value,
                    confidence=self._calculate_confidence(1),
                    sample_count=1,
                    last_updated=datetime.now(),
                    source="learned",
                )
                db.set_user_preference(new_pref)

    def _update_open_rate_preference(self, action: UserAction) -> None:
        """Learn how much open rate matters to the user.

        If user keeps low-open-rate senders, decrease weight.
        If user unsubs high-open-rate senders, decrease weight.
        """
        if action.open_rate is None:
            return

        feature = "open_rate_weight"
        existing = db.get_user_preference(feature)

        # Detect if user is going against open rate heuristics
        # Low open rate (<20%) + KEEP = user doesn't rely on open rate
        # High open rate (>50%) + UNSUB = user doesn't rely on open rate
        goes_against_open_rate = (action.open_rate < 20 and action.action == Action.KEEP) or (
            action.open_rate > 50 and action.action == Action.UNSUB
        )

        if existing:
            # Adjust weight based on whether user follows open rate logic
            adjustment = -0.05 if goes_against_open_rate else 0.02
            new_value = max(0.2, min(1.5, existing.value + adjustment))

            updated_pref = UserPreference(
                feature=feature,
                value=new_value,
                confidence=self._calculate_confidence(existing.sample_count + 1),
                sample_count=existing.sample_count + 1,
                last_updated=datetime.now(),
                source="learned",
            )
            db.set_user_preference(updated_pref)
        else:
            # Start with default, slight adjustment based on first action
            value = self.DEFAULT_OPEN_RATE_WEIGHT
            if goes_against_open_rate:
                value -= 0.05

            new_pref = UserPreference(
                feature=feature,
                value=value,
                confidence=self._calculate_confidence(1),
                sample_count=1,
                last_updated=datetime.now(),
                source="learned",
            )
            db.set_user_preference(new_pref)

    def _update_volume_preference(self, action: UserAction) -> None:
        """Learn user's volume tolerance.

        Track the email counts at which users tend to unsub.
        """
        if action.email_count is None:
            return

        feature = "volume_weight"
        existing = db.get_user_preference(feature)

        # High volume + KEEP = user tolerates high volume, decrease weight
        # Low volume + UNSUB = user is volume-sensitive, increase weight
        high_volume = action.email_count > 30
        low_volume = action.email_count < 10

        goes_against_volume = (high_volume and action.action == Action.KEEP) or (
            low_volume and action.action == Action.UNSUB
        )

        if existing:
            adjustment = -0.05 if goes_against_volume else 0.02
            new_value = max(0.2, min(1.5, existing.value + adjustment))

            updated_pref = UserPreference(
                feature=feature,
                value=new_value,
                confidence=self._calculate_confidence(existing.sample_count + 1),
                sample_count=existing.sample_count + 1,
                last_updated=datetime.now(),
                source="learned",
            )
            db.set_user_preference(updated_pref)
        else:
            value = self.DEFAULT_VOLUME_WEIGHT
            if goes_against_volume:
                value -= 0.05

            new_pref = UserPreference(
                feature=feature,
                value=value,
                confidence=self._calculate_confidence(1),
                sample_count=1,
                last_updated=datetime.now(),
                source="learned",
            )
            db.set_user_preference(new_pref)

    def get_preference_adjustments(self, sender: SenderStats) -> dict:
        """Get preference adjustments to apply to heuristic scoring.

        Returns a dict of adjustments that modify the base heuristic scoring:
        - open_rate_weight: Multiplier for open rate impact
        - volume_weight: Multiplier for volume impact
        - keyword_boost: Score adjustment based on domain keywords
        """
        preferences = self._get_cached_preferences()

        # Get weight adjustments
        open_rate_pref = preferences.get("open_rate_weight")
        volume_pref = preferences.get("volume_weight")

        adjustments = {
            "open_rate_weight": (
                open_rate_pref.value if open_rate_pref else self.DEFAULT_OPEN_RATE_WEIGHT
            ),
            "volume_weight": (volume_pref.value if volume_pref else self.DEFAULT_VOLUME_WEIGHT),
            "keyword_boost": self._get_keyword_boost(sender.domain, preferences),
        }

        return adjustments

    def _get_keyword_boost(self, domain: str, preferences: dict[str, UserPreference]) -> int:
        """Calculate score boost/penalty based on domain keywords."""
        keywords = self._extract_keywords(domain)
        total_boost = 0

        for keyword in keywords:
            feature = f"keyword:{keyword}"
            pref = preferences.get(feature)

            if (
                pref
                and pref.confidence >= 0.5
                and pref.sample_count >= self.MIN_SAMPLES_FOR_CONFIDENCE
            ):
                # Value is keep rate: 1.0 = always keep, 0.0 = always unsub
                # Convert to score adjustment: keep = negative (lower score), unsub = positive
                if pref.value > self.KEYWORD_CONFIDENCE_THRESHOLD:
                    # User tends to keep domains with this keyword
                    # Decrease spam score (make it more likely to keep)
                    total_boost -= int((pref.value - 0.5) * 20)
                elif pref.value < (1 - self.KEYWORD_CONFIDENCE_THRESHOLD):
                    # User tends to unsub domains with this keyword
                    # Increase spam score
                    total_boost += int((0.5 - pref.value) * 20)

        # Cap the boost to prevent extreme swings
        return max(-30, min(30, total_boost))

    def _extract_keywords(self, domain: str) -> list[str]:
        """Extract meaningful keywords from a domain.

        Examples:
        - 'marketing.example.com' -> ['marketing', 'example']
        - 'chase.bank.com' -> ['chase', 'bank']
        - 'news.ycombinator.com' -> ['news', 'ycombinator']
        """
        parts = re.split(r"[.\-_]", domain.lower())
        keywords = []

        for part in parts:
            # Skip TLDs, very short parts, and non-meaningful parts
            if part in self._TLDS or len(part) < 3 or part in self._SKIP_PARTS:
                continue
            keywords.append(part)

        return keywords

    def _recency_weight(self, timestamp: datetime) -> float:
        """Calculate recency weight using exponential decay."""
        days_ago = (datetime.now() - timestamp).days
        return math.exp(-days_ago / self.RECENCY_HALF_LIFE_DAYS)

    def _calculate_confidence(self, sample_count: int) -> float:
        """Calculate confidence based on sample count."""
        # Asymptotic approach to 1.0 as samples increase
        # 1 sample = ~0.33, 3 samples = ~0.6, 10 samples = ~0.91
        return 1 - math.exp(-sample_count / 3)

    def get_learning_summary(self) -> dict:
        """Get a summary of what has been learned.

        Returns insights about user preferences for display.
        """
        preferences = self._get_cached_preferences()
        stats = db.get_learning_stats()

        summary = {
            "total_actions": stats["total_actions"],
            "total_corrections": stats["total_corrections"],
            "open_rate_importance": "normal",
            "volume_sensitivity": "normal",
            "keyword_patterns": [],
        }

        # Interpret open rate weight
        open_rate_pref = preferences.get("open_rate_weight")
        if open_rate_pref:
            if open_rate_pref.value < 0.7:
                summary["open_rate_importance"] = "low"
            elif open_rate_pref.value > 1.2:
                summary["open_rate_importance"] = "high"

        # Interpret volume weight
        volume_pref = preferences.get("volume_weight")
        if volume_pref:
            if volume_pref.value < 0.7:
                summary["volume_sensitivity"] = "low"
            elif volume_pref.value > 1.2:
                summary["volume_sensitivity"] = "high"

        # Collect keyword patterns with enough confidence
        keyword_prefs = db.get_preferences_by_prefix("keyword:")
        for pref in keyword_prefs:
            if pref.confidence >= 0.5 and pref.sample_count >= self.MIN_SAMPLES_FOR_CONFIDENCE:
                keyword = pref.feature.replace("keyword:", "")
                tendency = "keep" if pref.value > 0.5 else "unsub"
                strength = "strongly" if abs(pref.value - 0.5) > 0.3 else "usually"
                summary["keyword_patterns"].append(
                    {
                        "keyword": keyword,
                        "tendency": tendency,
                        "strength": strength,
                        "sample_count": pref.sample_count,
                    }
                )

        return summary


# Global learner instance with thread-safe initialization
_learner: PreferenceLearner | None = None
_learner_lock = threading.Lock()


def get_learner() -> PreferenceLearner:
    """Get the global preference learner instance (thread-safe)."""
    global _learner
    if _learner is None:
        with _learner_lock:
            # Double-check after acquiring lock
            if _learner is None:
                _learner = PreferenceLearner()
    return _learner


def reset_learner() -> None:
    """Reset the global learner instance (for testing)."""
    global _learner
    with _learner_lock:
        _learner = None
