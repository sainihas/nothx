"""Layer 4: Heuristic-based scoring for classification."""

import logging
import re

from ..config import ScoringConfig, ThresholdConfig
from ..models import Action, Classification, EmailType, SenderStats
from .learner import get_learner

logger = logging.getLogger("nothx.classifier.heuristics")

# Spam signal patterns (raw strings for reference)
_SPAM_SUBJECT_PATTERNS_RAW = [
    r"\b(sale|deals?|discount|off|free|limited|urgent|act now)\b",
    r"\d+%\s*(off|discount)",
    r"(exclusive|special)\s+offer",
    r"(last chance|final|ends? (today|soon|tonight))",
    r"(winner|won|prize|congratulations)",
    r"(click here|open now|don't miss)",
    r"^\s*re:\s*re:",  # Fake reply chains
    r"[!?]{2,}",  # Excessive punctuation
]

# Case-sensitive spam signals: these depend on letter case, so they must be
# matched against the raw subject WITHOUT re.IGNORECASE (which would make
# "excessive caps" match any 5-letter word).
_SPAM_SUBJECT_CASE_PATTERNS_RAW = [
    r"[A-Z]{5,}",  # Excessive caps
]

_SPAM_SENDER_PATTERNS_RAW = [
    r"^(marketing|promo|sales|deals|offers|newsletter|news|info|hello|team|noreply|no-reply|donotreply)@",
    r"^.*-(noreply|marketing|promo)@",
]

# Safe patterns (likely transactional)
_SAFE_SUBJECT_PATTERNS_RAW = [
    r"(order|receipt|invoice|confirmation|shipping|delivery|tracking)",
    r"(password|verify|verification|security|2fa|two-factor|login)",
    r"(account|statement|billing|payment)",
    r"(welcome to|thanks for signing up)",
    r"#\d{5,}",  # Order numbers
]

_SAFE_SENDER_PATTERNS_RAW = [
    r"^(security|alerts?|notifications?|receipts?|orders?|shipping|delivery|support|help|service)@",
    r"^(verify|verification|confirm|confirmation)@",
]

# Cold outreach patterns
_COLD_OUTREACH_PATTERNS_RAW = [
    r"(quick question|following up|reaching out|touch base)",
    r"(i noticed|i saw|i found)",
    r"(your company|your team|your business)",
    r"(demo|call|meeting|chat|connect)",
]

# Pre-compiled patterns for performance
# Compiling at module load time avoids repeated compilation during scoring
SPAM_SUBJECT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _SPAM_SUBJECT_PATTERNS_RAW]
SPAM_SUBJECT_CASE_PATTERNS = [re.compile(p) for p in _SPAM_SUBJECT_CASE_PATTERNS_RAW]
SPAM_SENDER_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _SPAM_SENDER_PATTERNS_RAW]
SAFE_SUBJECT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _SAFE_SUBJECT_PATTERNS_RAW]
SAFE_SENDER_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _SAFE_SENDER_PATTERNS_RAW]
COLD_OUTREACH_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _COLD_OUTREACH_PATTERNS_RAW]


class HeuristicScorer:
    """Scores senders using rule-based heuristics with learned preferences."""

    def __init__(
        self,
        scoring_config: ScoringConfig | None = None,
        threshold_config: ThresholdConfig | None = None,
    ) -> None:
        """Initialize the scorer with access to the learner and config.

        Args:
            scoring_config: Scoring weights and adjustments. Uses defaults if None.
            threshold_config: Score thresholds. Uses defaults if None.
        """
        self._learner = get_learner()
        self._scoring = scoring_config or ScoringConfig()
        self._thresholds = threshold_config or ThresholdConfig()

    def score(self, sender: SenderStats) -> int:
        """
        Calculate a spam score for a sender (0-100).
        Higher score = more likely to be unwanted marketing.

        Now includes learned preference adjustments and uses configurable scoring weights.
        """
        cfg = self._scoring  # Shorthand for config

        # Get learned preference adjustments
        adjustments = self._learner.get_preference_adjustments(sender)
        open_rate_weight = adjustments.get("open_rate_weight", 1.0)
        volume_weight = adjustments.get("volume_weight", 1.0)
        keyword_boost = adjustments.get("keyword_boost", 0)

        # Start at base score (neutral)
        score = cfg.base_score

        # Apply keyword boost from learned patterns (capped by config)
        score += max(-cfg.keyword_boost_max, min(cfg.keyword_boost_max, keyword_boost))

        # Open rate scoring (now with learned weight)
        # Scale: 0% = spam signal, moderate = neutral, high = keep signal
        open_rate_adjustment = 0
        if sender.open_rate == 0 and sender.total_emails >= cfg.min_emails_for_never_opened:
            open_rate_adjustment = cfg.open_rate_never_opened  # Never opened = probably spam
        elif sender.open_rate < 10:
            open_rate_adjustment = cfg.open_rate_very_low  # Very low engagement
        elif sender.open_rate < 25:
            open_rate_adjustment = cfg.open_rate_low  # Low engagement
        elif sender.open_rate < 50:
            open_rate_adjustment = cfg.open_rate_moderate  # Moderate engagement
        elif sender.open_rate <= 75:
            open_rate_adjustment = cfg.open_rate_high  # High engagement = keep
        else:  # > 75%
            open_rate_adjustment = cfg.open_rate_very_high  # Very high engagement = definitely keep

        # Apply learned open rate weight
        score += int(open_rate_adjustment * open_rate_weight)

        # Volume scoring (now with learned weight)
        volume_adjustment = 0
        if sender.total_emails > 50:
            volume_adjustment = cfg.volume_high
        elif sender.total_emails > 20:
            volume_adjustment = cfg.volume_medium

        # Apply learned volume weight
        score += int(volume_adjustment * volume_weight)

        # Check subject patterns (using pre-compiled regex for performance).
        # Case-insensitive patterns match via re.IGNORECASE; the caps pattern
        # needs the raw subject, so nothing is lowercased here.
        for subject in sender.sample_subjects:
            # Spam patterns
            if any(p.search(subject) for p in SPAM_SUBJECT_PATTERNS) or any(
                p.search(subject) for p in SPAM_SUBJECT_CASE_PATTERNS
            ):
                score += cfg.subject_spam_pattern

            # Safe patterns
            if any(p.search(subject) for p in SAFE_SUBJECT_PATTERNS):
                score += cfg.subject_safe_pattern  # Negative value = decreases score

            # Cold outreach patterns
            if any(p.search(subject) for p in COLD_OUTREACH_PATTERNS):
                score += cfg.subject_cold_outreach

        # Check sender address patterns. These are local-part anchored
        # (e.g. "^marketing@"), so they must match full addresses, not the
        # bare domain (which never contains '@').
        addresses = [addr.lower() for addr in sender.sample_senders]
        if any(p.search(addr) for addr in addresses for p in SPAM_SENDER_PATTERNS):
            score += cfg.domain_spam_pattern

        if any(p.search(addr) for addr in addresses for p in SAFE_SENDER_PATTERNS):
            score += cfg.domain_safe_pattern  # Negative value = decreases score

        # No unsubscribe link might mean it's important (or spam without proper headers)
        if not sender.has_unsubscribe:
            score += cfg.no_unsubscribe_link  # Negative value = slightly favor keeping

        # Clamp to 0-100
        return max(0, min(100, score))

    def classify(self, sender: SenderStats) -> Classification | None:
        """
        Classify a sender based on heuristic score.
        Returns Classification if confident, None if uncertain.

        Score thresholds are configurable via ThresholdConfig:
        - score >= unsub_score_threshold (default 75) = unsub/block
        - score <= keep_score_threshold (default 25) = keep
        - Scores in between are uncertain
        """
        score = self.score(sender)
        unsub_threshold = self._thresholds.unsub_score_threshold
        keep_threshold = self._thresholds.keep_score_threshold

        if score >= unsub_threshold:
            # High spam score - likely marketing
            # Check for cold outreach specifically
            is_cold = self._is_cold_outreach(sender)

            # Anchor confidence at the auto-act threshold: a score that
            # clears the score threshold must also clear unsub_confidence,
            # otherwise scores 75-79 produce classifications nothing acts on.
            confidence = min(
                0.95,
                self._thresholds.unsub_confidence + (score - unsub_threshold) / 100,
            )
            classification = Classification(
                email_type=EmailType.COLD_OUTREACH if is_cold else EmailType.MARKETING,
                action=Action.BLOCK if is_cold else Action.UNSUB,
                confidence=confidence,
                reasoning=f"Heuristic score: {score}/100 (threshold: {unsub_threshold})"
                + (" (cold outreach detected)" if is_cold else ""),
                source="heuristics",
            )
            logger.debug(
                "Heuristics classified %s as %s (score: %d >= %d)",
                sender.domain,
                classification.action.value,
                score,
                unsub_threshold,
                extra={
                    "domain": sender.domain,
                    "score": score,
                    "threshold": unsub_threshold,
                    "action": classification.action.value,
                },
            )
            return classification

        elif score <= keep_threshold:
            # Low spam score - likely wanted
            confidence = min(
                0.95,
                self._thresholds.keep_confidence + (keep_threshold - score) / 100,
            )
            classification = Classification(
                email_type=EmailType.TRANSACTIONAL,
                action=Action.KEEP,
                confidence=confidence,
                reasoning=f"Heuristic score: {score}/100 (threshold: {keep_threshold})",
                source="heuristics",
            )
            logger.debug(
                "Heuristics classified %s as keep (score: %d <= %d)",
                sender.domain,
                score,
                keep_threshold,
                extra={
                    "domain": sender.domain,
                    "score": score,
                    "threshold": keep_threshold,
                    "action": "keep",
                },
            )
            return classification

        # Score between thresholds is uncertain
        logger.debug(
            "Heuristics uncertain for %s (score: %d, range: %d-%d)",
            sender.domain,
            score,
            keep_threshold,
            unsub_threshold,
            extra={
                "domain": sender.domain,
                "score": score,
                "keep_threshold": keep_threshold,
                "unsub_threshold": unsub_threshold,
            },
        )
        return None

    def _is_cold_outreach(self, sender: SenderStats) -> bool:
        """Check if sender appears to be cold sales outreach."""
        for subject in sender.sample_subjects:
            subject_lower = subject.lower()
            for pattern in COLD_OUTREACH_PATTERNS:
                if pattern.search(subject_lower):
                    return True
        return False
