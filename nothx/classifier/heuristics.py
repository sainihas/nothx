"""Layer 4: Heuristic-based scoring for classification."""

import re

from ..models import Action, Classification, EmailType, SenderStats
from .learner import get_learner

# Spam signal patterns
SPAM_SUBJECT_PATTERNS = [
    r"\b(sale|deals?|discount|off|free|limited|urgent|act now)\b",
    r"\d+%\s*(off|discount)",
    r"(exclusive|special)\s+offer",
    r"(last chance|final|ends? (today|soon|tonight))",
    r"(winner|won|prize|congratulations)",
    r"(click here|open now|don't miss)",
    r"^\s*re:\s*re:",  # Fake reply chains
    r"[A-Z]{5,}",  # Excessive caps
    r"[!?]{2,}",  # Excessive punctuation
]

SPAM_SENDER_PATTERNS = [
    r"^(marketing|promo|sales|deals|offers|newsletter|news|info|hello|team|noreply|no-reply|donotreply)@",
    r"^.*-(noreply|marketing|promo)@",
]

# Safe patterns (likely transactional)
SAFE_SUBJECT_PATTERNS = [
    r"(order|receipt|invoice|confirmation|shipping|delivery|tracking)",
    r"(password|verify|verification|security|2fa|two-factor|login)",
    r"(account|statement|billing|payment)",
    r"(welcome to|thanks for signing up)",
    r"#\d{5,}",  # Order numbers
]

SAFE_SENDER_PATTERNS = [
    r"^(security|alerts?|notifications?|receipts?|orders?|shipping|delivery|support|help|service)@",
    r"^(verify|verification|confirm|confirmation)@",
]

# Cold outreach patterns
COLD_OUTREACH_PATTERNS = [
    r"(quick question|following up|reaching out|touch base)",
    r"(i noticed|i saw|i found)",
    r"(your company|your team|your business)",
    r"(demo|call|meeting|chat|connect)",
]


class HeuristicScorer:
    """Scores senders using rule-based heuristics with learned preferences."""

    def __init__(self) -> None:
        """Initialize the scorer with access to the learner."""
        self._learner = get_learner()

    def score(self, sender: SenderStats) -> int:
        """
        Calculate a spam score for a sender (0-100).
        Higher score = more likely to be unwanted marketing.

        Now includes learned preference adjustments.
        """
        # Get learned preference adjustments
        adjustments = self._learner.get_preference_adjustments(sender)
        open_rate_weight = adjustments.get("open_rate_weight", 1.0)
        volume_weight = adjustments.get("volume_weight", 1.0)
        keyword_boost = adjustments.get("keyword_boost", 0)

        score = 50  # Start neutral

        # Apply keyword boost from learned patterns
        score += keyword_boost

        # Open rate scoring (now with learned weight)
        open_rate_adjustment = 0
        if sender.open_rate == 0 and sender.total_emails >= 5:
            open_rate_adjustment = 25  # Never opened = probably spam
        elif sender.open_rate < 10:
            open_rate_adjustment = 15
        elif sender.open_rate < 25:
            open_rate_adjustment = 5
        elif sender.open_rate > 75:
            open_rate_adjustment = -30  # Very high engagement = definitely keep
        elif sender.open_rate > 50:
            open_rate_adjustment = -20  # High engagement = keep

        # Apply learned open rate weight
        score += int(open_rate_adjustment * open_rate_weight)

        # Volume scoring (now with learned weight)
        volume_adjustment = 0
        if sender.total_emails > 50:
            volume_adjustment = 10
        elif sender.total_emails > 20:
            volume_adjustment = 5

        # Apply learned volume weight
        score += int(volume_adjustment * volume_weight)

        # Check subject patterns
        for subject in sender.sample_subjects:
            subject_lower = subject.lower()

            # Spam patterns
            for pattern in SPAM_SUBJECT_PATTERNS:
                if re.search(pattern, subject_lower, re.IGNORECASE):
                    score += 5
                    break

            # Safe patterns
            for pattern in SAFE_SUBJECT_PATTERNS:
                if re.search(pattern, subject_lower, re.IGNORECASE):
                    score -= 10
                    break

            # Cold outreach patterns
            for pattern in COLD_OUTREACH_PATTERNS:
                if re.search(pattern, subject_lower, re.IGNORECASE):
                    score += 15
                    break

        # Check sender domain patterns
        domain = sender.domain.lower()
        for pattern in SPAM_SENDER_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                score += 10
                break

        for pattern in SAFE_SENDER_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                score -= 15
                break

        # No unsubscribe link might mean it's important (or spam without proper headers)
        if not sender.has_unsubscribe:
            score -= 5  # Slightly favor keeping

        # Clamp to 0-100
        return max(0, min(100, score))

    def classify(self, sender: SenderStats) -> Classification | None:
        """
        Classify a sender based on heuristic score.
        Returns Classification if confident, None if uncertain.
        """
        score = self.score(sender)

        if score >= 75:
            # High spam score - likely marketing
            # Check for cold outreach specifically
            is_cold = self._is_cold_outreach(sender)

            return Classification(
                email_type=EmailType.COLD_OUTREACH if is_cold else EmailType.MARKETING,
                action=Action.BLOCK if is_cold else Action.UNSUB,
                confidence=min(score / 100, 0.90),
                reasoning=f"Heuristic score: {score}/100"
                + (" (cold outreach detected)" if is_cold else ""),
                source="heuristics",
            )

        elif score <= 25:
            # Low spam score - likely wanted
            return Classification(
                email_type=EmailType.TRANSACTIONAL,
                action=Action.KEEP,
                confidence=min((100 - score) / 100, 0.90),
                reasoning=f"Heuristic score: {score}/100 (low spam signals)",
                source="heuristics",
            )

        # Score between 25-75 is uncertain
        return None

    def _is_cold_outreach(self, sender: SenderStats) -> bool:
        """Check if sender appears to be cold sales outreach."""
        for subject in sender.sample_subjects:
            subject_lower = subject.lower()
            for pattern in COLD_OUTREACH_PATTERNS:
                if re.search(pattern, subject_lower, re.IGNORECASE):
                    return True
        return False
