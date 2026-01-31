"""Layer 4: Heuristic-based scoring for classification."""

import re
from typing import Optional

from ..models import SenderStats, Classification, Action, EmailType


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
    """Scores senders using rule-based heuristics."""

    def score(self, sender: SenderStats) -> int:
        """
        Calculate a spam score for a sender (0-100).
        Higher score = more likely to be unwanted marketing.
        """
        score = 50  # Start neutral

        # Open rate is a strong signal
        if sender.open_rate == 0 and sender.total_emails >= 5:
            score += 25  # Never opened = probably spam
        elif sender.open_rate < 10:
            score += 15
        elif sender.open_rate < 25:
            score += 5
        elif sender.open_rate > 75:
            score -= 30  # Very high engagement = definitely keep
        elif sender.open_rate > 50:
            score -= 20  # High engagement = keep

        # High volume is a signal
        if sender.total_emails > 50:
            score += 10
        elif sender.total_emails > 20:
            score += 5

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

    def classify(self, sender: SenderStats) -> Optional[Classification]:
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
                reasoning=f"Heuristic score: {score}/100" + (" (cold outreach detected)" if is_cold else ""),
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
