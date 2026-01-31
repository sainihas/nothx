"""Classification engine that orchestrates all layers."""

from typing import Optional

from ..config import Config
from ..models import SenderStats, Classification, Action, EmailType
from .rules import RulesMatcher
from .patterns import PatternMatcher
from .ai import AIClassifier
from .heuristics import HeuristicScorer


class ClassificationEngine:
    """
    Orchestrates the 5-layer classification system:
    1. User rules (highest priority)
    2. Preset patterns
    3. AI classification
    4. Heuristic scoring
    5. Review queue (fallback)
    """

    def __init__(self, config: Config):
        self.config = config
        self.rules = RulesMatcher()
        self.patterns = PatternMatcher()
        self.ai = AIClassifier(config)
        self.heuristics = HeuristicScorer()

    def classify(self, sender: SenderStats) -> Classification:
        """
        Classify a single sender through all layers.
        Returns the first confident classification or sends to review.
        """
        # Layer 1: User rules (highest priority)
        result = self.rules.match(sender)
        if result:
            return result

        # Layer 2: Preset patterns
        result = self.patterns.match(sender)
        if result:
            return result

        # Layer 3: AI classification (if enabled and configured)
        if self.ai.is_available():
            result = self.ai.classify_single(sender)
            if result and result.confidence >= self.config.thresholds.unsub_confidence:
                return result

        # Layer 4: Heuristic scoring (fallback)
        result = self.heuristics.classify(sender)
        if result:
            return result

        # Layer 5: Review queue (uncertain)
        return Classification(
            email_type=EmailType.UNKNOWN,
            action=Action.REVIEW,
            confidence=0.5,
            reasoning="Could not confidently classify - needs manual review",
            source="uncertain",
        )

    def classify_batch(
        self,
        senders: list[SenderStats]
    ) -> dict[str, Classification]:
        """
        Classify a batch of senders efficiently.
        Uses AI batch classification for better efficiency.
        """
        results: dict[str, Classification] = {}

        # Senders that need AI classification
        needs_ai: list[SenderStats] = []

        for sender in senders:
            # Layer 1: User rules
            result = self.rules.match(sender)
            if result:
                results[sender.domain] = result
                continue

            # Layer 2: Preset patterns
            result = self.patterns.match(sender)
            if result:
                results[sender.domain] = result
                continue

            # Collect for AI batch processing
            needs_ai.append(sender)

        # Layer 3: AI batch classification
        if needs_ai and self.ai.is_available():
            ai_results = self.ai.classify_batch(needs_ai)

            for sender in needs_ai:
                if sender.domain in ai_results:
                    result = ai_results[sender.domain]
                    if result.confidence >= self.config.thresholds.unsub_confidence:
                        results[sender.domain] = result
                        continue

                # Layer 4: Heuristic fallback
                heuristic_result = self.heuristics.classify(sender)
                if heuristic_result:
                    results[sender.domain] = heuristic_result
                else:
                    # Layer 5: Review queue
                    results[sender.domain] = Classification(
                        email_type=EmailType.UNKNOWN,
                        action=Action.REVIEW,
                        confidence=0.5,
                        reasoning="Could not confidently classify",
                        source="uncertain",
                    )
        else:
            # No AI available - use heuristics only
            for sender in needs_ai:
                result = self.heuristics.classify(sender)
                if result:
                    results[sender.domain] = result
                else:
                    results[sender.domain] = Classification(
                        email_type=EmailType.UNKNOWN,
                        action=Action.REVIEW,
                        confidence=0.5,
                        reasoning="Could not confidently classify",
                        source="uncertain",
                    )

        return results

    def should_auto_act(self, classification: Classification) -> bool:
        """Check if we should automatically act on this classification."""
        if self.config.operation_mode == "confirm":
            return False  # Always require confirmation

        if classification.action == Action.REVIEW:
            return False  # Never auto-act on uncertain

        if classification.action in (Action.UNSUB, Action.BLOCK):
            return classification.confidence >= self.config.thresholds.unsub_confidence

        if classification.action == Action.KEEP:
            return classification.confidence >= self.config.thresholds.keep_confidence

        return False
