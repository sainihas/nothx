"""Classification engine that orchestrates all layers."""

import logging

from ..config import Config
from ..models import Action, Classification, EmailType, SenderStats
from .ai import AIClassifier
from .heuristics import HeuristicScorer
from .patterns import PatternMatcher
from .rules import RulesMatcher

logger = logging.getLogger("nothx.classifier.engine")


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
        self.heuristics = HeuristicScorer(
            scoring_config=config.scoring,
            threshold_config=config.thresholds,
        )

    def classify(self, sender: SenderStats) -> Classification:
        """
        Classify a single sender through all layers.
        Returns the first confident classification or sends to review.
        """
        # Layer 1: User rules (highest priority)
        result = self.rules.match(sender)
        if result:
            logger.debug(
                "Classified %s via user rule: %s",
                sender.domain,
                result.action.value,
                extra={
                    "domain": sender.domain,
                    "source": "user_rule",
                    "action": result.action.value,
                },
            )
            return result

        # Layer 2: Preset patterns
        result = self.patterns.match(sender)
        if result:
            logger.debug(
                "Classified %s via preset pattern: %s",
                sender.domain,
                result.action.value,
                extra={"domain": sender.domain, "source": "preset", "action": result.action.value},
            )
            return result

        # Layer 3: AI classification (if enabled and configured)
        ai_attempted = False
        ai_result = None
        if self.ai.is_available():
            ai_attempted = True
            ai_result = self.ai.classify_single(sender)
            if ai_result and ai_result.confidence >= self.config.thresholds.unsub_confidence:
                logger.debug(
                    "Classified %s via AI: %s (confidence: %.2f)",
                    sender.domain,
                    ai_result.action.value,
                    ai_result.confidence,
                    extra={
                        "domain": sender.domain,
                        "source": "ai",
                        "action": ai_result.action.value,
                        "confidence": ai_result.confidence,
                    },
                )
                return ai_result

        # Layer 4: Heuristic scoring (fallback)
        result = self.heuristics.classify(sender)
        if result:
            # Log fallback reason
            if ai_attempted:
                if ai_result is None:
                    fallback_reason = "AI returned no result"
                else:
                    fallback_reason = f"AI confidence too low ({ai_result.confidence:.2f} < {self.config.thresholds.unsub_confidence})"
                logger.info(
                    "Falling back to heuristics for %s: %s",
                    sender.domain,
                    fallback_reason,
                    extra={
                        "domain": sender.domain,
                        "fallback_reason": fallback_reason,
                        "ai_confidence": ai_result.confidence if ai_result else None,
                        "threshold": self.config.thresholds.unsub_confidence,
                    },
                )
            logger.debug(
                "Classified %s via heuristics: %s",
                sender.domain,
                result.action.value,
                extra={
                    "domain": sender.domain,
                    "source": "heuristics",
                    "action": result.action.value,
                },
            )
            return result

        # Layer 5: Review queue (uncertain)
        logger.info(
            "Sender %s sent to review queue (no confident classification)",
            sender.domain,
            extra={"domain": sender.domain, "source": "uncertain"},
        )
        return Classification(
            email_type=EmailType.UNKNOWN,
            action=Action.REVIEW,
            confidence=0.5,
            reasoning="Could not confidently classify - needs manual review",
            source="uncertain",
        )

    def classify_batch(self, senders: list[SenderStats]) -> dict[str, Classification]:
        """
        Classify a batch of senders efficiently.
        Uses AI batch classification for better efficiency.
        """
        results: dict[str, Classification] = {}

        # Track classification sources for metrics
        source_counts = {"user_rule": 0, "preset": 0, "ai": 0, "heuristics": 0, "uncertain": 0}
        fallback_count = 0

        # Senders that need AI classification
        needs_ai: list[SenderStats] = []

        for sender in senders:
            # Layer 1: User rules
            result = self.rules.match(sender)
            if result:
                results[sender.domain] = result
                source_counts["user_rule"] += 1
                continue

            # Layer 2: Preset patterns
            result = self.patterns.match(sender)
            if result:
                results[sender.domain] = result
                source_counts["preset"] += 1
                continue

            # Collect for AI batch processing
            needs_ai.append(sender)

        # Layer 3: AI batch classification
        if needs_ai and self.ai.is_available():
            ai_results = self.ai.classify_batch(needs_ai)

            ai_success_count = 0
            ai_low_confidence_count = 0

            for sender in needs_ai:
                if sender.domain in ai_results:
                    result = ai_results[sender.domain]
                    if result.confidence >= self.config.thresholds.unsub_confidence:
                        results[sender.domain] = result
                        source_counts["ai"] += 1
                        ai_success_count += 1
                        continue
                    else:
                        ai_low_confidence_count += 1

                # Layer 4: Heuristic fallback
                fallback_count += 1
                heuristic_result = self.heuristics.classify(sender)
                if heuristic_result:
                    results[sender.domain] = heuristic_result
                    source_counts["heuristics"] += 1
                else:
                    # Layer 5: Review queue
                    results[sender.domain] = Classification(
                        email_type=EmailType.UNKNOWN,
                        action=Action.REVIEW,
                        confidence=0.5,
                        reasoning="Could not confidently classify",
                        source="uncertain",
                    )
                    source_counts["uncertain"] += 1

            # Log AI classification summary
            if needs_ai:
                logger.info(
                    "AI batch classification: %d/%d successful, %d low confidence, %d fell back to heuristics",
                    ai_success_count,
                    len(needs_ai),
                    ai_low_confidence_count,
                    fallback_count,
                    extra={
                        "ai_requested": len(needs_ai),
                        "ai_success": ai_success_count,
                        "ai_low_confidence": ai_low_confidence_count,
                        "heuristic_fallback": fallback_count,
                        "confidence_threshold": self.config.thresholds.unsub_confidence,
                    },
                )
        else:
            # No AI available - use heuristics only
            if needs_ai:
                logger.info(
                    "AI unavailable, using heuristics for %d senders",
                    len(needs_ai),
                    extra={"heuristic_only_count": len(needs_ai)},
                )
            for sender in needs_ai:
                result = self.heuristics.classify(sender)
                if result:
                    results[sender.domain] = result
                    source_counts["heuristics"] += 1
                else:
                    results[sender.domain] = Classification(
                        email_type=EmailType.UNKNOWN,
                        action=Action.REVIEW,
                        confidence=0.5,
                        reasoning="Could not confidently classify",
                        source="uncertain",
                    )
                    source_counts["uncertain"] += 1

        # Log classification summary
        logger.info(
            "Batch classification complete: %d senders, sources: %s",
            len(senders),
            source_counts,
            extra={"total_senders": len(senders), "source_distribution": source_counts},
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
