"""Classification engine that orchestrates all layers."""

import fnmatch
import logging

from ..config import Config
from ..models import Action, Classification, EmailType, SenderStats
from .ai import AIClassifier
from .heuristics import (
    SAFE_SENDER_PATTERNS,
    SAFE_SUBJECT_PATTERNS,
    SPAM_SUBJECT_CASE_PATTERNS,
    SPAM_SUBJECT_PATTERNS,
    HeuristicScorer,
    has_strong_cold_outreach_evidence,
)
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

    def classify(self, sender: SenderStats, persist: bool = True) -> Classification:
        """
        Classify a single sender through all layers.
        Returns the first confident classification or sends to review.

        ``persist=False`` disables cloud AI egress and uses local fallbacks,
        matching :meth:`classify_batch`.
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
            return self._apply_action_policy(sender, result)

        # Provider threat verdicts are disposition evidence, not a score.
        result = self._threat_precheck(sender)
        if result:
            return result

        result = self._authentication_precheck(sender)
        if result:
            return result

        result = self._cold_outreach_precheck(sender)
        if result:
            return result

        result = self._transactional_precheck(sender)
        if result:
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
            return self._apply_action_policy(sender, result)

        # Layer 3: AI classification (if enabled and configured)
        ai_attempted = False
        ai_result = None
        if persist and self._is_ai_candidate(sender) and self.ai.is_available():
            ai_attempted = True
            ai_result = self.ai.classify_single(sender, persist=persist)
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
                return self._apply_action_policy(sender, ai_result)

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
            return self._apply_action_policy(sender, result)

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

    def _threat_precheck(self, sender: SenderStats) -> Classification | None:
        """Short-circuit provider-vetted junk/phishing without contacting it."""
        if sender.provider_threat or sender.phishing_emails:
            return Classification(
                email_type=EmailType.COLD_OUTREACH,
                action=Action.BLOCK,
                confidence=0.99,
                reasoning="Mailbox provider classified this subscription as junk/phishing",
                source="provider_policy",
            )
        if sender.not_junk_emails and (sender.junk_emails or sender.junk_keyword_emails):
            return Classification(
                email_type=EmailType.UNKNOWN,
                action=Action.REVIEW,
                confidence=0.5,
                reasoning="Mailbox has conflicting Junk and NotJunk verdicts",
                source="provider_policy",
            )
        if sender.junk_emails or sender.junk_keyword_emails:
            return Classification(
                email_type=EmailType.COLD_OUTREACH,
                action=Action.BLOCK,
                confidence=0.99,
                reasoning="Mailbox provider classified this subscription as junk",
                source="provider_policy",
            )
        return None

    def _authentication_precheck(self, sender: SenderStats) -> Classification | None:
        """Keep strong trusted authentication failures out of AI and link paths."""
        # A spoof or broken forward must not poison an otherwise authenticated
        # From-grouped subscription. Treat strong failures as subscription-wide
        # block evidence only when they outnumber authenticated deliveries.
        if sender.authentication_failed_emails > sender.authenticated_emails:
            return Classification(
                email_type=EmailType.UNKNOWN,
                action=Action.BLOCK,
                confidence=0.95,
                reasoning="Trusted authentication failures dominate authenticated deliveries",
                source="auth_policy",
            )
        if sender.authentication_failed_emails and sender.authenticated_emails:
            return Classification(
                email_type=EmailType.UNKNOWN,
                action=Action.REVIEW,
                confidence=0.5,
                reasoning=(
                    "Authentication evidence is mixed; a failed message cannot classify "
                    "the account/list identity"
                ),
                source="auth_policy",
            )
        if sender.authenticated_emails <= 0 and (
            sender.dkim_pass is False or sender.dmarc_pass is False
        ):
            return Classification(
                email_type=EmailType.UNKNOWN,
                action=Action.REVIEW,
                confidence=0.5,
                reasoning="Authentication failed or broke in transit; manual review is required",
                source="auth_policy",
            )
        return None

    def _cold_outreach_precheck(self, sender: SenderStats) -> Classification | None:
        """Resolve high-confidence cold outreach locally before any AI call."""
        result = self.heuristics.classify(sender)
        if (
            result
            and result.action is Action.BLOCK
            and result.email_type is EmailType.COLD_OUTREACH
        ):
            return result
        return None

    def _transactional_precheck(self, sender: SenderStats) -> Classification | None:
        """Keep strong transactional/security evidence local and non-destructive.

        A list/bulk header alone is not permission to send possibly sensitive
        transactional subjects to AI. Mixed promotional or outreach evidence
        remains eligible for normal classification; otherwise a matching safe
        sender plus consistently transactional subjects can be kept, and the
        less-certain cases remain review-only.
        """
        subjects = [subject for subject in sender.sample_subjects if subject.strip()]
        if not subjects:
            return None
        safe_subjects = [
            any(pattern.search(subject) for pattern in SAFE_SUBJECT_PATTERNS)
            for subject in subjects
        ]
        if not any(safe_subjects):
            return None
        has_risk_signal = any(
            any(pattern.search(subject) for pattern in SPAM_SUBJECT_PATTERNS)
            or any(pattern.search(subject) for pattern in SPAM_SUBJECT_CASE_PATTERNS)
            or has_strong_cold_outreach_evidence(subject)
            for subject in subjects
        )
        if has_risk_signal:
            return None

        security_words = ("password", "verify", "verification", "security", "2fa", "login")
        email_type = (
            EmailType.SECURITY
            if any(word in subject.casefold() for word in security_words for subject in subjects)
            else EmailType.TRANSACTIONAL
        )
        safe_sender = any(
            pattern.search(address)
            for address in sender.sample_senders
            for pattern in SAFE_SENDER_PATTERNS
        )
        if all(safe_subjects) and safe_sender and sender.authenticated_emails > 0:
            return Classification(
                email_type=email_type,
                action=Action.KEEP,
                confidence=0.95,
                reasoning="Consistent transactional/security subjects from a matching sender role",
                source="transactional_policy",
            )
        return Classification(
            email_type=email_type,
            action=Action.REVIEW,
            confidence=0.70,
            reasoning="Transactional/security content is protected from automatic unsubscribe",
            source="transactional_policy",
        )

    def _is_protected(self, domain: str) -> bool:
        value = domain.casefold()
        return any(
            fnmatch.fnmatch(value, pattern.casefold())
            for pattern in self.config.safety.never_unsub_domains
        )

    def _always_confirm(self, domain: str) -> bool:
        value = domain.casefold()
        return any(
            fnmatch.fnmatch(value, pattern.casefold())
            for pattern in self.config.safety.always_confirm_domains
        )

    def _is_ai_candidate(self, sender: SenderStats) -> bool:
        """Keep unrelated personal headers out of cloud classification calls."""
        return any(
            (
                sender.has_unsubscribe,
                bool(sender.list_id),
                sender.bulk_precedence,
                sender.auto_submitted,
                sender.has_feedback_id,
                bool(sender.esp_name),
                bool(sender.provider_bulk_emails),
                sender.provider_threat,
                bool(sender.junk_emails),
            )
        )

    def _apply_action_policy(
        self, sender: SenderStats, classification: Classification
    ) -> Classification:
        """Turn a content preference into a safe executable disposition."""
        if (
            classification.action is Action.BLOCK
            and classification.source != "user_rule"
            and sender.authenticated_emails <= 0
            and not sender.provider_threat
            and not sender.phishing_emails
            and not sender.junk_emails
            and not sender.junk_keyword_emails
        ):
            return Classification(
                email_type=classification.email_type,
                action=Action.REVIEW,
                confidence=classification.confidence,
                reasoning=f"{classification.reasoning}; authentication is unknown",
                source="auth_policy",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )
        if (
            classification.action is Action.KEEP
            and classification.source != "user_rule"
            and classification.email_type in (EmailType.TRANSACTIONAL, EmailType.SECURITY)
            and sender.authenticated_emails <= 0
        ):
            return Classification(
                email_type=classification.email_type,
                action=Action.REVIEW,
                confidence=classification.confidence,
                reasoning=f"{classification.reasoning}; authentication is unknown",
                source="auth_policy",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )
        if classification.action != Action.UNSUB:
            return classification
        if classification.email_type in (EmailType.TRANSACTIONAL, EmailType.SECURITY):
            return Classification(
                email_type=classification.email_type,
                action=Action.REVIEW,
                confidence=classification.confidence,
                reasoning=f"{classification.reasoning}; protected transactional/security mail",
                source="safety_policy",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )
        if self._is_protected(sender.domain) or self._always_confirm(sender.domain):
            return Classification(
                email_type=classification.email_type,
                action=Action.REVIEW,
                confidence=classification.confidence,
                reasoning=f"{classification.reasoning}; protected/confirmation-required sender",
                source="safety_policy",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )
        if sender.authenticated_emails <= 0 and not sender.can_unsubscribe_emails:
            return Classification(
                email_type=classification.email_type,
                action=Action.REVIEW,
                confidence=classification.confidence,
                reasoning=f"{classification.reasoning}; authentication is unknown",
                source="auth_policy",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )
        if not sender.has_unsubscribe:
            return Classification(
                email_type=classification.email_type,
                action=Action.BLOCK,
                confidence=classification.confidence,
                reasoning=f"{classification.reasoning}; no safe unsubscribe method, suppress locally",
                source="method_policy",
                recommended_action=classification.recommended_action or classification.action,
                original_source=classification.original_source or classification.source,
            )
        return classification

    def classify_batch(
        self, senders: list[SenderStats], persist: bool = True
    ) -> dict[str, Classification]:
        """
        Classify a batch of senders efficiently.
        Uses AI batch classification for better efficiency.

        When persist is False (dry-run or a pre-consent scan), cloud AI calls
        and classification writes are both disabled; candidates fall back to
        local heuristics.
        """
        results: dict[str, Classification] = {}

        # Track classification sources for metrics
        source_counts = {"user_rule": 0, "preset": 0, "ai": 0, "heuristics": 0, "uncertain": 0}
        fallback_count = 0

        # Senders that need AI classification
        needs_ai: list[SenderStats] = []
        local_only: list[SenderStats] = []

        for sender in senders:
            # Layer 1: User rules
            result = self.rules.match(sender)
            if result:
                results[sender.classification_key] = self._apply_action_policy(sender, result)
                source_counts["user_rule"] += 1
                continue

            result = self._threat_precheck(sender)
            if result:
                results[sender.classification_key] = result
                source_counts.setdefault("provider_policy", 0)
                source_counts["provider_policy"] += 1
                continue

            result = self._authentication_precheck(sender)
            if result:
                results[sender.classification_key] = result
                source_counts.setdefault("auth_policy", 0)
                source_counts["auth_policy"] += 1
                continue

            result = self._cold_outreach_precheck(sender)
            if result:
                results[sender.classification_key] = result
                source_counts["heuristics"] += 1
                continue

            result = self._transactional_precheck(sender)
            if result:
                results[sender.classification_key] = result
                source_counts.setdefault("transactional_policy", 0)
                source_counts["transactional_policy"] += 1
                continue

            # Layer 2: Preset patterns
            result = self.patterns.match(sender)
            if result:
                results[sender.classification_key] = self._apply_action_policy(sender, result)
                source_counts["preset"] += 1
                continue

            # Collect for AI batch processing
            if self._is_ai_candidate(sender):
                needs_ai.append(sender)
            else:
                local_only.append(sender)

        # Unrelated personal headers never leave the machine. They receive
        # deterministic local scoring only.
        for sender in local_only:
            local_result = self.heuristics.classify(sender)
            if local_result:
                results[sender.classification_key] = self._apply_action_policy(sender, local_result)
                source_counts["heuristics"] += 1
            else:
                results[sender.classification_key] = Classification(
                    email_type=EmailType.UNKNOWN,
                    action=Action.REVIEW,
                    confidence=0.5,
                    reasoning="Local policy could not confidently classify this sender",
                    source="uncertain",
                )
                source_counts["uncertain"] += 1

        # Layer 3: AI batch classification
        if needs_ai and persist and self.ai.is_available():
            ai_results = self.ai.classify_batch(needs_ai, persist=persist)

            ai_success_count = 0
            ai_low_confidence_count = 0

            for sender in needs_ai:
                if sender.classification_key in ai_results:
                    result = ai_results[sender.classification_key]
                    if result.confidence >= self.config.thresholds.unsub_confidence:
                        results[sender.classification_key] = self._apply_action_policy(
                            sender, result
                        )
                        source_counts["ai"] += 1
                        ai_success_count += 1
                        continue
                    else:
                        ai_low_confidence_count += 1

                # Layer 4: Heuristic fallback
                fallback_count += 1
                heuristic_result = self.heuristics.classify(sender)
                if heuristic_result:
                    results[sender.classification_key] = self._apply_action_policy(
                        sender, heuristic_result
                    )
                    source_counts["heuristics"] += 1
                else:
                    # Layer 5: Review queue
                    results[sender.classification_key] = Classification(
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
            # No AI available or egress is disabled - use heuristics only.
            if needs_ai:
                if persist:
                    logger.info(
                        "AI unavailable, using heuristics for %d senders",
                        len(needs_ai),
                        extra={"heuristic_only_count": len(needs_ai)},
                    )
                else:
                    logger.info(
                        "AI egress disabled, using local heuristics for %d senders",
                        len(needs_ai),
                        extra={"heuristic_only_count": len(needs_ai)},
                    )
            for sender in needs_ai:
                result = self.heuristics.classify(sender)
                if result:
                    results[sender.classification_key] = self._apply_action_policy(sender, result)
                    source_counts["heuristics"] += 1
                else:
                    results[sender.classification_key] = Classification(
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
