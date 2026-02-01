"""Layer 3: AI-powered classification using configurable providers."""

import json
import logging
from datetime import datetime
from typing import Any

from .. import db
from ..config import Config
from ..models import Action, Classification, EmailType, SenderStats, UserPreference
from .providers import get_provider, SUPPORTED_PROVIDERS
from .providers.base import BaseAIProvider

logger = logging.getLogger("nothx.classifier.ai")


CLASSIFICATION_PROMPT = """You are an email classification assistant. Your job is to analyze email senders and classify them to help users manage their inbox.

For each sender, you'll receive:
- Domain name
- Number of emails received
- Open rate (percentage of emails the user has read)
- Sample subject lines
- Whether they have a working unsubscribe link

Classify each sender into one of these types:
- marketing: Promotional emails, sales, deals, advertising
- transactional: Receipts, shipping notifications, order confirmations, account activity
- security: Password resets, 2FA codes, login alerts, security notifications
- newsletter: Content-focused newsletters the user subscribed to
- cold_outreach: Unsolicited sales emails, B2B cold outreach

Then recommend an action:
- keep: Important emails the user should continue receiving
- unsub: Marketing/promotional emails the user likely doesn't want
- block: Spam, cold outreach, or persistent unwanted senders
- review: Uncertain cases that need human decision

Consider these factors:
1. Open rate: Low open rate (<10%) suggests user doesn't value these emails
2. Subject patterns: "SALE", "% OFF", urgency words suggest marketing
3. Sender patterns: noreply@, marketing@, promo@ suggest promotional
4. Transactional signals: Order numbers, shipping info, receipts = keep
5. Security signals: Password, verify, confirm, 2FA = always keep

{correction_context}

Respond with a JSON array of classifications:
```json
[
  {{
    "domain": "example.com",
    "type": "marketing",
    "action": "unsub",
    "confidence": 0.92,
    "reasoning": "Low open rate (3%), promotional subject lines"
  }}
]
```

Here are the senders to classify:
{senders}
"""


class AIClassifier:
    """AI-powered email classification using configurable providers."""

    def __init__(self, config: Config):
        self.config = config
        self._provider: BaseAIProvider | None = None
        self._provider_initialized = False

    def _get_provider(self) -> BaseAIProvider | None:
        """Get or create the AI provider."""
        if not self._provider_initialized:
            self._provider = get_provider(
                provider_name=self.config.ai.provider,
                api_key=self.config.ai.api_key,
                model=self.config.ai.model,
                api_base=self.config.ai.api_base,
            )
            self._provider_initialized = True
        return self._provider

    def is_available(self) -> bool:
        """Check if AI classification is available."""
        if not self.config.ai.enabled:
            return False

        provider = self._get_provider()
        if provider is None:
            return False

        return provider.is_available()

    def classify_batch(self, senders: list[SenderStats]) -> dict[str, Classification]:
        """
        Classify a batch of senders using AI.
        Returns a dictionary mapping domain -> Classification.
        """
        if not self.is_available():
            return {}

        if not senders:
            return {}

        provider = self._get_provider()
        if provider is None:
            return {}

        # Build sender descriptions
        sender_descriptions = []
        for sender in senders:
            desc = {
                "domain": sender.domain,
                "total_emails": sender.total_emails,
                "open_rate": f"{sender.open_rate:.1f}%",
                "sample_subjects": sender.sample_subjects[:3],
                "has_unsubscribe": sender.has_unsubscribe,
            }
            sender_descriptions.append(desc)

        # Get correction context for learning
        correction_context = self._get_correction_context()

        # Build prompt
        prompt = CLASSIFICATION_PROMPT.format(
            correction_context=correction_context,
            senders=json.dumps(sender_descriptions, indent=2),
        )

        # Call provider
        try:
            response = provider.complete(prompt, max_tokens=4096)

            # Parse response
            classifications = self._parse_response(response.text)

            # Update database with AI classifications
            for domain, classification in classifications.items():
                db.update_sender_classification(
                    domain=domain,
                    classification=classification.email_type.value,
                    confidence=classification.confidence,
                )

            return classifications

        except Exception as e:
            # Log error but don't crash
            logger.error("AI classification error: %s", e)
            return {}

    def classify_single(self, sender: SenderStats) -> Classification | None:
        """Classify a single sender."""
        results = self.classify_batch([sender])
        return results.get(sender.domain)

    def _get_correction_context(self) -> str:
        """Get user corrections to include in prompt for learning."""
        corrections = db.get_recent_corrections(limit=20)
        if not corrections:
            return ""

        context_lines = ["User has made these corrections to previous AI decisions:"]
        for c in corrections:
            context_lines.append(
                f"- {c['domain']}: AI said '{c['ai_decision']}', user changed to '{c['user_decision']}'"
            )
        context_lines.append("\nLearn from these corrections and adjust your recommendations.")

        return "\n".join(context_lines)

    def _parse_response(self, response_text: str) -> dict[str, Classification]:
        """Parse AI response into Classification objects."""
        results: dict[str, Classification] = {}

        try:
            # Extract JSON from response
            json_start = response_text.find("[")
            json_end = response_text.rfind("]") + 1
            if json_start == -1 or json_end == 0:
                return results

            json_str = response_text[json_start:json_end]
            data = json.loads(json_str)

            for item in data:
                domain = item.get("domain", "").lower()
                if not domain:
                    continue

                # Parse email type
                type_str = item.get("type", "unknown").lower()
                try:
                    email_type = EmailType(type_str)
                except ValueError:
                    email_type = EmailType.UNKNOWN

                # Parse action
                action_str = item.get("action", "review").lower()
                try:
                    action = Action(action_str)
                except ValueError:
                    action = Action.REVIEW

                results[domain] = Classification(
                    email_type=email_type,
                    action=action,
                    confidence=float(item.get("confidence", 0.5)),
                    reasoning=item.get("reasoning", ""),
                    source="ai",
                )

        except json.JSONDecodeError:
            pass

        return results


PATTERN_ANALYSIS_PROMPT = """You are analyzing a user's email management decisions to identify their preferences.

Here are the user's recent decisions on email senders:
{actions}

Analyze these decisions and identify patterns. Look for:
1. Industry/category preferences (finance, tech, retail, etc.)
2. Content type preferences (newsletters vs promotions vs updates)
3. Engagement thresholds (open rates that correlate with decisions)
4. Domain keyword patterns (words in domains that predict keep/unsub)
5. Behavioral shifts (if recent decisions differ from older ones)

For each pattern you identify, assess:
- confidence: How strong is this pattern? (0.0-1.0)
- sample_count: How many examples support it?

Respond with a JSON object:
```json
{{
  "insights": [
    {{
      "type": "keyword",
      "pattern": "bank",
      "action": "keep",
      "confidence": 0.9,
      "reasoning": "User kept 4/4 senders with 'bank' in domain"
    }},
    {{
      "type": "open_rate",
      "threshold": 30,
      "action": "keep",
      "confidence": 0.7,
      "reasoning": "User tends to keep senders with >30% open rate"
    }},
    {{
      "type": "volume",
      "threshold": 50,
      "action": "unsub",
      "confidence": 0.6,
      "reasoning": "User unsubs from high-volume senders (>50 emails)"
    }},
    {{
      "type": "category",
      "pattern": "retail",
      "action": "unsub",
      "confidence": 0.8,
      "reasoning": "User tends to unsub from retail/shopping domains"
    }}
  ],
  "behavior_shift": {{
    "detected": false,
    "description": null
  }}
}}
```

Only include insights with confidence >= 0.5 and at least 3 supporting examples.
"""


class AIPatternAnalyzer:
    """AI-powered pattern analysis for learning user preferences."""

    def __init__(self, config: Config):
        self.config = config
        self._provider: BaseAIProvider | None = None
        self._provider_initialized = False

    def _get_provider(self) -> BaseAIProvider | None:
        """Get or create the AI provider."""
        if not self._provider_initialized:
            self._provider = get_provider(
                provider_name=self.config.ai.provider,
                api_key=self.config.ai.api_key,
                model=self.config.ai.model,
                api_base=self.config.ai.api_base,
            )
            self._provider_initialized = True
        return self._provider

    def is_available(self) -> bool:
        """Check if AI analysis is available."""
        if not self.config.ai.enabled:
            return False

        provider = self._get_provider()
        if provider is None:
            return False

        return provider.is_available()

    def analyze_patterns(self, min_actions: int = 10) -> dict | None:
        """Analyze user actions to find patterns.

        Args:
            min_actions: Minimum number of actions required for analysis

        Returns:
            Dict with insights and behavior_shift, or None if not enough data/AI unavailable
        """
        if not self.is_available():
            return None

        provider = self._get_provider()
        if provider is None:
            return None

        # Get recent user actions
        actions = db.get_user_actions(days=60, limit=100)

        if len(actions) < min_actions:
            logger.info(
                "Not enough actions for AI pattern analysis (%d < %d)",
                len(actions),
                min_actions,
            )
            return None

        # Build action descriptions
        action_descriptions = []
        for action in actions:
            desc = {
                "domain": action.domain,
                "action": action.action.value,
                "open_rate": f"{action.open_rate:.1f}%" if action.open_rate else "unknown",
                "email_count": action.email_count or 0,
                "timestamp": action.timestamp.strftime("%Y-%m-%d"),
            }
            action_descriptions.append(desc)

        # Build prompt
        prompt = PATTERN_ANALYSIS_PROMPT.format(
            actions=json.dumps(action_descriptions, indent=2)
        )

        try:
            response = provider.complete(prompt, max_tokens=2048)

            # Parse response
            return self._parse_analysis(response.text)

        except Exception as e:
            logger.error("AI pattern analysis error: %s", e)
            return None

    def _parse_analysis(self, response_text: str) -> dict | None:
        """Parse AI analysis response."""
        try:
            import re

            # Try to extract JSON from markdown code block first (more robust)
            match = re.search(r"```json\s*(\{.*?\})\s*```", response_text, re.DOTALL)
            if match:
                json_str = match.group(1)
            else:
                # Fallback for cases where the AI doesn't use markdown fences
                json_start = response_text.find("{")
                json_end = response_text.rfind("}") + 1
                if json_start == -1 or json_end == 0:
                    return None
                json_str = response_text[json_start:json_end]

            return json.loads(json_str)

        except json.JSONDecodeError:
            logger.error("Failed to parse AI analysis response")
            return None

    def apply_insights_to_preferences(self, analysis: dict) -> int:
        """Apply AI insights to user preferences.

        Args:
            analysis: The analysis dict from analyze_patterns()

        Returns:
            Number of preferences created/updated
        """
        if not analysis or "insights" not in analysis:
            return 0

        updated = 0
        now = datetime.now()

        for insight in analysis.get("insights", []):
            insight_type = insight.get("type")
            confidence = insight.get("confidence", 0)

            # Skip low-confidence insights
            if confidence < 0.5:
                continue

            # Get sample count from AI response, default to 3 (minimum required)
            sample_count = insight.get("sample_count", 3)

            if insight_type == "keyword":
                # Create/update keyword preference
                pattern = insight.get("pattern", "")
                action = insight.get("action", "")
                if pattern and action:
                    feature = f"keyword:{pattern}"
                    # Value is keep rate (1.0 for keep, 0.0 for unsub)
                    value = 1.0 if action == "keep" else 0.0

                    pref = UserPreference(
                        feature=feature,
                        value=value,
                        confidence=confidence,
                        sample_count=sample_count,
                        last_updated=now,
                        source="ai",
                    )
                    db.set_user_preference(pref)
                    updated += 1

            elif insight_type == "open_rate":
                # Update open rate weight based on threshold insight
                threshold = insight.get("threshold", 0)
                if threshold > 0:
                    # If AI detected a threshold pattern, adjust the weight
                    # Higher threshold = user cares less about open rate
                    weight = 1.0 - (threshold / 100) * 0.5  # Scale to 0.5-1.0

                    pref = UserPreference(
                        feature="open_rate_weight",
                        value=weight,
                        confidence=confidence,
                        sample_count=sample_count,
                        last_updated=now,
                        source="ai",
                    )
                    db.set_user_preference(pref)
                    updated += 1

            elif insight_type == "volume":
                # Update volume weight based on threshold insight
                threshold = insight.get("threshold", 0)
                action = insight.get("action", "")
                if threshold > 0 and action == "unsub":
                    # User is sensitive to volume
                    pref = UserPreference(
                        feature="volume_weight",
                        value=1.2,  # Increase volume importance
                        confidence=confidence,
                        sample_count=sample_count,
                        last_updated=now,
                        source="ai",
                    )
                    db.set_user_preference(pref)
                    updated += 1

            elif insight_type == "category":
                # Store category preference as keyword so it influences scoring
                pattern = insight.get("pattern", "")
                action = insight.get("action", "")
                if pattern and action:
                    feature = f"keyword:{pattern}"  # Use keyword: prefix for scoring
                    value = 1.0 if action == "keep" else 0.0

                    pref = UserPreference(
                        feature=feature,
                        value=value,
                        confidence=confidence,
                        sample_count=sample_count,
                        last_updated=now,
                        source="ai",
                    )
                    db.set_user_preference(pref)
                    updated += 1

        return updated


def test_ai_connection(config: Config) -> tuple[bool, str]:
    """Test if AI connection works with the configured provider."""
    if config.ai.provider == "none":
        return True, "AI disabled (heuristics only)"

    provider = get_provider(
        provider_name=config.ai.provider,
        api_key=config.ai.api_key,
        model=config.ai.model,
        api_base=config.ai.api_base,
    )

    if provider is None:
        return False, "No provider configured"

    return provider.test_connection()
