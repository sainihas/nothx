"""Layer 3: AI-powered classification using Anthropic Claude."""

import json
import logging
from typing import Any

from .. import db
from ..config import Config
from ..models import Action, Classification, EmailType, SenderStats

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
    """AI-powered email classification using Anthropic Claude."""

    def __init__(self, config: Config):
        self.config = config
        self._client: Any = None

    def _get_client(self):
        """Get or create Anthropic client."""
        if self._client is None:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self.config.ai.api_key)
        return self._client

    def is_available(self) -> bool:
        """Check if AI classification is available."""
        if not self.config.ai.enabled:
            return False
        if self.config.ai.provider != "anthropic":
            return False
        if not self.config.ai.api_key:
            return False
        return True

    def classify_batch(self, senders: list[SenderStats]) -> dict[str, Classification]:
        """
        Classify a batch of senders using AI.
        Returns a dictionary mapping domain -> Classification.
        """
        if not self.is_available():
            return {}

        if not senders:
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
            correction_context=correction_context, senders=json.dumps(sender_descriptions, indent=2)
        )

        # Call Claude API
        try:
            client = self._get_client()
            response = client.messages.create(
                model=self.config.ai.model,
                max_tokens=4096,
                messages=[{"role": "user", "content": prompt}],
            )

            # Parse response
            response_text = response.content[0].text
            classifications = self._parse_response(response_text)

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


def test_ai_connection(config: Config) -> tuple[bool, str]:
    """Test if AI connection works."""
    if not config.ai.api_key:
        return False, "No API key configured"

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=config.ai.api_key)
        client.messages.create(
            model=config.ai.model, max_tokens=10, messages=[{"role": "user", "content": "Say 'ok'"}]
        )
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)
