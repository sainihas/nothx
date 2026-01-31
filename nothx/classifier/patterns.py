"""Layer 2: Preset pattern matching for classification."""

import json
from pathlib import Path
from typing import Optional

from ..models import SenderStats, Classification, Action, EmailType
from .utils import matches_pattern


# Default patterns shipped with nothx
DEFAULT_PATTERNS = {
    "unsub_patterns": [
        # Common marketing prefixes
        "marketing.*",
        "promo.*",
        "promotions.*",
        "newsletter.*",
        "news.*",
        "deals.*",
        "offers.*",
        "sales.*",
        "noreply.*",
        "no-reply.*",
        "donotreply.*",
        "updates.*",
        "info.*",
        "hello.*",
        "team.*",
        # Marketing domains
        "*.mailchimp.com",
        "*.sendgrid.net",
        "*.klaviyo.com",
        "*.sailthru.com",
        "*.exacttarget.com",
        "*.constantcontact.com",
        "*.campaign-archive.com",
    ],
    "keep_patterns": [
        # Government
        "*.gov",
        "*.gov.uk",
        "*.gov.au",
        # Banking and finance
        "*bank*",
        "*credit*",
        "*finance*",
        "*.visa.com",
        "*.mastercard.com",
        "*.paypal.com",
        "*.stripe.com",
        # Health
        "*health*",
        "*medical*",
        "*hospital*",
        "*clinic*",
        "*pharmacy*",
        # Important services
        "*.amazon.com",  # Transactional emails
        "*.apple.com",
        "*.google.com",
        "*.microsoft.com",
        "*.github.com",
        # Security
        "security.*",
        "alert.*",
        "alerts.*",
        "verify.*",
        "verification.*",
        "confirm.*",
        "confirmation.*",
        "receipt.*",
        "receipts.*",
        "order.*",
        "orders.*",
        "shipping.*",
        "delivery.*",
    ],
    "block_patterns": [
        # Known spam domains (examples)
        "*.spam.com",
        "*.junk.com",
    ]
}


class PatternMatcher:
    """Matches senders against preset patterns."""

    def __init__(self, patterns_file: Optional[Path] = None):
        self.patterns = self._load_patterns(patterns_file)

    def _load_patterns(self, patterns_file: Optional[Path]) -> dict:
        """Load patterns from file or use defaults."""
        if patterns_file and patterns_file.exists():
            with open(patterns_file) as f:
                return json.load(f)
        return DEFAULT_PATTERNS

    def match(self, sender: SenderStats) -> Optional[Classification]:
        """
        Check if sender matches any preset pattern.
        Returns Classification if match found, None otherwise.
        """
        domain = sender.domain.lower()

        # Check block patterns first (highest priority for presets)
        for pattern in self.patterns.get("block_patterns", []):
            if matches_pattern(domain, pattern):
                return Classification(
                    email_type=EmailType.MARKETING,
                    action=Action.BLOCK,
                    confidence=0.95,
                    reasoning=f"Matched block pattern: {pattern}",
                    source="preset",
                )

        # Check keep patterns
        for pattern in self.patterns.get("keep_patterns", []):
            if matches_pattern(domain, pattern):
                return Classification(
                    email_type=EmailType.TRANSACTIONAL,
                    action=Action.KEEP,
                    confidence=0.90,
                    reasoning=f"Matched keep pattern: {pattern}",
                    source="preset",
                )

        # Check unsub patterns
        for pattern in self.patterns.get("unsub_patterns", []):
            if matches_pattern(domain, pattern):
                return Classification(
                    email_type=EmailType.MARKETING,
                    action=Action.UNSUB,
                    confidence=0.85,
                    reasoning=f"Matched unsub pattern: {pattern}",
                    source="preset",
                )

        return None
