"""Layer 2: Preset pattern matching for classification."""

import json
import logging
from importlib import resources
from pathlib import Path

from ..models import Action, Classification, EmailType, SenderStats
from .utils import matches_pattern

logger = logging.getLogger("nothx.classifier.patterns")

# Minimal in-code fallback used only if the packaged patterns.json can't be
# loaded (e.g. a broken wheel). The packaged JSON at data/patterns.json is the
# authoritative, fuller list (ESP domains, etc.).
FALLBACK_PATTERNS = {
    "unsub_patterns": [
        "marketing.*",
        "promo.*",
        "newsletter.*",
        "noreply.*",
        "no-reply.*",
        "*.mailchimp.com",
        "*.sendgrid.net",
        "*.amazonses.com",
    ],
    "keep_patterns": [
        "*.gov",
        "*bank*",
        "*health*",
        "security.*",
        "*.paypal.com",
    ],
    "block_patterns": [
        "*.spam.com",
        "*.junk.com",
    ],
}


def _load_packaged_patterns() -> dict:
    """Load the patterns JSON shipped inside the package."""
    try:
        with resources.files("nothx.classifier.data").joinpath("patterns.json").open() as f:
            return json.load(f)
    except (OSError, ValueError, ModuleNotFoundError) as e:
        logger.warning("Failed to load packaged patterns, using fallback: %s", e)
        return FALLBACK_PATTERNS


# Loaded once at import time; the packaged JSON is the single source of truth.
DEFAULT_PATTERNS = _load_packaged_patterns()


class PatternMatcher:
    """Matches senders against preset patterns."""

    def __init__(self, patterns_file: Path | None = None):
        self.patterns = self._load_patterns(patterns_file)

    def _load_patterns(self, patterns_file: Path | None) -> dict:
        """Load patterns from a user-provided file, or the packaged defaults."""
        if patterns_file and patterns_file.exists():
            with open(patterns_file) as f:
                return json.load(f)
        return DEFAULT_PATTERNS

    def match(self, sender: SenderStats) -> Classification | None:
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
