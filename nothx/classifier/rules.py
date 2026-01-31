"""Layer 1: User-defined rules for classification."""

from typing import Optional

from ..models import SenderStats, Classification, Action, EmailType
from .. import db
from .utils import matches_pattern


class RulesMatcher:
    """Matches senders against user-defined rules."""

    def __init__(self):
        self._rules: Optional[list[dict]] = None

    def _load_rules(self) -> list[dict]:
        """Load rules from database."""
        if self._rules is None:
            self._rules = db.get_rules()
        return self._rules

    def reload(self) -> None:
        """Force reload of rules from database."""
        self._rules = None

    def match(self, sender: SenderStats) -> Optional[Classification]:
        """
        Check if sender matches any user rule.
        Returns Classification if match found, None otherwise.
        """
        rules = self._load_rules()

        for rule in rules:
            pattern = rule["pattern"].lower()
            action_str = rule["action"]

            # Validate action value
            try:
                action = Action(action_str)
            except ValueError:
                # Skip rules with invalid action values
                continue

            # Check if domain matches pattern
            if matches_pattern(sender.domain, pattern):
                return Classification(
                    email_type=EmailType.UNKNOWN,
                    action=action,
                    confidence=1.0,
                    reasoning=f"Matched user rule: {pattern}",
                    source="user_rule",
                )

        # Check if there's a user override in the sender record
        sender_record = db.get_sender(sender.domain)
        if sender_record and sender_record.get("user_override"):
            override_str = sender_record["user_override"]
            try:
                override_action = Action(override_str)
                return Classification(
                    email_type=EmailType.UNKNOWN,
                    action=override_action,
                    confidence=1.0,
                    reasoning="User override",
                    source="user_rule",
                )
            except ValueError:
                # Invalid override value, skip
                pass

        return None

    def add_rule(self, pattern: str, action: str) -> None:
        """Add a new rule."""
        if action not in ("keep", "unsub", "block"):
            raise ValueError(f"Invalid action: {action}")
        db.add_rule(pattern, action)
        self.reload()

    def remove_rule(self, pattern: str) -> bool:
        """Remove a rule."""
        result = db.delete_rule(pattern)
        self.reload()
        return result

    def get_rules(self) -> list[dict]:
        """Get all rules."""
        return self._load_rules()
