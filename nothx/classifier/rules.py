"""Layer 1: User-defined rules for classification."""

import logging

from .. import db
from ..models import Action, Classification, EmailType, SenderStats
from .utils import matches_pattern

logger = logging.getLogger("nothx.classifier.rules")


class RulesMatcher:
    """Matches senders against user-defined rules."""

    def __init__(self):
        self._rules: list[dict] | None = None

    def _load_rules(self) -> list[dict]:
        """Load rules from database."""
        if self._rules is None:
            self._rules = db.get_rules()
        return self._rules

    def reload(self) -> None:
        """Force reload of rules from database."""
        self._rules = None

    def match(self, sender: SenderStats) -> Classification | None:
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
                # Log invalid rules instead of silently skipping
                logger.warning(
                    "Skipping rule with invalid action: pattern='%s', action='%s'",
                    pattern,
                    action_str,
                    extra={
                        "pattern": pattern,
                        "invalid_action": action_str,
                        "valid_actions": [a.value for a in Action],
                    },
                )
                continue

            # Check if domain matches pattern
            if matches_pattern(sender.domain, pattern):
                logger.debug(
                    "Rule matched: %s -> %s (pattern: %s)",
                    sender.domain,
                    action.value,
                    pattern,
                    extra={
                        "domain": sender.domain,
                        "action": action.value,
                        "pattern": pattern,
                    },
                )
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
                logger.debug(
                    "User override applied: %s -> %s",
                    sender.domain,
                    override_action.value,
                    extra={"domain": sender.domain, "action": override_action.value},
                )
                return Classification(
                    email_type=EmailType.UNKNOWN,
                    action=override_action,
                    confidence=1.0,
                    reasoning="User override",
                    source="user_rule",
                )
            except ValueError:
                # Log invalid override instead of silently skipping
                logger.warning(
                    "Sender %s has invalid user_override value: '%s'",
                    sender.domain,
                    override_str,
                    extra={
                        "domain": sender.domain,
                        "invalid_override": override_str,
                        "valid_actions": [a.value for a in Action],
                    },
                )

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
