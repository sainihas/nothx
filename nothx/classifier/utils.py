"""Shared utilities for the classifier module."""

import fnmatch


def matches_pattern(value: str, pattern: str) -> bool:
    """
    Check if a value matches a pattern (supports wildcards).

    Supports patterns like:
    - "*.domain.com" - suffix match
    - "marketing.*" - prefix match (for subdomains like marketing.company.com)
    - "*bank*" - contains match
    - "exact.match.com" - exact match

    Args:
        value: The string to check (e.g., domain name)
        pattern: The pattern to match against

    Returns:
        True if the value matches the pattern
    """
    value = value.lower()
    pattern = pattern.lower()

    # Direct match
    if value == pattern:
        return True

    # Handle patterns like "marketing.*" (prefix match for subdomains)
    if pattern.endswith(".*"):
        prefix = pattern[:-2]
        # Check if value starts with prefix followed by a dot
        # e.g., "marketing.company.com" matches "marketing.*"
        if value.startswith(prefix + "."):
            return True
        return False

    # Handle patterns like "*.domain.com" (suffix match)
    if pattern.startswith("*."):
        suffix = pattern[1:]  # Keep the dot: ".domain.com"
        # Check if value ends with suffix or equals the base domain
        if value.endswith(suffix) or value == suffix[1:]:
            return True
        return False

    # Handle patterns with * in the middle or elsewhere (e.g., "*bank*")
    if "*" in pattern:
        return fnmatch.fnmatch(value, pattern)

    return False
