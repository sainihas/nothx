"""Parsing of Authentication-Results headers (RFC 8601).

Only the topmost Authentication-Results header whose authserv-id belongs to the
user's own mail provider is trusted; sender-forged instances further down are
ignored. Verdicts are tri-state (True=pass, False=fail, None=unknown/not
present) so downstream policy can distinguish "authentication failed" from
"we could not determine authentication".
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass

# authserv-id patterns per provider. A leading "." means case-insensitive
# suffix match; "" matches a header that has no authserv-id at all (Microsoft's
# non-compliant "spf=pass; dkim=pass" format). These should be validated
# against real message samples; the table is trivially extendable.
PROVIDER_AUTHSERV_IDS: dict[str, tuple[str, ...]] = {
    "gmail": ("mx.google.com",),
    "yahoo": (".yahoo.com", "yahoo.com"),
    "icloud": (".icloud.com", "icloud.com", ".apple.com", ".me.com"),
    "outlook": ("", "outlook.com", "hotmail.com", ".prod.outlook.com", ".protection.outlook.com"),
}

_FOLD_RE = re.compile(r"\r?\n[ \t]+")
_COMMENT_RE = re.compile(r"\([^()]*\)")
_METHOD_RE = re.compile(r"\s*(dkim|spf|dmarc)\s*=\s*([A-Za-z0-9_]+)", re.IGNORECASE)


@dataclass(frozen=True)
class AuthVerdicts:
    """SPF/DKIM/DMARC verdicts from a trusted Authentication-Results header."""

    dkim: bool | None = None
    spf: bool | None = None
    dmarc: bool | None = None


def _strip_comments(value: str) -> str:
    """Remove RFC 5322 comments, including nested parentheses."""
    prev = None
    while prev != value:
        prev = value
        value = _COMMENT_RE.sub(" ", value)
    return value


def _authserv_matches(authserv_id: str, patterns: tuple[str, ...]) -> bool:
    authserv_id = authserv_id.lower()
    for pattern in patterns:
        if pattern == "":
            if authserv_id == "":
                return True
        elif pattern.startswith("."):
            if authserv_id.endswith(pattern) or authserv_id == pattern[1:]:
                return True
        elif authserv_id == pattern:
            return True
    return False


def _result_to_bool(result: str) -> bool | None:
    result = result.lower()
    if result == "pass":
        return True
    if result == "fail":
        return False
    return None  # none, neutral, softfail, temperror, permerror, policy, ...


def parse_authentication_results(headers: Sequence[str], provider: str) -> AuthVerdicts:
    """Return SPF/DKIM/DMARC verdicts from the first trusted A-R header.

    Args:
        headers: All Authentication-Results header values on the message.
        provider: The account's provider key (gmail/outlook/yahoo/icloud/...).
    """
    patterns = PROVIDER_AUTHSERV_IDS.get(provider)
    if patterns is None:
        return AuthVerdicts()  # unknown provider: don't trust any instance

    for raw in headers:
        if not raw:
            continue
        unfolded = _FOLD_RE.sub(" ", raw)
        clean = _strip_comments(unfolded)
        segments = clean.split(";")
        if not segments:
            continue

        # authserv-id is the first whitespace token of the first segment.
        first_tokens = segments[0].split()
        # If that token contains '=', the header has no authserv-id (matches "").
        authserv_id = "" if (not first_tokens or "=" in first_tokens[0]) else first_tokens[0]

        if not _authserv_matches(authserv_id, patterns):
            continue

        dkim = spf = dmarc = None
        for segment in segments:
            m = _METHOD_RE.match(segment)
            if not m:
                continue
            method, result = m.group(1).lower(), m.group(2)
            verdict = _result_to_bool(result)
            if method == "dkim" and dkim is None:
                dkim = verdict
            elif method == "spf" and spf is None:
                spf = verdict
            elif method == "dmarc" and dmarc is None:
                dmarc = verdict
        return AuthVerdicts(dkim=dkim, spf=spf, dmarc=dmarc)

    return AuthVerdicts()
