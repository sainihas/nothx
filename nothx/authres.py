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

from .models import AuthenticationEvidence, AuthenticationResultEvidence, AuthResult

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
_METHOD_RE = re.compile(r"\s*(dkim|spf|dmarc|arc)\s*=\s*([A-Za-z0-9_]+)", re.IGNORECASE)
_PROPERTY_RE = re.compile(
    r"\b(header\.d|header\.s|header\.i|header\.from|smtp\.mailfrom)\s*=\s*([^\s;]+)",
    re.IGNORECASE,
)
_DKIM_TAG_RE = re.compile(r"(?:^|;)\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*([^;]*)")


def _normalize_domain(value: str | None) -> str | None:
    """Return a comparison-safe DNS domain, or None for invalid input."""
    if not value:
        return None
    candidate = value.strip().casefold().rstrip(".")
    if candidate.startswith("@"):
        candidate = candidate[1:]
    if not candidate or any(character.isspace() for character in candidate):
        return None
    try:
        normalized = candidate.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return None
    labels = normalized.split(".")
    if (
        len(normalized) > 253
        or len(labels) < 2
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )
    ):
        return None
    return normalized


def _dkim_domain_aligned(signing_domain: str | None, from_domain: str | None) -> bool:
    """Apply RFC 8058's same-domain-or-subdomain alignment requirement."""
    signing = _normalize_domain(signing_domain)
    sender = _normalize_domain(from_domain)
    return bool(signing and sender and (signing == sender or signing.endswith(f".{sender}")))


def has_aligned_dkim_pass(evidence: AuthenticationEvidence, from_domain: str | None) -> bool:
    """Return whether trusted results contain a From-aligned DKIM pass."""
    if not evidence.trusted or evidence.dkim is not AuthResult.PASS:
        return False
    passing_domains = {
        result.domain
        for result in evidence.results
        if result.method == "dkim" and result.result is AuthResult.PASS and result.domain
    }
    # ``dkim_domains`` contains only explicit header.d values from passing
    # results and keeps compatibility with callers constructing evidence
    # without the per-result tuple.
    passing_domains.update(evidence.dkim_domains)
    return any(_dkim_domain_aligned(domain, from_domain) for domain in passing_domains)


@dataclass(frozen=True)
class AuthVerdicts:
    """SPF/DKIM/DMARC verdicts from a trusted Authentication-Results header."""

    dkim: bool | None = None
    spf: bool | None = None
    dmarc: bool | None = None
    arc: bool | None = None
    evidence: AuthenticationEvidence = AuthenticationEvidence()


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


def _result_to_enum(result: str) -> AuthResult:
    try:
        return AuthResult(result.casefold())
    except ValueError:
        return AuthResult.UNKNOWN


def _aggregate_results(results: list[AuthResult]) -> AuthResult:
    """Prefer pass, otherwise preserve the strongest known failure/result."""
    if AuthResult.PASS in results:
        return AuthResult.PASS
    for candidate in (
        AuthResult.FAIL,
        AuthResult.PERMERROR,
        AuthResult.TEMPERROR,
        AuthResult.SOFTFAIL,
        AuthResult.NEUTRAL,
        AuthResult.POLICY,
        AuthResult.NONE,
    ):
        if candidate in results:
            return candidate
    return AuthResult.UNKNOWN


def _enum_to_bool(result: AuthResult) -> bool | None:
    if result is AuthResult.PASS:
        return True
    if result is AuthResult.FAIL:
        return False
    return None


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

        method_results: dict[str, list[AuthResult]] = {
            "dkim": [],
            "spf": [],
            "dmarc": [],
            "arc": [],
        }
        dkim_domains: list[str] = []
        dkim_selectors: list[str] = []
        aligned_results: list[AuthenticationResultEvidence] = []
        for segment in segments:
            m = _METHOD_RE.match(segment)
            if not m:
                continue
            method, result = m.group(1).lower(), m.group(2)
            verdict = _result_to_enum(result)
            method_results[method].append(verdict)
            props = {
                key.casefold(): value.strip('"').casefold()
                for key, value in _PROPERTY_RE.findall(segment)
            }
            identifier = None
            domain = None
            selector = None
            if method == "dkim":
                identifier = props.get("header.i")
                # Only header.d can be correlated exactly with a DKIM-Signature
                # d= tag. header.i is retained separately but must not stand in
                # for an omitted signing domain.
                domain = props.get("header.d")
                selector = props.get("header.s")
            elif method == "spf":
                identifier = props.get("smtp.mailfrom")
            elif method == "dmarc":
                identifier = props.get("header.from")
            aligned_results.append(
                AuthenticationResultEvidence(
                    method=method,
                    result=verdict,
                    identifier=identifier,
                    domain=domain,
                    selector=selector,
                )
            )
            if method == "dkim" and verdict is AuthResult.PASS:
                if domain := props.get("header.d"):
                    if domain not in dkim_domains:
                        dkim_domains.append(domain)
                if selector := props.get("header.s"):
                    if selector not in dkim_selectors:
                        dkim_selectors.append(selector)

        dkim_result = _aggregate_results(method_results["dkim"])
        spf_result = _aggregate_results(method_results["spf"])
        dmarc_result = _aggregate_results(method_results["dmarc"])
        arc_result = _aggregate_results(method_results["arc"])
        evidence = AuthenticationEvidence(
            spf=spf_result,
            dkim=dkim_result,
            dmarc=dmarc_result,
            arc=arc_result,
            dkim_domains=tuple(dkim_domains),
            dkim_selectors=tuple(dkim_selectors),
            results=tuple(aligned_results),
            trusted=True,
        )
        return AuthVerdicts(
            dkim=_enum_to_bool(dkim_result),
            spf=_enum_to_bool(spf_result),
            dmarc=_enum_to_bool(dmarc_result),
            arc=_enum_to_bool(arc_result),
            evidence=evidence,
        )

    return AuthVerdicts()


def dkim_covers_unsubscribe(
    signatures: Sequence[str],
    verdicts: AuthVerdicts,
    from_domain: str | None = None,
) -> bool:
    """Correlate a passing DKIM result with a signature covering both list headers.

    RFC 8058 requires both List-Unsubscribe fields in the h= tag and aligns the
    passing signing domain with From. When ``from_domain`` is omitted, alignment
    is skipped for API compatibility; automatic callers must always supply it.

    Correlation is deliberately fail-closed: Authentication-Results must expose
    both header.d and header.s, and exactly one raw signature may match that
    pair. This prevents a passing signature from being confused with a second,
    attacker-added signature using the same partial identity.
    """
    evidence = verdicts.evidence
    if not evidence.trusted or evidence.dkim is not AuthResult.PASS:
        return False
    passing_dkim = [
        result
        for result in evidence.results
        if result.method == "dkim" and result.result is AuthResult.PASS
    ]
    if not passing_dkim:
        return False

    parsed_signatures: list[dict[str, str]] = [
        {key.casefold(): value.strip() for key, value in _DKIM_TAG_RE.findall(raw or "")}
        for raw in signatures
    ]
    passing_pairs = {
        (domain, selector)
        for result in passing_dkim
        if (domain := _normalize_domain(result.domain))
        and (selector := (result.selector or "").strip().casefold())
        and (from_domain is None or _dkim_domain_aligned(domain, from_domain))
    }
    for domain, selector in passing_pairs:
        matches = [
            tags
            for tags in parsed_signatures
            if _normalize_domain(tags.get("d")) == domain
            and tags.get("s", "").strip().casefold() == selector
        ]
        if len(matches) != 1:
            continue
        covered = {name.strip().casefold() for name in matches[0].get("h", "").split(":")}
        if {"list-unsubscribe", "list-unsubscribe-post"}.issubset(covered):
            return True
    return False
