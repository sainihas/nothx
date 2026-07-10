"""Unsubscribe execution for nothx."""

import email.utils
import fnmatch
import hashlib
import logging
import re
import smtplib
import ssl
import time
import urllib.error
import urllib.parse
from datetime import UTC, datetime
from email.mime.text import MIMEText

from . import __version__, db, msauth
from .authres import has_aligned_dkim_pass
from .config import CURRENT_UNSUBSCRIBE_CONSENT_VERSION, AccountConfig, Config
from .errors import RateLimiter
from .models import (
    AuthResult,
    EmailHeader,
    MessageRef,
    SenderStatus,
    UnsubMethod,
    UnsubResult,
    UnsubscribeAttemptResult,
    UnsubscribeOutcome,
)
from .safefetch import SSRFBlockedError, redacted_host, redacted_url, safe_fetch


class UnsafeUnsubscribeError(Exception):
    """Raised when attempting to unsubscribe from a protected domain."""

    pass


class InvalidProviderError(Exception):
    """Raised when an invalid email provider is specified."""

    pass


logger = logging.getLogger("nothx.unsubscriber")

# User agent for HTTP requests - identifies as nothx email automation tool
USER_AGENT = (
    f"nothx/{__version__} (Email Unsubscribe Automation; +https://github.com/sainihas/nothx)"
)

# Timeout for HTTP requests
REQUEST_TIMEOUT = 30
MAX_UNSUB_URI = 4096
MAX_MAILTO_SUBJECT = 998
MAX_MAILTO_BODY = 16_384
AUTOMATION_CONSENT_VERSION = CURRENT_UNSUBSCRIBE_CONSENT_VERSION
MAX_MESSAGE_PLANS = 3
MAX_TARGET_ATTEMPTS = 5
MAX_RETRY_AFTER = 60.0
SMTP_PRE_SEND_ATTEMPTS = 3

# Rate limiter for HTTP unsubscribe requests
# Default: 2 requests per second, burst of 5
# This prevents overwhelming mail servers and getting blocked
_http_rate_limiter = RateLimiter(requests_per_second=2.0, burst_size=5)


def _redact_target(target: str) -> str:
    """Return a useful destination without recipient or opaque URL tokens."""
    try:
        parsed = urllib.parse.urlsplit(target)
        scheme = parsed.scheme.casefold()
        if scheme == "mailto":
            address = _strict_unquote(parsed.path)
            domain = address.rsplit("@", 1)[-1] if "@" in address else ""
            host = redacted_host(domain)
            return f"mailto:*@{host}"
        return redacted_url(target)
    except (UnicodeError, ValueError):
        return "invalid target"


# RFC 8058: the List-Unsubscribe-Post header value must be exactly this pair.
ONE_CLICK_POST_VALUE = "list-unsubscribe=one-click"
_STRICT_ONE_CLICK_RE = re.compile(r"^\s*<(https://[^<>\s]+)>\s*$", re.IGNORECASE)
_BAD_PERCENT_RE = re.compile(r"%(?![0-9a-fA-F]{2})")
_LOCAL_ATOM_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$")
_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _is_protected_domain(domain: str, safety_config) -> bool:
    """Check if a domain matches any protected pattern."""
    domain_lower = domain.lower()
    for pattern in safety_config.never_unsub_domains:
        pattern_lower = pattern.lower()
        if fnmatch.fnmatch(domain_lower, pattern_lower):
            return True
    return False


def _has_one_click(email_header: EmailHeader) -> bool:
    """True if the message advertises RFC 8058 one-click unsubscribe."""
    post_value = email_header.list_unsubscribe_post
    if not post_value:
        return False
    return post_value.strip().lower() == ONE_CLICK_POST_VALUE


def contact_suppression_reason(email_header: EmailHeader) -> str | None:
    """Return why contacting a message's sender-controlled target is unsafe.

    This guard is shared by automatic, legacy-manual, and browser-opening
    paths.  It intentionally considers only evidence that must suppress all
    contact; current versioned consent is checked separately by callers so a
    provider threat verdict can retain the stronger ``blocked`` outcome.
    """
    if email_header.server_junk or email_header.server_phishing:
        return "Provider marked this mail as junk or phishing; use mailbox blocking"
    if (
        email_header.dkim_pass is False
        or email_header.dmarc_pass is False
        or email_header.strongly_failed_authentication
    ):
        return "Sender failed authentication (DKIM/DMARC); consider blocking instead"
    return None


def is_contact_permitted(email_header: EmailHeader, config: Config) -> bool:
    """Return whether safety evidence and current consent allow sender contact."""
    return config.permits_unsubscribe and contact_suppression_reason(email_header) is None


def _contact_denied_result(email_header: EmailHeader, config: Config) -> UnsubResult | None:
    """Build a no-contact grouped result when policy forbids execution."""
    reason = contact_suppression_reason(email_header)
    if reason is not None:
        outcome = (
            UnsubscribeOutcome.BLOCKED
            if email_header.server_junk or email_header.server_phishing
            else UnsubscribeOutcome.NEEDS_USER
        )
        return _grouped_result(
            outcome,
            reason,
            needs_confirmation=outcome is UnsubscribeOutcome.NEEDS_USER,
        )
    if not config.permits_unsubscribe:
        return _grouped_result(
            UnsubscribeOutcome.NEEDS_USER,
            "Current versioned unsubscribe-contact consent is required",
            needs_confirmation=True,
        )
    return None


def unsubscribe(
    email_header: EmailHeader, config: Config, account: AccountConfig | None = None
) -> UnsubResult:
    """
    Attempt to unsubscribe from a sender.

    Method order: RFC 8058 one-click POST (when properly advertised), then
    mailto, then plain GET on remaining http(s) targets. One-click and mailto
    are the sanctioned paths; GET links are the risky ones (tracking,
    confirmation pages), so they come last. Every attempt is logged; the
    sender status is updated once based on the overall outcome.

    Raises:
        UnsafeUnsubscribeError: If the domain matches a protected pattern.
    """
    # Safety check: Never unsubscribe from protected domains
    if _is_protected_domain(email_header.domain, config.safety):
        raise UnsafeUnsubscribeError(
            f"Cannot unsubscribe from protected domain: {email_header.domain}. "
            "This domain matches a pattern in your safety configuration."
        )

    domain = email_header.domain

    denied = _contact_denied_result(email_header, config)
    if denied is not None:
        logger.warning("Contact policy suppressed unsubscribe for %s", domain)
        return denied
    targets = email_header.list_unsubscribe_targets
    http_targets = [t for t in targets if t.lower().startswith(("https://", "http://"))]
    mailto_targets = [t for t in targets if t.lower().startswith("mailto:")]

    attempts: list[UnsubResult] = []
    one_click_url: str | None = None

    # Method 1: RFC 8058 one-click POST (only when properly advertised)
    if _has_one_click(email_header) and http_targets:
        one_click_url = http_targets[0]
        result = _execute_one_click(one_click_url)
        attempts.append(result)
        if result.success:
            return _finish(domain, attempts, result)

    # Method 2: Mailto (requires SMTP account)
    for mailto in mailto_targets:
        if not account:
            logger.debug("No account available for mailto unsubscribe to %s", domain)
            break
        result = _execute_mailto(mailto, account, config)
        attempts.append(result)
        if result.success:
            return _finish(domain, attempts, result)

    # Method 3: HTTPS GET, last resort. Never against the one-click URL:
    # that endpoint is defined for POST, and a GET typically lands on a
    # tracking or confirmation page.
    for url in http_targets:
        if url == one_click_url:
            continue
        result = _execute_get(url)
        attempts.append(result)
        if result.success:
            return _finish(domain, attempts, result)

    if attempts:
        # All methods failed; report the last attempt's detail.
        return _finish(domain, attempts, attempts[-1])

    result = UnsubResult(success=False, method=None, error="No unsubscribe method available")
    return _finish(domain, [result], result)


def unsubscribe_subscription(
    email_headers: list[EmailHeader],
    config: Config,
    account: AccountConfig | None = None,
    *,
    automatic: bool = True,
    exclude_fingerprints: set[str] | None = None,
) -> UnsubResult:
    """Execute a bounded account/list-level unsubscribe plan.

    Source URLs are reconstructed from recent messages and remain in memory.
    The result exposes only a redacted destination and grouped outcome.
    """
    if not email_headers:
        return _grouped_result(
            UnsubscribeOutcome.FAILED,
            "No recent source message is available",
        )

    ordered = sorted(email_headers, key=_message_date_key, reverse=True)

    # Threat verdicts always win, including for identities covered by a
    # protected-domain rule. Spam must not receive unsubscribe traffic.
    threat_denial = next(
        (
            denied
            for header in ordered
            if (denied := _contact_denied_result(header, config)) is not None
            and denied.outcome is UnsubscribeOutcome.BLOCKED
        ),
        None,
    )
    if threat_denial is not None:
        return threat_denial

    # An explicit authentication failure also forbids every outbound method,
    # even when the server advertised $canunsubscribe for the message.
    auth_denial = next(
        (
            denied
            for header in ordered
            if contact_suppression_reason(header) is not None
            and (denied := _contact_denied_result(header, config)) is not None
        ),
        None,
    )
    if auth_denial is not None:
        return auth_denial

    protected = any(
        _header_matches_patterns(header, config.safety.never_unsub_domains) for header in ordered
    )
    always_confirm = any(
        _header_matches_patterns(header, config.safety.always_confirm_domains) for header in ordered
    )
    if automatic and (protected or always_confirm):
        return _grouped_result(
            UnsubscribeOutcome.NEEDS_USER,
            "This subscription requires explicit review before contacting it",
            needs_confirmation=True,
        )

    if not config.permits_unsubscribe:
        return _grouped_result(
            UnsubscribeOutcome.NEEDS_USER,
            "Current versioned unsubscribe-contact consent is required",
            needs_confirmation=True,
        )

    plans = ordered[:MAX_MESSAGE_PLANS]
    one_click: list[tuple[UnsubMethod, str, MessageRef | None]] = []
    header_methods: list[tuple[UnsubMethod, str, MessageRef | None]] = []
    footer_methods: list[tuple[UnsubMethod, str, MessageRef | None]] = []
    declared_one_click: set[bytes] = set()
    deferred_for_auth = False
    footer_requires_user = automatic and any(item.footer_requires_user for item in plans)

    # Tier 1: newest compliant RFC 8058 source messages.
    for header in plans:
        target = _strict_one_click_target(header)
        if target is None:
            continue
        declared_one_click.add(_endpoint_fingerprint(target))
        evidence_ok = header.server_can_unsubscribe or (
            header.dkim_covers_unsubscribe
            and has_aligned_dkim_pass(header.authentication, header.domain)
        )
        if evidence_ok or not automatic:
            one_click.append((UnsubMethod.ONE_CLICK, target, header.message_ref))
        else:
            deferred_for_auth = True

    # Tier 2: remaining header methods, preserving advertised order within
    # each message and preferring newer source messages.
    for header in plans:
        authenticated = _trusted_unsubscribe_auth(header)
        for target in header.list_unsubscribe_targets:
            if _endpoint_fingerprint(target) in declared_one_click:
                # A one-click endpoint is defined for POST; never downgrade it.
                continue
            method = _safe_legacy_method(target)
            if method is None:
                continue
            if automatic and not authenticated:
                deferred_for_auth = True
                continue
            header_methods.append((method, target, header.message_ref))

    # Tier 3: local footer candidates. Footer URLs are never POST targets.
    for header in plans:
        if automatic and header.footer_requires_user:
            # A form/interactive flow on this source message makes its footer
            # endpoints manual-only. Safe header methods above remain usable.
            continue
        authenticated = _trusted_unsubscribe_auth(header)
        for footer in header.footer_unsubscribe_candidates:
            method = _safe_legacy_method(footer.uri)
            if method is None:
                continue
            if automatic and not authenticated:
                deferred_for_auth = True
                continue
            footer_methods.append((method, footer.uri, header.message_ref))

    candidates, skipped = _dedupe_endpoints(
        (*one_click, *header_methods, *footer_methods),
        exclude_fingerprints or set(),
    )
    attempts = 0
    last: UnsubResult | None = None
    needs_user: UnsubResult | None = None
    attempt_results: list[UnsubscribeAttemptResult] = list(skipped)

    for method, target, message_ref in candidates:
        attempts += 1
        if method is UnsubMethod.ONE_CLICK:
            result = _execute_one_click(target)
        elif method is UnsubMethod.MAILTO:
            if account is None:
                result = UnsubResult(
                    success=False,
                    method=method,
                    error="The matching SMTP account is unavailable",
                    needs_confirmation=True,
                )
                _mark_attempt(result, "needs_user", "smtp_account_missing")
            else:
                result = _execute_mailto(target, account, config)
        else:
            result = _execute_get(target)

        # Only redacted metadata crosses the executor boundary.
        result.target_display = _redact_target(target)
        result.response_snippet = None
        result.attempts = attempts
        attempt_results.append(_persistable_attempt(result, target, message_ref))
        result.attempt_results = tuple(attempt_results)
        last = result
        if bool(getattr(result, "_ambiguous_send", False)):
            # DATA may already have been accepted. Do not contact a fallback
            # endpoint and risk issuing the same unsubscribe twice.
            result.outcome = UnsubscribeOutcome.NEEDS_USER
            return result
        if result.success:
            result.outcome = UnsubscribeOutcome.REQUESTED
            return result
        if result.attempt_results[-1].ambiguous_send:
            result.outcome = UnsubscribeOutcome.NEEDS_USER
            result.needs_confirmation = True
            return result
        if result.needs_confirmation:
            result.outcome = UnsubscribeOutcome.NEEDS_USER
            needs_user = result

    if needs_user is not None:
        needs_user.attempts = attempts
        needs_user.attempt_results = tuple(attempt_results)
        return needs_user
    if not candidates and deferred_for_auth:
        result = _grouped_result(
            UnsubscribeOutcome.NEEDS_USER,
            "Authentication is unknown or insufficient; manual review is required",
            needs_confirmation=True,
        )
        result.attempt_results = tuple(attempt_results)
        return result
    if not candidates and skipped:
        result = _grouped_result(
            UnsubscribeOutcome.NEEDS_USER,
            "No fresh unsubscribe endpoint is available",
            needs_confirmation=True,
        )
        result.attempt_results = tuple(attempt_results)
        return result
    if last is not None:
        last.outcome = UnsubscribeOutcome.FAILED
        last.attempts = attempts
        last.attempt_results = tuple(attempt_results)
        return last
    if footer_requires_user:
        result = _grouped_result(
            UnsubscribeOutcome.NEEDS_USER,
            "The footer requires interactive user action",
            needs_confirmation=True,
        )
        result.attempts = attempts
        result.attempt_results = tuple(attempt_results)
        return result
    return _grouped_result(
        UnsubscribeOutcome.FAILED,
        "No safe unsubscribe method is available",
    )


def _grouped_result(
    outcome: UnsubscribeOutcome,
    error: str,
    *,
    needs_confirmation: bool = False,
) -> UnsubResult:
    """Build a grouped result without endpoint or response-body data."""
    return UnsubResult(
        success=False,
        method=None,
        error=error,
        needs_confirmation=needs_confirmation,
        outcome=outcome,
        attempts=0,
    )


def _message_date_key(header: EmailHeader) -> float:
    """Prefer server delivery time; retain Date only for legacy callers."""
    value = header.received_at or header.date
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.timestamp()


def _matches_domain_patterns(domain: str, patterns: list[str]) -> bool:
    value = domain.casefold()
    return any(fnmatch.fnmatch(value, pattern.casefold()) for pattern in patterns)


def _header_matches_patterns(header: EmailHeader, patterns: list[str]) -> bool:
    """Match protection rules against From and unambiguous List-Id identity."""
    values = [header.domain]
    if header.normalized_list_id:
        values.append(header.normalized_list_id)
    return any(_matches_domain_patterns(value, patterns) for value in values)


def _strict_one_click_target(header: EmailHeader) -> str | None:
    """Return the sole RFC 8058 target only when field syntax is compliant."""
    if header.list_unsubscribe_count != 1 or header.list_unsubscribe_post_count != 1:
        return None
    if (header.list_unsubscribe_post or "").strip().casefold() != ONE_CLICK_POST_VALUE:
        return None
    match = _STRICT_ONE_CLICK_RE.fullmatch(header.list_unsubscribe or "")
    if match is None:
        return None
    target = match.group(1)
    targets = header.list_unsubscribe_targets
    if len(targets) != 1 or targets[0] != target:
        return None
    return target


def _trusted_unsubscribe_auth(header: EmailHeader) -> bool:
    """Require provider-trusted authentication rather than legacy booleans."""
    if header.server_can_unsubscribe:
        return True
    evidence = header.authentication
    return evidence.trusted and (
        evidence.dmarc is AuthResult.PASS or has_aligned_dkim_pass(evidence, header.domain)
    )


def _safe_legacy_method(target: str) -> UnsubMethod | None:
    """Map a target to an allowed non-one-click method."""
    try:
        scheme = urllib.parse.urlsplit(target).scheme.casefold()
    except ValueError:
        return None
    if scheme == "https":
        return UnsubMethod.GET
    if scheme == "mailto":
        return UnsubMethod.MAILTO
    return None


def _endpoint_fingerprint(target: str) -> bytes:
    """Build an in-memory opaque fingerprint for endpoint deduplication."""
    return hashlib.sha256(target.encode("utf-8", errors="surrogatepass")).digest()


def _dedupe_endpoints(
    candidates: tuple[tuple[UnsubMethod, str, MessageRef | None], ...],
    exclude_fingerprints: set[str],
) -> tuple[
    list[tuple[UnsubMethod, str, MessageRef | None]],
    list[UnsubscribeAttemptResult],
]:
    """Keep tier/order semantics while bounding distinct network endpoints."""
    result: list[tuple[UnsubMethod, str, MessageRef | None]] = []
    skipped: list[UnsubscribeAttemptResult] = []
    seen: set[bytes] = set()
    normalized_exclusions = {value.casefold() for value in exclude_fingerprints}
    for method, target, message_ref in candidates:
        fingerprint = _endpoint_fingerprint(target)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        fingerprint_hex = fingerprint.hex()
        if fingerprint_hex in normalized_exclusions:
            skipped.append(
                UnsubscribeAttemptResult(
                    method=method,
                    outcome="skipped",
                    endpoint_fingerprint=fingerprint_hex,
                    target_display=_redact_target(target),
                    error_code="endpoint_already_accepted",
                    message_ref=message_ref,
                )
            )
            continue
        result.append((method, target, message_ref))
        if len(result) == MAX_TARGET_ATTEMPTS:
            break
    return result, skipped


def _mark_attempt(
    result: UnsubResult,
    outcome: str,
    error_code: str | None = None,
    *,
    ambiguous_send: bool = False,
) -> UnsubResult:
    """Attach in-memory execution metadata without expanding public results."""
    result._attempt_outcome = outcome  # type: ignore[attr-defined]
    result._error_code = error_code  # type: ignore[attr-defined]
    result._ambiguous_send = ambiguous_send  # type: ignore[attr-defined]
    return result


def _persistable_attempt(
    result: UnsubResult,
    target: str,
    message_ref: MessageRef | None,
) -> UnsubscribeAttemptResult:
    """Convert an endpoint result to a token-free persistence record."""
    explicit_outcome = str(getattr(result, "_attempt_outcome", ""))
    if result.success:
        outcome = "accepted"
    elif explicit_outcome == "ambiguous":
        outcome = "ambiguous"
    elif result.needs_confirmation:
        outcome = "needs_user"
    else:
        outcome = explicit_outcome or "permanent_failure"
    return UnsubscribeAttemptResult(
        method=result.method or UnsubMethod.GET,
        outcome=outcome,
        endpoint_fingerprint=_endpoint_fingerprint(target).hex(),
        target_display=_redact_target(target),
        http_status=result.http_status,
        error_code=getattr(result, "_error_code", None),
        ambiguous_send=bool(getattr(result, "_ambiguous_send", False)),
        message_ref=message_ref,
    )


def _finish(domain: str, attempts: list[UnsubResult], final: UnsubResult) -> UnsubResult:
    """Log every attempt, update the sender status once, return the outcome."""
    for attempt in attempts:
        db.log_unsub_attempt(
            domain=domain,
            success=attempt.success,
            method=attempt.method,
            http_status=attempt.http_status,
            error=attempt.error,
            response_snippet=attempt.response_snippet,
            needs_confirmation=attempt.needs_confirmation,
        )
    if final.success:
        db.update_sender_status(domain, SenderStatus.UNSUBSCRIBED)
    else:
        db.update_sender_status(domain, SenderStatus.FAILED)
    return final


def _rate_limited(method: UnsubMethod) -> UnsubResult | None:
    """Wait for a rate-limit slot; return a failure result on timeout."""
    if not _http_rate_limiter.acquire(timeout=30.0):
        logger.warning("Rate limit timeout for %s unsubscribe", method.value)
        return _mark_attempt(
            UnsubResult(success=False, method=method, error="Rate limit timeout"),
            "retryable_failure",
            "local_rate_limit",
        )
    return None


def _fetch_with_retry(url: str, **kwargs):
    """Fetch with a bounded retry policy and no endpoint-bearing log data."""
    max_attempts = 3
    method = str(kwargs.get("method", "GET"))
    for attempt in range(1, max_attempts + 1):
        try:
            response = safe_fetch(url, **kwargs)
        except SSRFBlockedError:
            raise
        except urllib.error.HTTPError as e:
            if not _retryable_http_status(e.code) or attempt == max_attempts:
                raise
            delay = _retry_delay(attempt, e.headers)
            e.close()
            logger.info(
                "Retrying %s unsubscribe transport (attempt %d/%d) after %.1fs",
                method,
                attempt + 1,
                max_attempts,
                delay,
            )
            time.sleep(delay)
            continue
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            if attempt == max_attempts:
                raise
            delay = _retry_delay(attempt, None)
            logger.info(
                "Retrying %s unsubscribe transport (attempt %d/%d) after %.1fs",
                method,
                attempt + 1,
                max_attempts,
                delay,
            )
            time.sleep(delay)
            continue

        if _retryable_http_status(response.status) and attempt < max_attempts:
            delay = _retry_delay(attempt, None)
            logger.info(
                "Retrying %s unsubscribe response (attempt %d/%d) after %.1fs",
                method,
                attempt + 1,
                max_attempts,
                delay,
            )
            time.sleep(delay)
            continue
        return response

    raise RuntimeError("unreachable retry state")


def _retryable_http_status(status: int) -> bool:
    return status in {408, 425, 429} or 500 <= status < 600


def _retry_delay(attempt: int, headers) -> float:
    """Return a bounded Retry-After value or exponential fallback."""
    value = headers.get("Retry-After") if headers is not None else None
    if value:
        value = value.strip()
        if value.isdigit():
            return min(float(value), MAX_RETRY_AFTER)
        try:
            retry_at = email.utils.parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=UTC)
            return min(max((retry_at - datetime.now(UTC)).total_seconds(), 0.0), MAX_RETRY_AFTER)
        except (TypeError, ValueError, OverflowError):
            pass
    return min(float(2 ** (attempt - 1)), 10.0)


def _execute_one_click(url: str) -> UnsubResult:
    """Execute RFC 8058 one-click unsubscribe (POST request)."""
    limited = _rate_limited(UnsubMethod.ONE_CLICK)
    if limited:
        return limited

    try:
        # RFC 8058: POST the literal pair, form-encoded, no cookies/auth.
        # HTTPS only; a redirect on a one-click endpoint is a failure.
        response = _fetch_with_retry(
            url,
            method="POST",
            data=b"List-Unsubscribe=One-Click",
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=REQUEST_TIMEOUT,
            allow_http=False,
            follow_redirects=False,
        )
        result = UnsubResult(
            success=200 <= response.status < 300,
            method=UnsubMethod.ONE_CLICK,
            http_status=response.status,
            error=None if 200 <= response.status < 300 else f"HTTP {response.status}",
        )
        if result.success:
            return _mark_attempt(result, "accepted")
        retryable = _retryable_http_status(response.status)
        return _mark_attempt(
            result,
            "retryable_failure" if retryable else "permanent_failure",
            "http_retryable" if retryable else "http_permanent",
        )
    except SSRFBlockedError:
        logger.warning("Blocked unsafe one-click destination %s", _redact_target(url))
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.ONE_CLICK,
                error="Blocked unsafe URL",
            ),
            "permanent_failure",
            "unsafe_destination",
        )
    except urllib.error.HTTPError as e:
        retryable = _retryable_http_status(e.code)
        e.close()
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.ONE_CLICK,
                http_status=e.code,
                error=f"HTTP {e.code}",
            ),
            "retryable_failure" if retryable else "permanent_failure",
            "http_retryable" if retryable else "http_permanent",
        )
    except Exception as exc:
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.ONE_CLICK,
                error=f"Transport failure ({type(exc).__name__})",
            ),
            "retryable_failure",
            "transport_failure",
        )


def _execute_get(url: str) -> UnsubResult:
    """Execute GET request to unsubscribe URL (last-resort method)."""
    limited = _rate_limited(UnsubMethod.GET)
    if limited:
        return limited

    try:
        response = _fetch_with_retry(
            url,
            method="GET",
            headers={"User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
            allow_http=False,
            follow_redirects=True,
        )
        # A 200 alone proves nothing: many unsubscribe pages require another
        # click. Success needs a positive phrase and no confirmation prompt.
        # A 204 No Content is unconditional success by definition (there is no
        # body to require a phrase from).
        needs_confirmation = _check_needs_user_indicators(response.body)
        success = response.status == 204 or (
            200 <= response.status < 300
            and _check_success_indicators(response.body)
            and not needs_confirmation
        )
        result = UnsubResult(
            success=success,
            method=UnsubMethod.GET,
            http_status=response.status,
            needs_confirmation=needs_confirmation,
            error=None
            if success or needs_confirmation
            else "No unsubscribe confirmation in response",
        )
        if success:
            return _mark_attempt(result, "accepted")
        if needs_confirmation:
            return _mark_attempt(result, "needs_user", "interactive_response")
        retryable = _retryable_http_status(response.status)
        return _mark_attempt(
            result,
            "retryable_failure" if retryable else "permanent_failure",
            "http_retryable" if retryable else "unconfirmed_response",
        )
    except SSRFBlockedError:
        logger.warning("Blocked unsafe GET destination %s", _redact_target(url))
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.GET,
                error="Blocked unsafe URL",
            ),
            "permanent_failure",
            "unsafe_destination",
        )
    except urllib.error.HTTPError as e:
        retryable = _retryable_http_status(e.code)
        e.close()
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.GET,
                http_status=e.code,
                error=f"HTTP {e.code}",
            ),
            "retryable_failure" if retryable else "permanent_failure",
            "http_retryable" if retryable else "http_permanent",
        )
    except Exception as exc:
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.GET,
                error=f"Transport failure ({type(exc).__name__})",
            ),
            "retryable_failure",
            "transport_failure",
        )


def _execute_mailto(mailto: str, account: AccountConfig, config: Config) -> UnsubResult:
    """Execute mailto unsubscribe by sending an email."""
    try:
        if len(mailto.encode("utf-8")) > MAX_UNSUB_URI:
            return _mark_attempt(
                UnsubResult(
                    success=False,
                    method=UnsubMethod.MAILTO,
                    error="mailto URI exceeds safety limit",
                ),
                "permanent_failure",
                "mailto_too_large",
            )
        parsed = urllib.parse.urlsplit(mailto)
        if parsed.scheme.casefold() != "mailto" or parsed.netloc or parsed.fragment:
            raise ValueError("invalid mailto structure")
        to_address = _strict_unquote(parsed.path)

        subject = "unsubscribe"
        body = "Please unsubscribe me from this mailing list."

        # Only subject/body are safe for an automatically constructed message.
        if parsed.query:
            if _BAD_PERCENT_RE.search(parsed.query):
                raise ValueError("malformed percent encoding")
            pairs = urllib.parse.parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                encoding="utf-8",
                errors="strict",
                max_num_fields=2,
            )
            params: dict[str, str] = {}
            for key, value in pairs:
                name = key.casefold()
                if name not in {"subject", "body"} or name in params:
                    raise ValueError("unsupported or duplicate mailto parameter")
                params[name] = value
            subject = params.get("subject", subject)
            body = params.get("body", body)

        if "\r" in subject or "\n" in subject or "\x00" in subject:
            raise ValueError("invalid subject control character")
        if "\x00" in body:
            raise ValueError("invalid body control character")
        if (
            len(subject.encode("utf-8")) > MAX_MAILTO_SUBJECT
            or len(body.encode("utf-8")) > MAX_MAILTO_BODY
        ):
            return _mark_attempt(
                UnsubResult(
                    success=False,
                    method=UnsubMethod.MAILTO,
                    error="mailto subject/body exceeds safety limit",
                ),
                "permanent_failure",
                "mailto_content_too_large",
            )

        to_address = _validate_single_recipient(to_address)

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = account.email
        msg["To"] = to_address
        msg["Date"] = email.utils.format_datetime(datetime.now(UTC))
        msg["Message-ID"] = email.utils.make_msgid(domain=account.email.rsplit("@", 1)[-1])
        msg["Auto-Submitted"] = "auto-generated"

        _send_mailto_message(msg, account)

        return _mark_attempt(
            UnsubResult(success=True, method=UnsubMethod.MAILTO),
            "accepted",
        )
    except _AmbiguousSMTPDelivery:
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.MAILTO,
                error="SMTP delivery outcome is ambiguous; do not retry",
                needs_confirmation=True,
            ),
            "ambiguous",
            "smtp_ambiguous_send",
            ambiguous_send=True,
        )
    except (ValueError, UnicodeError):
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.MAILTO,
                error="Invalid or multi-recipient mailto address or parameters",
            ),
            "permanent_failure",
            "invalid_mailto",
        )
    except Exception as exc:
        return _mark_attempt(
            UnsubResult(
                success=False,
                method=UnsubMethod.MAILTO,
                error=f"SMTP pre-send failure ({type(exc).__name__})",
            ),
            "retryable_failure" if _is_transient_smtp_error(exc) else "permanent_failure",
            "smtp_transport_failure" if _is_transient_smtp_error(exc) else "smtp_permanent_failure",
        )


def _strict_unquote(value: str) -> str:
    if _BAD_PERCENT_RE.search(value):
        raise ValueError("malformed percent encoding")
    return urllib.parse.unquote_to_bytes(value).decode("utf-8", errors="strict")


def _validate_single_recipient(value: str) -> str:
    """Accept one conservative RFC addr-spec and reject all routing syntax."""
    if len(value.encode("utf-8")) > 320 or value.count("@") != 1:
        raise ValueError("invalid recipient count")
    local, domain = value.rsplit("@", 1)
    if (
        not local
        or len(local.encode("utf-8")) > 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or _LOCAL_ATOM_RE.fullmatch(local) is None
    ):
        raise ValueError("invalid local part")
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid recipient domain") from exc
    if len(ascii_domain) > 255 or "." not in ascii_domain:
        raise ValueError("invalid recipient domain")
    if any(_DOMAIN_LABEL_RE.fullmatch(label) is None for label in ascii_domain.split(".")):
        raise ValueError("invalid recipient domain")
    return f"{local}@{ascii_domain.casefold()}"


class _AmbiguousSMTPDelivery(Exception):
    """Raised after DATA begins because retrying could send a duplicate."""

    pass


def _send_mailto_message(msg: MIMEText, account: AccountConfig) -> None:
    """Authenticate completely before issuing exactly one DATA/send."""
    server, port, use_starttls = _get_smtp_config(account.provider)
    context = ssl.create_default_context()

    def _connect(access_token: str | None = None) -> smtplib.SMTP:
        if use_starttls:
            smtp = smtplib.SMTP(server, port, timeout=REQUEST_TIMEOUT)
        else:
            smtp = smtplib.SMTP_SSL(server, port, context=context, timeout=REQUEST_TIMEOUT)
        try:
            if use_starttls:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
            if account.uses_oauth:
                assert access_token is not None
                raw_response = msauth.build_xoauth2_bytes(account.email, access_token).decode(
                    "utf-8"
                )
                smtp.auth(
                    "XOAUTH2",
                    lambda _challenge=None: raw_response,
                    initial_response_ok=True,
                )
            else:
                smtp.login(account.email, account.password)
            return smtp
        except Exception:
            _close_smtp(smtp)
            raise

    if account.uses_oauth and (account.provider != "outlook" or not account.client_id):
        raise InvalidProviderError("OAuth SMTP requires an Outlook client ID")

    access_token: str | None = None
    refreshed = False
    if account.uses_oauth:
        assert account.client_id is not None
        access_token = msauth.get_access_token(account.email, account.client_id)

    smtp: smtplib.SMTP | None = None
    transient_failures = 0
    while smtp is None:
        try:
            smtp = _connect(access_token)
        except smtplib.SMTPAuthenticationError as exc:
            if account.uses_oauth and not refreshed:
                assert account.client_id is not None
                access_token = msauth.get_access_token(
                    account.email,
                    account.client_id,
                    force_refresh=True,
                )
                refreshed = True
                continue
            if not _is_transient_smtp_error(exc):
                raise
            transient_failures += 1
            if transient_failures >= SMTP_PRE_SEND_ATTEMPTS:
                raise
            time.sleep(min(float(2 ** (transient_failures - 1)), 10.0))
        except Exception as exc:
            if not _is_transient_smtp_error(exc):
                raise
            transient_failures += 1
            if transient_failures >= SMTP_PRE_SEND_ATTEMPTS:
                raise
            time.sleep(min(float(2 ** (transient_failures - 1)), 10.0))

    # Never retry from here. Any send_message failure can occur after the SMTP
    # server accepted DATA, so its delivery outcome is inherently ambiguous.
    try:
        smtp.send_message(msg)
    except Exception as exc:
        raise _AmbiguousSMTPDelivery from exc
    finally:
        _close_smtp(smtp)


def _close_smtp(smtp: smtplib.SMTP) -> None:
    try:
        smtp.quit()
    except Exception:
        try:
            smtp.close()
        except Exception:
            pass


def _is_transient_smtp_error(exc: BaseException) -> bool:
    if isinstance(exc, (TimeoutError, OSError, smtplib.SMTPServerDisconnected)):
        return True
    if isinstance(exc, smtplib.SMTPResponseException):
        return 400 <= exc.smtp_code < 500
    return False


# Valid SMTP providers - reject any provider not in this whitelist
SMTP_CONFIGS = {
    "gmail": ("smtp.gmail.com", 465, False),
    "outlook": ("smtp.office365.com", 587, True),  # STARTTLS; 465 unsupported
    "yahoo": ("smtp.mail.yahoo.com", 465, False),
    "icloud": ("smtp.mail.me.com", 587, True),  # STARTTLS
}


def _get_smtp_config(provider: str) -> tuple[str, int, bool]:
    """Get SMTP config for email provider. Returns (server, port, use_starttls).

    Raises:
        InvalidProviderError: If the provider is not in the whitelist.
    """
    if provider not in SMTP_CONFIGS:
        valid_providers = ", ".join(sorted(SMTP_CONFIGS.keys()))
        raise InvalidProviderError(
            f"Unknown email provider: '{provider}'. Valid providers are: {valid_providers}"
        )
    return SMTP_CONFIGS[provider]


def _check_success_indicators(body: str) -> bool:
    """Check if response body indicates successful unsubscribe."""
    body_lower = body.lower()
    success_phrases = [
        "successfully unsubscribed",
        "you have been unsubscribed",
        "unsubscribe successful",
        "has been removed from",
        "no longer receive",
        "subscription cancelled",
        "subscription canceled",
        "thank you for unsubscribing",
    ]
    return any(phrase in body_lower for phrase in success_phrases)


def _check_confirmation_indicators(body: str) -> bool:
    """Check if the response is asking for further interaction."""
    body_lower = body.lower()
    confirmation_phrases = [
        "confirm your unsubscribe",
        "confirm unsubscribe",
        "click to unsubscribe",
        "click the button",
        "click here to unsubscribe",
        "are you sure",
        "please confirm",
    ]
    return any(phrase in body_lower for phrase in confirmation_phrases)


def _check_needs_user_indicators(body: str) -> bool:
    """Identify responses that safe, stateless GET cannot complete."""
    body_lower = body.casefold()
    interactive_markers = (
        "<form",
        "<script",
        "javascript:",
        "captcha",
        "recaptcha",
        "sign in",
        "log in",
        "login required",
        "manage preferences",
        "update preferences",
        "preference center",
        "javascript required",
        "enable javascript",
        "cookies required",
        "enable cookies",
    )
    return _check_confirmation_indicators(body) or any(
        marker in body_lower for marker in interactive_markers
    )
