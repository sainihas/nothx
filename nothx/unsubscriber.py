"""Unsubscribe execution for nothx."""

import fnmatch
import logging
import smtplib
import ssl
import urllib.error
import urllib.parse
from email.mime.text import MIMEText

from . import db
from . import __version__
from .config import AccountConfig, Config
from .errors import RateLimiter, RetryConfig, retry_with_backoff, safe_truncate
from .models import EmailHeader, SenderStatus, UnsubMethod, UnsubResult
from .safefetch import SSRFBlockedError, safe_fetch


class UnsafeUnsubscribeError(Exception):
    """Raised when attempting to unsubscribe from a protected domain."""

    pass


class InvalidProviderError(Exception):
    """Raised when an invalid email provider is specified."""

    pass


logger = logging.getLogger("nothx.unsubscriber")

# User agent for HTTP requests - identifies as nothx email automation tool
USER_AGENT = f"nothx/{__version__} (Email Unsubscribe Automation; +https://github.com/sainihas/nothx)"

# Timeout for HTTP requests
REQUEST_TIMEOUT = 30

# Rate limiter for HTTP unsubscribe requests
# Default: 2 requests per second, burst of 5
# This prevents overwhelming mail servers and getting blocked
_http_rate_limiter = RateLimiter(requests_per_second=2.0, burst_size=5)

class _TransientHTTPFailure(Exception):
    """Wraps a retryable failure (network error or 5xx).

    urllib's HTTPError subclasses OSError, so filtering the retry decorator
    on stdlib exception types would retry 4xx responses too. Wrapping makes
    the retryable set explicit.
    """

    def __init__(self, cause: Exception):
        super().__init__(str(cause))
        self.cause = cause


# Retry transient failures (network errors, 5xx) on unsubscribe requests
HTTP_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=1.0,
    max_delay=10.0,
    exponential_base=2.0,
    retryable_exceptions=(_TransientHTTPFailure,),
)

# RFC 8058: the List-Unsubscribe-Post header value must be exactly this pair.
ONE_CLICK_POST_VALUE = "list-unsubscribe=one-click"


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
    return bool(post_value) and post_value.strip().lower() == ONE_CLICK_POST_VALUE


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
        return UnsubResult(success=False, method=method, error="Rate limit timeout")
    return None


def _fetch_with_retry(url: str, **kwargs):
    """safe_fetch with retries on transient failures (network errors, 5xx).

    Non-retryable outcomes (4xx, blocked URLs) propagate immediately; if all
    attempts fail, the wrapped original exception is re-raised.
    """

    @retry_with_backoff(
        config=HTTP_RETRY_CONFIG,
        on_retry=lambda e, attempt, delay: logger.info(
            "Retrying unsubscribe request (attempt %d) after %.1fs: %s", attempt, delay, e
        ),
    )
    def _fetch():
        try:
            return safe_fetch(url, **kwargs)
        except SSRFBlockedError:
            raise  # never retry a blocked URL
        except urllib.error.HTTPError as e:
            if 500 <= e.code < 600:
                raise _TransientHTTPFailure(e) from e
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            raise _TransientHTTPFailure(e) from e

    try:
        return _fetch()
    except _TransientHTTPFailure as e:
        raise e.cause from e


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
        return UnsubResult(
            success=200 <= response.status < 300,
            method=UnsubMethod.ONE_CLICK,
            http_status=response.status,
            response_snippet=safe_truncate(response.body, 200) if response.body else None,
        )
    except SSRFBlockedError as e:
        logger.warning("Blocked unsafe one-click URL for %s: %s", url, e)
        return UnsubResult(
            success=False, method=UnsubMethod.ONE_CLICK, error=f"Blocked unsafe URL: {e}"
        )
    except urllib.error.HTTPError as e:
        return UnsubResult(
            success=False, method=UnsubMethod.ONE_CLICK, http_status=e.code, error=str(e)
        )
    except Exception as e:
        return UnsubResult(success=False, method=UnsubMethod.ONE_CLICK, error=str(e))


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
        snippet = safe_truncate(response.body, 200) if response.body else None

        # A 200 alone proves nothing: many unsubscribe pages require another
        # click. Success needs a positive phrase and no confirmation prompt.
        needs_confirmation = _check_confirmation_indicators(response.body)
        success = (
            200 <= response.status < 300
            and _check_success_indicators(response.body)
            and not needs_confirmation
        )
        return UnsubResult(
            success=success,
            method=UnsubMethod.GET,
            http_status=response.status,
            response_snippet=snippet,
            needs_confirmation=needs_confirmation,
            error=None if success or needs_confirmation else "No unsubscribe confirmation in response",
        )
    except SSRFBlockedError as e:
        logger.warning("Blocked unsafe GET URL for %s: %s", url, e)
        return UnsubResult(success=False, method=UnsubMethod.GET, error=f"Blocked unsafe URL: {e}")
    except urllib.error.HTTPError as e:
        return UnsubResult(success=False, method=UnsubMethod.GET, http_status=e.code, error=str(e))
    except Exception as e:
        return UnsubResult(success=False, method=UnsubMethod.GET, error=str(e))


def _execute_mailto(mailto: str, account: AccountConfig, config: Config) -> UnsubResult:
    """Execute mailto unsubscribe by sending an email."""
    try:
        parsed = urllib.parse.urlsplit(mailto)
        to_address = urllib.parse.unquote(parsed.path).strip()

        subject = "unsubscribe"
        body = "Please unsubscribe me from this mailing list."

        # Preserve subject/body parameters per RFC 6068
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            subject = params.get("subject", [subject])[0]
            body = params.get("body", [body])[0]

        # Header injection guard: no CR/LF in addressing or subject
        to_address = to_address.replace("\r", "").replace("\n", "")
        subject = subject.replace("\r", " ").replace("\n", " ")

        if "@" not in to_address:
            return UnsubResult(
                success=False,
                method=UnsubMethod.MAILTO,
                error=f"Invalid mailto address: {to_address!r}",
            )

        # Create email
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = account.email
        msg["To"] = to_address

        # Send via SMTP with certificate verification
        server, port, use_starttls = _get_smtp_config(account.provider)
        context = ssl.create_default_context()
        if use_starttls:
            with smtplib.SMTP(server, port) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()  # Required after STARTTLS
                smtp.login(account.email, account.password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP_SSL(server, port, context=context) as smtp:
                smtp.login(account.email, account.password)
                smtp.send_message(msg)

        return UnsubResult(
            success=True,
            method=UnsubMethod.MAILTO,
            response_snippet=f"Sent unsubscribe email to {to_address}",
        )

    except Exception as e:
        return UnsubResult(
            success=False,
            method=UnsubMethod.MAILTO,
            error=str(e),
        )


# Valid SMTP providers - reject any provider not in this whitelist
SMTP_CONFIGS = {
    "gmail": ("smtp.gmail.com", 465, False),
    "outlook": ("smtp-mail.outlook.com", 587, True),  # STARTTLS; 465 unsupported
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
