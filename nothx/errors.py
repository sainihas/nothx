"""Custom exception types and error handling utilities for nothx."""

import functools
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ParamSpec, TypeVar

logger = logging.getLogger("nothx.errors")

P = ParamSpec("P")
T = TypeVar("T")


class ErrorCode(Enum):
    """Error codes for classification and categorization."""

    # AI errors
    AI_PROVIDER_UNAVAILABLE = "ai_provider_unavailable"
    AI_API_ERROR = "ai_api_error"
    AI_TIMEOUT = "ai_timeout"
    AI_RATE_LIMITED = "ai_rate_limited"
    AI_RESPONSE_PARSE_ERROR = "ai_response_parse_error"
    AI_INVALID_RESPONSE = "ai_invalid_response"

    # IMAP errors
    IMAP_CONNECTION_FAILED = "imap_connection_failed"
    IMAP_AUTH_FAILED = "imap_auth_failed"
    IMAP_TIMEOUT = "imap_timeout"
    IMAP_FETCH_ERROR = "imap_fetch_error"

    # HTTP errors
    HTTP_CONNECTION_ERROR = "http_connection_error"
    HTTP_TIMEOUT = "http_timeout"
    HTTP_ERROR_RESPONSE = "http_error_response"

    # Configuration errors
    CONFIG_INVALID = "config_invalid"
    CONFIG_MISSING = "config_missing"

    # Database errors
    DB_CONNECTION_ERROR = "db_connection_error"
    DB_QUERY_ERROR = "db_query_error"

    # General errors
    UNKNOWN_ERROR = "unknown_error"
    VALIDATION_ERROR = "validation_error"


@dataclass
class NothxError(Exception):
    """Base exception for nothx with structured error information."""

    code: ErrorCode
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    cause: Exception | None = None

    def __str__(self) -> str:
        parts = [f"[{self.code.value}] {self.message}"]
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            parts.append(f" ({details_str})")
        if self.cause:
            parts.append(f" caused by: {self.cause}")
        return "".join(parts)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/serialization."""
        return {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
            "cause": str(self.cause) if self.cause else None,
        }


class AIError(NothxError):
    """AI-related errors."""

    pass


class IMAPError(NothxError):
    """IMAP-related errors."""

    pass


class HTTPError(NothxError):
    """HTTP request errors."""

    pass


class ConfigError(NothxError):
    """Configuration errors."""

    pass


class ValidationError(NothxError):
    """Data validation errors."""

    pass


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_attempts: int = 3
    base_delay: float = 1.0  # seconds
    max_delay: float = 30.0  # seconds
    exponential_base: float = 2.0
    jitter: float = 0.1  # Add randomness to prevent thundering herd
    retryable_exceptions: tuple[type[Exception], ...] = (
        ConnectionError,
        TimeoutError,
        OSError,
    )


def retry_with_backoff(
    config: RetryConfig | None = None,
    on_retry: Callable[[Exception, int, float], None] | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator for retrying functions with exponential backoff.

    Args:
        config: Retry configuration. Uses defaults if not provided.
        on_retry: Optional callback called on each retry with (exception, attempt, delay).

    Returns:
        Decorated function that will retry on failure.
    """
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            last_exception: Exception | None = None

            for attempt in range(1, config.max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except config.retryable_exceptions as e:
                    last_exception = e

                    if attempt == config.max_attempts:
                        # Final attempt failed
                        logger.error(
                            "All %d retry attempts failed for %s: %s",
                            config.max_attempts,
                            func.__name__,
                            e,
                            extra={
                                "function": func.__name__,
                                "attempts": config.max_attempts,
                                "error_type": type(e).__name__,
                            },
                        )
                        raise

                    # Calculate delay with exponential backoff
                    delay = min(
                        config.base_delay * (config.exponential_base ** (attempt - 1)),
                        config.max_delay,
                    )

                    # Add jitter
                    import random

                    jitter_amount = delay * config.jitter * random.random()
                    delay += jitter_amount

                    logger.warning(
                        "Attempt %d/%d failed for %s: %s. Retrying in %.2fs",
                        attempt,
                        config.max_attempts,
                        func.__name__,
                        e,
                        delay,
                        extra={
                            "function": func.__name__,
                            "attempt": attempt,
                            "max_attempts": config.max_attempts,
                            "delay": delay,
                            "error_type": type(e).__name__,
                        },
                    )

                    if on_retry:
                        on_retry(e, attempt, delay)

                    time.sleep(delay)

            # Should not reach here, but satisfy type checker
            assert last_exception is not None
            raise last_exception

        return wrapper

    return decorator


def validate_confidence(confidence: float, context: str = "") -> float:
    """
    Validate and clamp confidence value to [0.0, 1.0] range.

    Args:
        confidence: The confidence value to validate
        context: Optional context for error messages

    Returns:
        Clamped confidence value

    Logs a warning if the value was out of range.
    """
    if confidence < 0.0 or confidence > 1.0:
        logger.warning(
            "Confidence value %.4f out of range [0.0, 1.0]%s, clamping",
            confidence,
            f" in {context}" if context else "",
            extra={"original_confidence": confidence, "context": context},
        )
        return max(0.0, min(1.0, confidence))
    return confidence


@dataclass
class RateLimiter:
    """Simple token bucket rate limiter.

    Args:
        requests_per_second: Maximum requests per second (default: 1.0)
        burst_size: Maximum burst size (default: 5)
    """

    requests_per_second: float = 1.0
    burst_size: int = 5
    _tokens: float = field(default=0.0, init=False, repr=False)
    _last_update: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self):
        """Initialize tokens to burst size."""
        self._tokens = float(self.burst_size)
        self._last_update = time.time()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Acquire a token, waiting if necessary.

        Args:
            timeout: Maximum time to wait in seconds

        Returns:
            True if token acquired, False if timeout
        """
        start_time = time.time()

        while True:
            # Refill tokens based on elapsed time
            now = time.time()
            elapsed = now - self._last_update
            self._tokens = min(
                self.burst_size,
                self._tokens + elapsed * self.requests_per_second,
            )
            self._last_update = now

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True

            # Check timeout
            if time.time() - start_time >= timeout:
                return False

            # Wait a bit before retrying
            time.sleep(min(0.1, (1.0 - self._tokens) / self.requests_per_second))

    def try_acquire(self) -> bool:
        """Try to acquire a token without waiting.

        Returns:
            True if token acquired, False otherwise
        """
        # Refill tokens based on elapsed time
        now = time.time()
        elapsed = now - self._last_update
        self._tokens = min(
            self.burst_size,
            self._tokens + elapsed * self.requests_per_second,
        )
        self._last_update = now

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


def safe_truncate(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Safely truncate text to max_length, respecting UTF-8 boundaries.

    Args:
        text: Text to truncate
        max_length: Maximum length in characters
        suffix: Suffix to add when truncating (default: "...")

    Returns:
        Truncated text that is valid UTF-8
    """
    if len(text) <= max_length:
        return text

    # Account for suffix length
    truncate_at = max_length - len(suffix)
    if truncate_at <= 0:
        return suffix[:max_length]

    # Truncate and ensure we don't break UTF-8
    truncated = text[:truncate_at]

    # If we cut in the middle of a multi-byte character, back up
    # This handles the case where slicing might create invalid UTF-8
    while truncated:
        try:
            truncated.encode("utf-8")
            break  # The string is valid UTF-8, so we can stop
        except UnicodeEncodeError:
            truncated = truncated[:-1]  # Back up one character and try again

    return truncated + suffix
