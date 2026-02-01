"""Base class for AI providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProviderErrorType(Enum):
    """Types of provider errors for categorization."""

    CONNECTION_ERROR = "connection_error"
    AUTHENTICATION_ERROR = "authentication_error"
    RATE_LIMIT_ERROR = "rate_limit_error"
    TIMEOUT_ERROR = "timeout_error"
    INVALID_REQUEST = "invalid_request"
    MODEL_ERROR = "model_error"
    PARSE_ERROR = "parse_error"
    UNKNOWN = "unknown"


@dataclass
class ProviderError(Exception):
    """Structured error from AI providers."""

    error_type: ProviderErrorType
    message: str
    provider: str
    details: dict[str, Any] = field(default_factory=dict)
    retryable: bool = False
    cause: Exception | None = None

    def __str__(self) -> str:
        parts = [f"[{self.provider}:{self.error_type.value}] {self.message}"]
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            parts.append(f" ({details_str})")
        if self.cause:
            parts.append(f" caused by: {type(self.cause).__name__}: {self.cause}")
        return "".join(parts)


@dataclass
class ProviderResponse:
    """Standardized response from AI providers."""

    text: str
    model: str
    usage: dict | None = None


class BaseAIProvider(ABC):
    """Abstract base class for AI providers.

    All providers must implement these methods to be used
    for email classification in nothx.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider name."""
        pass

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Return the default model for this provider."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this provider is properly configured and available."""
        pass

    @abstractmethod
    def complete(self, prompt: str, max_tokens: int = 4096) -> ProviderResponse:
        """Send a prompt and get a completion.

        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response

        Returns:
            ProviderResponse with the completion text

        Raises:
            Exception if the request fails
        """
        pass

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """Test if the provider connection works.

        Returns:
            Tuple of (success: bool, message: str)
        """
        pass

    def get_model_options(self) -> list[str]:
        """Return available models for this provider."""
        return [self.default_model]
