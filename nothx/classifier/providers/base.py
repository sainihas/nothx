"""Base class for AI providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass


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
