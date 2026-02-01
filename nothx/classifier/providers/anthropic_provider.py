"""Anthropic Claude provider implementation."""

import logging
from typing import Any

from .base import BaseAIProvider, ProviderResponse

logger = logging.getLogger("nothx.providers.anthropic")


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude API provider."""

    def __init__(self, api_key: str | None, model: str | None = None):
        self.api_key = api_key
        self.model = model or self.default_model
        self._client: Any = None

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def default_model(self) -> str:
        return "claude-sonnet-4-20250514"

    def get_model_options(self) -> list[str]:
        return [
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
        ]

    def _get_client(self):
        """Get or create Anthropic client."""
        if self._client is None:
            try:
                import anthropic

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError as err:
                raise ImportError(
                    "Anthropic SDK not installed. Run: pip install anthropic"
                ) from err
        return self._client

    def is_available(self) -> bool:
        """Check if Anthropic is configured."""
        return bool(self.api_key)

    def complete(self, prompt: str, max_tokens: int = 4096) -> ProviderResponse:
        """Send prompt to Claude and get response."""
        client = self._get_client()
        response = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )

        return ProviderResponse(
            text=response.content[0].text,
            model=self.model,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )

    def test_connection(self) -> tuple[bool, str]:
        """Test Anthropic API connection."""
        if not self.api_key:
            return False, "No API key configured"

        try:
            client = self._get_client()
            client.messages.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": "Say 'ok'"}],
            )
            return True, "Connection successful"
        except ImportError:
            return False, "Anthropic SDK not installed. Run: pip install anthropic"
        except Exception as e:
            return False, str(e)
