"""OpenAI GPT provider implementation."""

import logging
from typing import Any

from .base import BaseAIProvider, ProviderResponse

logger = logging.getLogger("nothx.providers.openai")


class OpenAIProvider(BaseAIProvider):
    """OpenAI GPT API provider."""

    def __init__(
        self,
        api_key: str | None,
        model: str | None = None,
        api_base: str | None = None,
    ):
        self.api_key = api_key
        self.model = model or self.default_model
        self.api_base = api_base
        self._client: Any = None

    @property
    def name(self) -> str:
        return "openai"

    @property
    def default_model(self) -> str:
        return "gpt-4o"

    def get_model_options(self) -> list[str]:
        return [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-3.5-turbo",
        ]

    def _get_client(self):
        """Get or create OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI

                kwargs = {"api_key": self.api_key}
                if self.api_base:
                    kwargs["base_url"] = self.api_base

                self._client = OpenAI(**kwargs)
            except ImportError:
                raise ImportError(
                    "OpenAI SDK not installed. Run: pip install openai"
                )
        return self._client

    def is_available(self) -> bool:
        """Check if OpenAI is configured."""
        return bool(self.api_key)

    def complete(self, prompt: str, max_tokens: int = 4096) -> ProviderResponse:
        """Send prompt to GPT and get response."""
        client = self._get_client()
        response = client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )

        usage = None
        if response.usage:
            usage = {
                "input_tokens": response.usage.prompt_tokens,
                "output_tokens": response.usage.completion_tokens,
            }

        return ProviderResponse(
            text=response.choices[0].message.content or "",
            model=self.model,
            usage=usage,
        )

    def test_connection(self) -> tuple[bool, str]:
        """Test OpenAI API connection."""
        if not self.api_key:
            return False, "No API key configured"

        try:
            client = self._get_client()
            client.chat.completions.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": "Say 'ok'"}],
            )
            return True, "Connection successful"
        except ImportError:
            return False, "OpenAI SDK not installed. Run: pip install openai"
        except Exception as e:
            return False, str(e)
