"""OpenAI GPT provider implementation."""

import logging
from typing import Any

from .base import BaseAIProvider, ProviderError, ProviderErrorType, ProviderResponse

logger = logging.getLogger("nothx.providers.openai")


def _sanitize_error_message(error: Exception) -> str:
    """Sanitize error message to avoid exposing API keys."""
    msg = str(error)
    # Common patterns that might contain API keys
    sensitive_patterns = ["api_key=", "api-key=", "authorization:", "bearer ", "sk-"]
    msg_lower = msg.lower()
    for pattern in sensitive_patterns:
        if pattern in msg_lower:
            return "API error (details redacted for security)"
    return msg


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

                if self.api_base:
                    self._client = OpenAI(api_key=self.api_key, base_url=self.api_base)
                else:
                    self._client = OpenAI(api_key=self.api_key)
            except ImportError as err:
                raise ImportError("OpenAI SDK not installed. Run: pip install openai") from err
        return self._client

    def is_available(self) -> bool:
        """Check if OpenAI is configured."""
        return bool(self.api_key)

    def complete(self, prompt: str, max_tokens: int = 4096) -> ProviderResponse:
        """Send prompt to GPT and get response."""
        try:
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
        except ImportError:
            raise
        except Exception as e:
            error_msg = _sanitize_error_message(e)
            error_type = ProviderErrorType.UNKNOWN
            retryable = False

            # Detect specific error types
            error_str = str(e).lower()
            if "rate" in error_str or "limit" in error_str:
                error_type = ProviderErrorType.RATE_LIMIT_ERROR
                retryable = True
            elif "auth" in error_str or "key" in error_str or "401" in error_str:
                error_type = ProviderErrorType.AUTHENTICATION_ERROR
            elif "timeout" in error_str:
                error_type = ProviderErrorType.TIMEOUT_ERROR
                retryable = True
            elif "connect" in error_str:
                error_type = ProviderErrorType.CONNECTION_ERROR
                retryable = True

            raise ProviderError(
                error_type=error_type,
                message=error_msg,
                provider=self.name,
                retryable=retryable,
                cause=e,
            ) from e

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
            return False, _sanitize_error_message(e)
