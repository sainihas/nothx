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
            from openai import (
                APIConnectionError,
                APITimeoutError,
                AuthenticationError,
                RateLimitError,
            )

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
        except RateLimitError as e:
            raise ProviderError(
                error_type=ProviderErrorType.RATE_LIMIT_ERROR,
                message=str(e),
                provider=self.name,
                retryable=True,
                cause=e,
            ) from e
        except AuthenticationError as e:
            raise ProviderError(
                error_type=ProviderErrorType.AUTHENTICATION_ERROR,
                message=_sanitize_error_message(e),
                provider=self.name,
                retryable=False,
                cause=e,
            ) from e
        except APITimeoutError as e:
            raise ProviderError(
                error_type=ProviderErrorType.TIMEOUT_ERROR,
                message=str(e),
                provider=self.name,
                retryable=True,
                cause=e,
            ) from e
        except APIConnectionError as e:
            raise ProviderError(
                error_type=ProviderErrorType.CONNECTION_ERROR,
                message=str(e),
                provider=self.name,
                retryable=True,
                cause=e,
            ) from e
        except Exception as e:
            raise ProviderError(
                error_type=ProviderErrorType.UNKNOWN,
                message=_sanitize_error_message(e),
                provider=self.name,
                retryable=False,
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
