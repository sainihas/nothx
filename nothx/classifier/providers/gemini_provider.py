"""Google Gemini provider implementation."""

import logging
from typing import Any

from .base import BaseAIProvider, ProviderError, ProviderErrorType, ProviderResponse

logger = logging.getLogger("nothx.providers.gemini")


def _sanitize_error_message(error: Exception) -> str:
    """Sanitize error message to avoid exposing API keys."""
    msg = str(error)
    # Common patterns that might contain API keys
    sensitive_patterns = ["api_key=", "api-key=", "authorization:", "bearer ", "aiza"]
    msg_lower = msg.lower()
    for pattern in sensitive_patterns:
        if pattern in msg_lower:
            return "API error (details redacted for security)"
    return msg


class GeminiProvider(BaseAIProvider):
    """Google Gemini API provider."""

    def __init__(self, api_key: str | None, model: str | None = None):
        self.api_key = api_key
        self.model = model or self.default_model
        self._client: Any = None

    @property
    def name(self) -> str:
        return "gemini"

    @property
    def default_model(self) -> str:
        return "gemini-1.5-flash"

    def get_model_options(self) -> list[str]:
        return [
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-2.0-flash",
        ]

    def _get_client(self):
        """Get or create Gemini client."""
        if self._client is None:
            try:
                import google.generativeai as genai

                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(self.model)
            except ImportError as err:
                raise ImportError(
                    "Google Generative AI SDK not installed. Run: pip install google-generativeai"
                ) from err
        return self._client

    def is_available(self) -> bool:
        """Check if Gemini is configured."""
        return bool(self.api_key)

    def complete(self, prompt: str, max_tokens: int = 4096) -> ProviderResponse:
        """Send prompt to Gemini and get response."""
        try:
            client = self._get_client()

            # Gemini uses generation_config for max tokens
            response = client.generate_content(
                prompt,
                generation_config={"max_output_tokens": max_tokens},
            )

            # Extract usage if available
            usage = None
            if hasattr(response, "usage_metadata") and response.usage_metadata:
                usage = {
                    "input_tokens": getattr(response.usage_metadata, "prompt_token_count", 0),
                    "output_tokens": getattr(response.usage_metadata, "candidates_token_count", 0),
                }

            return ProviderResponse(
                text=response.text,
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
            if "rate" in error_str or "limit" in error_str or "quota" in error_str:
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
        """Test Gemini API connection."""
        if not self.api_key:
            return False, "No API key configured"

        try:
            client = self._get_client()
            client.generate_content(
                "Say 'ok'",
                generation_config={"max_output_tokens": 10},
            )
            return True, "Connection successful"
        except ImportError:
            return (
                False,
                "Google Generative AI SDK not installed. Run: pip install google-generativeai",
            )
        except Exception as e:
            return False, _sanitize_error_message(e)
