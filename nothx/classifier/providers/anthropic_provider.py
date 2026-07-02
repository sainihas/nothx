"""Anthropic Claude provider implementation."""

import logging
from typing import Any

from .base import BaseAIProvider, ProviderError, ProviderErrorType, ProviderResponse

logger = logging.getLogger("nothx.providers.anthropic")


MODEL_REPLACEMENTS = {
    # Retired on the Anthropic API in 2026; keep existing user configs working.
    "claude-sonnet-4-20250514": "claude-sonnet-4-6",
    "claude-opus-4-20250514": "claude-opus-4-8",
    "claude-opus-4-1-20250805": "claude-opus-4-8",
    "claude-3-7-sonnet-20250219": "claude-sonnet-4-6",
    "claude-3-5-sonnet-20240620": "claude-sonnet-4-6",
    "claude-3-5-sonnet-20241022": "claude-sonnet-4-6",
    "claude-3-sonnet-20240229": "claude-sonnet-4-6",
    "claude-3-haiku-20240307": "claude-haiku-4-5-20251001",
    "claude-3-5-haiku-20241022": "claude-haiku-4-5-20251001",
    # Earlier nothx releases used the short Haiku alias. Use the documented ID.
    "claude-haiku-4-5": "claude-haiku-4-5-20251001",
}


def _normalize_model(model: str) -> str:
    """Map retired or ambiguous Anthropic model IDs to current API models."""
    return MODEL_REPLACEMENTS.get(model, model)


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


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude API provider."""

    def __init__(self, api_key: str | None, model: str | None = None):
        self.api_key = api_key
        requested_model = model or self.default_model
        self.model = _normalize_model(requested_model)
        if self.model != requested_model:
            logger.info(
                "Using replacement Anthropic model %s for configured model %s",
                self.model,
                requested_model,
            )
        self._client: Any = None

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def default_model(self) -> str:
        # Haiku is the cost-effective choice for high-volume header classification
        return "claude-haiku-4-5-20251001"

    def get_model_options(self) -> list[str]:
        return [
            "claude-haiku-4-5-20251001",
            "claude-sonnet-5",
            "claude-sonnet-4-6",
            "claude-opus-4-8",
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

    def _extract_response_text(self, response: Any) -> str:
        """Return text content from an Anthropic message response.

        Newer models can include non-text blocks such as thinking before the
        answer. The classifier only needs the final text JSON, so skip any
        block that is not text instead of assuming content[0].text exists.
        """
        text_parts: list[str] = []
        for block in getattr(response, "content", []) or []:
            if isinstance(block, dict):
                block_type = block.get("type")
                text = block.get("text")
            else:
                block_type = getattr(block, "type", None)
                text = getattr(block, "text", None)

            if block_type == "text" and isinstance(text, str) and text:
                text_parts.append(text)

        if not text_parts:
            raise ProviderError(
                error_type=ProviderErrorType.PARSE_ERROR,
                message="Anthropic response did not include a text block",
                provider=self.name,
                retryable=False,
            )

        return "".join(text_parts)

    def complete(self, prompt: str, max_tokens: int = 4096) -> ProviderResponse:
        """Send prompt to Claude and get response."""
        try:
            import anthropic

            client = self._get_client()
            response = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            return ProviderResponse(
                text=self._extract_response_text(response),
                model=self.model,
                usage={
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                },
            )
        except ImportError:
            raise
        except ProviderError:
            raise
        except anthropic.RateLimitError as e:
            raise ProviderError(
                error_type=ProviderErrorType.RATE_LIMIT_ERROR,
                message=str(e),
                provider=self.name,
                retryable=True,
                cause=e,
            ) from e
        except anthropic.NotFoundError as e:
            raise ProviderError(
                error_type=ProviderErrorType.MODEL_ERROR,
                message=f"Anthropic model is not available: {self.model}",
                provider=self.name,
                details={"model": self.model},
                retryable=False,
                cause=e,
            ) from e
        except anthropic.AuthenticationError as e:
            raise ProviderError(
                error_type=ProviderErrorType.AUTHENTICATION_ERROR,
                message=_sanitize_error_message(e),
                provider=self.name,
                retryable=False,
                cause=e,
            ) from e
        except anthropic.APITimeoutError as e:
            raise ProviderError(
                error_type=ProviderErrorType.TIMEOUT_ERROR,
                message=str(e),
                provider=self.name,
                retryable=True,
                cause=e,
            ) from e
        except anthropic.APIConnectionError as e:
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
            return False, _sanitize_error_message(e)
