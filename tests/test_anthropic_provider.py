"""Tests for Anthropic provider compatibility handling."""

from types import SimpleNamespace

import pytest

from nothx.classifier.providers.anthropic_provider import AnthropicProvider
from nothx.classifier.providers.base import ProviderError, ProviderErrorType


class TestAnthropicProvider:
    def test_default_model_uses_current_haiku_id(self):
        provider = AnthropicProvider(api_key="test-key")

        assert provider.model == "claude-haiku-4-5-20251001"

    def test_retired_sonnet_model_is_replaced(self):
        provider = AnthropicProvider(api_key="test-key", model="claude-sonnet-4-20250514")

        assert provider.model == "claude-sonnet-4-6"

    def test_sonnet_5_model_is_preserved(self):
        provider = AnthropicProvider(api_key="test-key", model="claude-sonnet-5")

        assert provider.model == "claude-sonnet-5"

    def test_short_haiku_alias_is_replaced(self):
        provider = AnthropicProvider(api_key="test-key", model="claude-haiku-4-5")

        assert provider.model == "claude-haiku-4-5-20251001"

    def test_extract_response_text_skips_thinking_blocks(self):
        provider = AnthropicProvider(api_key="test-key")
        response = SimpleNamespace(
            content=[
                SimpleNamespace(type="thinking", thinking="internal summary"),
                SimpleNamespace(type="text", text='[{"domain": "example.com"}]'),
            ]
        )

        assert provider._extract_response_text(response) == '[{"domain": "example.com"}]'

    def test_extract_response_text_concatenates_text_blocks(self):
        provider = AnthropicProvider(api_key="test-key")
        response = SimpleNamespace(
            content=[
                {"type": "text", "text": '[{"domain": "a.com"}]'},
                {"type": "redacted_thinking", "data": "..."},
                {"type": "text", "text": "\n"},
            ]
        )

        assert provider._extract_response_text(response) == '[{"domain": "a.com"}]\n'

    def test_extract_response_text_errors_without_text_blocks(self):
        provider = AnthropicProvider(api_key="test-key")
        response = SimpleNamespace(content=[SimpleNamespace(type="thinking", thinking="...")])

        with pytest.raises(ProviderError) as exc_info:
            provider._extract_response_text(response)

        assert exc_info.value.error_type == ProviderErrorType.PARSE_ERROR
