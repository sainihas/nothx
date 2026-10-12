"""Tests for OpenAI provider request shape."""

from types import SimpleNamespace

import pytest

from nothx.classifier.providers.openai_provider import OpenAIProvider


class _FakeCompletions:
    def __init__(self):
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))],
            usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2),
        )


def _provider_with_fake_client(model: str | None) -> tuple[OpenAIProvider, _FakeCompletions]:
    provider = OpenAIProvider(api_key="test-key", model=model)
    completions = _FakeCompletions()
    provider._client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    return provider, completions


def test_default_model_is_gpt_6_luna():
    assert OpenAIProvider(api_key="test-key").model == "gpt-6-luna"


@pytest.mark.parametrize("model", [None, "gpt-6-luna", "gpt-6.1-sol", "gpt-5.4-mini", "o4-mini"])
def test_reasoning_models_use_max_completion_tokens(model):
    provider, completions = _provider_with_fake_client(model)

    response = provider.complete("classify", max_tokens=123)

    assert response.text == '{"ok": true}'
    assert completions.calls[0]["max_completion_tokens"] == 123
    assert "max_tokens" not in completions.calls[0]


def test_legacy_models_keep_max_tokens():
    provider, completions = _provider_with_fake_client("gpt-4o-mini")

    provider.complete("classify", max_tokens=123)

    assert completions.calls[0]["max_tokens"] == 123
    assert "max_completion_tokens" not in completions.calls[0]
