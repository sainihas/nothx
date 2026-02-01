"""Factory for creating AI provider instances."""

from ..providers.base import BaseAIProvider

# Provider metadata for CLI display
SUPPORTED_PROVIDERS = {
    "anthropic": {
        "name": "Anthropic (Claude)",
        "description": "Best for email classification. Recommended.",
        "requires_key": True,
        "key_url": "https://console.anthropic.com",
        "key_env": "ANTHROPIC_API_KEY",
    },
    "openai": {
        "name": "OpenAI (GPT)",
        "description": "GPT-4o and GPT-4 models.",
        "requires_key": True,
        "key_url": "https://platform.openai.com/api-keys",
        "key_env": "OPENAI_API_KEY",
    },
    "gemini": {
        "name": "Google (Gemini)",
        "description": "Gemini models with generous free tier.",
        "requires_key": True,
        "key_url": "https://aistudio.google.com/apikey",
        "key_env": "GOOGLE_API_KEY",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "description": "Run models locally. No API key needed.",
        "requires_key": False,
        "key_url": None,
        "key_env": None,
    },
    "none": {
        "name": "None (Heuristics only)",
        "description": "Skip AI, use rule-based classification.",
        "requires_key": False,
        "key_url": None,
        "key_env": None,
    },
}


def get_provider(
    provider_name: str,
    api_key: str | None = None,
    model: str | None = None,
    api_base: str | None = None,
) -> BaseAIProvider | None:
    """Create an AI provider instance.

    Args:
        provider_name: Name of the provider (anthropic, openai, gemini, ollama, none)
        api_key: API key for the provider (not needed for ollama/none)
        model: Model to use (uses provider default if not specified)
        api_base: Custom API base URL (for ollama or custom endpoints)

    Returns:
        BaseAIProvider instance or None if provider is "none"

    Raises:
        ValueError: If provider_name is not supported
    """
    provider_name = provider_name.lower()

    if provider_name == "none":
        return None

    if provider_name not in SUPPORTED_PROVIDERS:
        valid = ", ".join(SUPPORTED_PROVIDERS.keys())
        raise ValueError(f"Unknown provider: {provider_name}. Valid options: {valid}")

    if provider_name == "anthropic":
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=api_key, model=model)

    elif provider_name == "openai":
        from .openai_provider import OpenAIProvider

        return OpenAIProvider(api_key=api_key, model=model, api_base=api_base)

    elif provider_name == "gemini":
        from .gemini_provider import GeminiProvider

        return GeminiProvider(api_key=api_key, model=model)

    elif provider_name == "ollama":
        from .ollama_provider import OllamaProvider

        return OllamaProvider(api_base=api_base, model=model)

    else:
        raise ValueError(f"Provider {provider_name} not implemented")
