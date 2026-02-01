"""Ollama local model provider implementation."""

import logging

import requests

from .base import BaseAIProvider, ProviderError, ProviderErrorType, ProviderResponse

logger = logging.getLogger("nothx.providers.ollama")


class OllamaProvider(BaseAIProvider):
    """Ollama local model provider.

    Runs models locally via Ollama. No API key needed,
    but requires Ollama to be installed and running.
    """

    def __init__(
        self,
        api_base: str | None = None,
        model: str | None = None,
        api_key: str | None = None,  # Unused, for interface compatibility
    ):
        self.api_base = api_base or "http://localhost:11434"
        self.model = model or self.default_model
        self._available: bool | None = None

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def default_model(self) -> str:
        return "llama3.2"

    def get_model_options(self) -> list[str]:
        """Get list of available local models."""
        try:
            response = requests.get(
                f"{self.api_base}/api/tags",
                timeout=5,
            )
            if response.ok:
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            pass

        # Fallback to common models
        return [
            "llama3.2",
            "llama3.1",
            "mistral",
            "codellama",
            "phi3",
        ]

    def is_available(self) -> bool:
        """Check if Ollama is running and accessible."""
        if self._available is not None:
            return self._available

        try:
            response = requests.get(
                f"{self.api_base}/api/tags",
                timeout=5,
            )
            self._available = response.ok
        except Exception:
            self._available = False

        return self._available

    def complete(self, prompt: str, max_tokens: int = 4096) -> ProviderResponse:
        """Send prompt to Ollama and get response."""
        try:
            response = requests.post(
                f"{self.api_base}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "num_predict": max_tokens,
                    },
                },
                timeout=120,  # Local models can be slow
            )

            response.raise_for_status()
            data = response.json()

            usage = None
            if "prompt_eval_count" in data or "eval_count" in data:
                usage = {
                    "input_tokens": data.get("prompt_eval_count", 0),
                    "output_tokens": data.get("eval_count", 0),
                }

            return ProviderResponse(
                text=data.get("response", ""),
                model=self.model,
                usage=usage,
            )
        except requests.exceptions.HTTPError as e:
            error_type = ProviderErrorType.UNKNOWN
            if e.response is not None:
                if e.response.status_code == 404:
                    error_type = ProviderErrorType.MODEL_ERROR
                elif e.response.status_code == 429:
                    error_type = ProviderErrorType.RATE_LIMIT_ERROR
            raise ProviderError(
                error_type=error_type,
                message=f"Ollama HTTP error: {e}",
                provider=self.name,
                retryable=error_type == ProviderErrorType.RATE_LIMIT_ERROR,
                cause=e,
            ) from e
        except requests.exceptions.Timeout as e:
            raise ProviderError(
                error_type=ProviderErrorType.TIMEOUT_ERROR,
                message="Ollama request timed out",
                provider=self.name,
                retryable=True,
                cause=e,
            ) from e
        except requests.exceptions.ConnectionError as e:
            raise ProviderError(
                error_type=ProviderErrorType.CONNECTION_ERROR,
                message=f"Cannot connect to Ollama at {self.api_base}",
                provider=self.name,
                retryable=True,
                cause=e,
            ) from e
        except Exception as e:
            raise ProviderError(
                error_type=ProviderErrorType.UNKNOWN,
                message=str(e),
                provider=self.name,
                retryable=False,
                cause=e,
            ) from e

    def test_connection(self) -> tuple[bool, str]:
        """Test Ollama connection."""
        try:
            # First check if Ollama is running
            response = requests.get(
                f"{self.api_base}/api/tags",
                timeout=5,
            )

            if not response.ok:
                return False, f"Ollama not responding at {self.api_base}"

            # Check if our model is available
            data = response.json()
            models = [m["name"] for m in data.get("models", [])]

            # Model names can include :tag, so check prefix
            model_base = self.model.split(":")[0]
            model_found = any(m.startswith(model_base) for m in models)

            if not model_found:
                available = ", ".join(models[:5]) if models else "none"
                return (
                    False,
                    f"Model '{self.model}' not found. Available: {available}. "
                    f"Run: ollama pull {self.model}",
                )

            # Test actual generation
            test_response = requests.post(
                f"{self.api_base}/api/generate",
                json={
                    "model": self.model,
                    "prompt": "Say 'ok'",
                    "stream": False,
                    "options": {"num_predict": 10},
                },
                timeout=30,
            )

            if test_response.ok:
                return True, "Connection successful"
            else:
                return False, f"Generation failed: {test_response.text}"

        except requests.exceptions.ConnectionError:
            return (
                False,
                f"Cannot connect to Ollama at {self.api_base}. "
                "Is Ollama running? Start with: ollama serve",
            )
        except Exception as e:
            return False, str(e)
