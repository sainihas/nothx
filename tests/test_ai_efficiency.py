import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from nothx import ai_cache, db
from nothx.classifier.ai import AIClassifier
from nothx.classifier.providers.anthropic_provider import AnthropicProvider
from nothx.classifier.providers.base import ProviderError, ProviderResponse
from nothx.config import Config
from nothx.models import Action, SenderStats


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setattr(db, "get_db_path", lambda: path)
    db.init_db()
    return path


class Provider:
    name = "fake"
    model = "model-one"
    batch_size = 32
    max_parallel_batches = 4

    def __init__(self):
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.calls = 0

    def is_available(self):
        return True

    def complete(self, prompt, max_tokens=4096):
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.calls += 1
        try:
            time.sleep(0.01)
            data = json.loads(prompt.rsplit("<email_data>", 1)[1].split("</email_data>")[0])
            assert len(data) <= 32
            assert max_tokens == (8192 if len(data) > 15 else 4096)
            return ProviderResponse(
                json.dumps(
                    [
                        dict(
                            key=item["key"],
                            domain=item["domain"],
                            type="marketing",
                            action="unsub",
                            confidence=0.95,
                            reasoning="Promotions",
                        )
                        for item in data
                    ]
                ),
                self.model,
            )
        finally:
            with self.lock:
                self.active -= 1


def classifier(provider):
    config = Config()
    config.ai.enabled = True
    instance = AIClassifier(config)
    instance._provider = provider
    instance._provider_initialized = True
    return instance


def senders(count):
    return [
        SenderStats(
            domain="mail.example",
            account_key=f"account-{index}@example.com",
            identity_kind="list_id",
            identity_value=f"list-{index}.example",
            total_emails=10,
            seen_emails=0,
            first_seen=datetime(2026, 1, 1, tzinfo=UTC),
            last_seen=datetime(2026, 2, 1, tzinfo=UTC),
            sample_subjects=["Weekend sale"],
            sample_senders=["offers@mail.example"],
            has_unsubscribe=True,
        )
        for index in range(count)
    ]


def test_parallel_aliases_preserve_account_list_identity_and_main_thread_writes(database):
    provider = Provider()
    instance = classifier(provider)
    items = senders(160)
    progress = []
    owner = threading.get_ident()
    writes = []
    with patch.object(
        db,
        "update_sender_classification",
        side_effect=lambda *args: writes.append(threading.get_ident()),
    ):
        result = instance.classify_batch(
            items, on_progress=lambda done, total: progress.append((done, total))
        )
    assert set(result) == {item.classification_key for item in items}
    assert all(value.action is Action.UNSUB for value in result.values())
    assert 1 < provider.peak <= 4
    assert provider.calls == 5
    assert writes == [owner] * 160
    assert progress == [(n, 160) for n in (0, 32, 64, 96, 128, 160)]


def test_cache_reuses_only_exact_prompt_model_corrections_and_identity(database):
    provider = Provider()
    instance = classifier(provider)
    items = senders(2)
    instance.classify_batch(items)
    assert provider.calls == 1
    assert instance.classify_batch(items)
    assert (provider.calls, instance.last_cache_hits) == (1, 2)
    items[0].sample_subjects.append("Another sale")
    instance.classify_batch(items)
    assert (provider.calls, instance.last_cache_hits) == (2, 1)
    provider.model = "model-two"
    instance.classify_batch(items)
    assert (provider.calls, instance.last_cache_hits) == (3, 0)
    with patch.object(instance, "_get_correction_context", return_value="New user correction"):
        instance.classify_batch(items)
    assert (provider.calls, instance.last_cache_hits) == (4, 0)
    items[0].account_key = "new-account@example.com"
    instance.classify_batch(items)
    assert (provider.calls, instance.last_cache_hits) == (5, 1)


def test_readonly_preview_does_not_write_cache_or_legacy_labels(database):
    provider = Provider()
    instance = classifier(provider)
    with patch.object(db, "update_sender_classification") as update:
        assert instance.classify_batch(senders(1), persist=False) == {}
        assert provider.calls == 0
        assert instance.classify_batch(senders(1), persist=False, allow_egress=True)
        update.assert_not_called()
    assert not database.with_suffix(".ai-cache.sqlite3").exists()


def test_cache_contains_no_headers_and_expired_corrupt_entries_are_ignored(database):
    instance = classifier(Provider())
    instance.classify_batch(senders(1))
    cache = database.with_suffix(".ai-cache.sqlite3")
    assert cache.stat().st_mode & 0o777 == 0o600
    raw = cache.read_bytes()
    for private in (
        b"Weekend sale",
        b"offers@mail.example",
        b"account-0@example.com",
        b"list-0.example",
    ):
        assert private not in raw
    with sqlite3.connect(cache) as connection:
        key = connection.execute("SELECT fingerprint FROM classifications").fetchone()[0]
        connection.execute("UPDATE classifications SET created_at=0")
    assert ai_cache.load([key]) == {}
    cache.write_bytes(b"corrupt")
    assert ai_cache.load([key]) == {}
    ai_cache.save({})
    assert instance.classify_batch(senders(1))


def test_anthropic_client_is_shared_and_has_bounded_retries():
    client = Mock()
    with patch("anthropic.Anthropic", return_value=client) as factory:
        provider = AnthropicProvider("synthetic-key")
        with ThreadPoolExecutor(max_workers=4) as pool:
            assert list(pool.map(lambda _: provider._get_client(), range(20))) == [client] * 20
    factory.assert_called_once_with(api_key="synthetic-key", timeout=60.0, max_retries=0)


def test_cached_content_still_obeys_current_local_policy(database):
    from nothx.classifier.engine import ClassificationEngine

    provider = Provider()
    ai = classifier(provider)
    items = senders(1)
    items[0].seen_emails = 4
    items[0].authenticated_emails = 10
    engine = ClassificationEngine(ai.config)
    engine.ai = ai
    engine.config.review_engaged_marketing = False
    first = engine.classify_batch(items)
    assert first[items[0].classification_key].action is Action.UNSUB
    engine.config.review_engaged_marketing = True
    second = engine.classify_batch(items)
    assert provider.calls == 1
    assert ai.last_cache_hits == 1
    assert second[items[0].classification_key].action is Action.REVIEW
    items[0].protected_subject_emails = 1
    third = engine.classify_batch(items)
    assert provider.calls == 1
    assert third[items[0].classification_key].action is Action.REVIEW


def test_failed_batch_still_advances_progress_and_does_not_cache(database):
    provider = Provider()
    instance = classifier(provider)
    progress = []
    with patch.object(instance, "_classify_chunk", return_value={}):
        assert (
            instance.classify_batch(senders(65), on_progress=lambda n, t: progress.append(n)) == {}
        )
    assert progress == [0, 32, 64, 65] or progress == [0, 32, 33, 65] or progress == [0, 1, 33, 65]
    assert not database.with_suffix(".ai-cache.sqlite3").exists()


def test_anthropic_rate_limit_cooldown_is_shared(database):
    from types import SimpleNamespace

    import anthropic

    provider = AnthropicProvider("synthetic-key")
    client = Mock()
    provider._client = client
    response = SimpleNamespace(status_code=429, headers={"retry-after": "30"}, request=object())
    limited = anthropic.RateLimitError("Rate limit", response=response, body={})
    client.messages.create.side_effect = limited
    with (
        patch("nothx.classifier.providers.anthropic_provider.time.monotonic", return_value=100),
        patch("nothx.classifier.providers.anthropic_provider.time.sleep") as sleep,
    ):
        with pytest.raises(ProviderError) as error:
            provider.complete("synthetic")
        assert error.value.retryable is True
        with pytest.raises(ProviderError):
            provider.complete("synthetic")
        sleep.assert_called_once_with(30)
        provider._retry_at = 200
        with pytest.raises(ProviderError) as error:
            provider.complete("synthetic")
        assert error.value.retryable is False
        assert client.messages.create.call_count == 2


@pytest.mark.parametrize("status", [400, 500, 529])
def test_anthropic_status_retry_policy_replaces_disabled_sdk_retries(status):
    from types import SimpleNamespace

    import anthropic

    provider = AnthropicProvider("synthetic-key")
    provider._client = Mock()
    response = SimpleNamespace(status_code=status, headers={}, request=object())
    provider._client.messages.create.side_effect = anthropic.APIStatusError(
        "API failure", response=response, body={}
    )
    with pytest.raises(ProviderError) as error:
        provider.complete("synthetic")
    assert error.value.retryable is (status >= 500)
