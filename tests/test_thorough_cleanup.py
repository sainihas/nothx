"""Thorough cleanup unsubscribes from list mail the AI reads as marketing."""

from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db
from nothx.classifier.engine import ClassificationEngine
from nothx.config import Config
from nothx.models import Action, Classification, EmailType, SenderStats


@pytest.fixture
def make_engine(tmp_path: Path):
    with patch("nothx.db.get_db_path", return_value=tmp_path / "thorough.db"):
        db.init_db()

        def build(level: str, ai_result: Classification) -> ClassificationEngine:
            config = Config()
            config.cleanup_level = level
            engine = ClassificationEngine(config)
            engine.ai.is_available = lambda: True  # type: ignore[method-assign]
            engine.ai.classify_batch = lambda senders, **_: {  # type: ignore[method-assign]
                sender.classification_key: ai_result for sender in senders
            }
            engine.ai.classify_single = lambda sender, **_: ai_result  # type: ignore[method-assign]
            return engine

        yield build


def _list_sender(**overrides: object) -> SenderStats:
    values: dict[str, object] = {
        "domain": "news.example.com",
        "total_emails": 4,
        "has_unsubscribe": True,
        "list_id": "weekly.news.example.com",
        "authenticated_emails": 4,
        "sample_subjects": ["This week in product", "New features roundup"],
    }
    values.update(overrides)
    return SenderStats(**values)  # type: ignore[arg-type]


def _ai(email_type: EmailType, action: Action, confidence: float) -> Classification:
    return Classification(email_type, action, confidence, "AI view", "ai")


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    ("email_type", "action", "confidence"),
    [
        (EmailType.NEWSLETTER, Action.REVIEW, 0.7),
        (EmailType.MARKETING, Action.UNSUB, 0.6),
        (EmailType.NEWSLETTER, Action.REVIEW, 0.95),
    ],
)
def test_thorough_unsubscribes_from_list_marketing_and_newsletters(
    make_engine, batch, email_type, action, confidence
):
    engine = make_engine("thorough", _ai(email_type, action, confidence))
    sender = _list_sender()
    result = (
        engine.classify_batch([sender])[sender.classification_key]
        if batch
        else engine.classify(sender)
    )
    assert result.action is Action.UNSUB


@pytest.mark.parametrize("batch", [False, True])
def test_standard_still_reviews_uncertain_newsletters(make_engine, batch):
    engine = make_engine("standard", _ai(EmailType.NEWSLETTER, Action.REVIEW, 0.7))
    sender = _list_sender()
    result = (
        engine.classify_batch([sender])[sender.classification_key]
        if batch
        else engine.classify(sender)
    )
    assert result.action is Action.REVIEW


@pytest.mark.parametrize(
    ("ai_result", "sender"),
    [
        (_ai(EmailType.NEWSLETTER, Action.REVIEW, 0.55), _list_sender()),
        (_ai(EmailType.TRANSACTIONAL, Action.REVIEW, 0.7), _list_sender()),
        (
            _ai(EmailType.MARKETING, Action.UNSUB, 0.7),
            _list_sender(has_unsubscribe=False, list_id=None),
        ),
        (
            _ai(EmailType.MARKETING, Action.UNSUB, 0.85),
            _list_sender(has_unsubscribe=False, list_id=None, authenticated_emails=0),
        ),
        (_ai(EmailType.MARKETING, Action.UNSUB, 0.7), _list_sender(domain="mybank.example")),
    ],
)
def test_thorough_leaves_weak_protected_or_listless_mail_alone(make_engine, ai_result, sender):
    engine = make_engine("thorough", ai_result)
    assert engine.classify(sender).action is not Action.UNSUB


def test_unknown_cleanup_level_loads_as_standard(tmp_path: Path):
    with patch("nothx.config.get_config_dir", return_value=tmp_path):
        config = Config()
        config.cleanup_level = "thorough"
        config.save()
        assert Config.load().cleanup_level == "thorough"
        raw = (tmp_path / "config.json").read_text().replace('"thorough"', '"extreme"')
        (tmp_path / "config.json").write_text(raw)
        assert Config.load().cleanup_level == "standard"


def test_thorough_suppresses_confident_unlisted_marketing_locally(make_engine):
    engine = make_engine("thorough", _ai(EmailType.MARKETING, Action.REVIEW, 0.8))
    sender = _list_sender(has_unsubscribe=False, list_id=None, esp_name="ExampleESP")
    result = engine.classify(sender)
    assert result.action is Action.BLOCK
    assert result.source == "method_policy"


@pytest.mark.parametrize(
    ("ai_result", "bulk", "blocked"),
    [
        (_ai(EmailType.NEWSLETTER, Action.REVIEW, 0.65), {"esp_name": "ExampleESP"}, True),
        (_ai(EmailType.NEWSLETTER, Action.REVIEW, 0.65), {"bulk_precedence": True}, True),
        (_ai(EmailType.MARKETING, Action.BLOCK, 0.85), {"esp_name": "ExampleESP"}, True),
        (_ai(EmailType.NEWSLETTER, Action.REVIEW, 0.65), {"auto_submitted": True}, False),
    ],
)
def test_thorough_uses_bulk_evidence_for_unlisted_mail(make_engine, ai_result, bulk, blocked):
    engine = make_engine("thorough", ai_result)
    sender = _list_sender(has_unsubscribe=False, list_id=None, **bulk)
    assert (engine.classify(sender).action is Action.BLOCK) is blocked
