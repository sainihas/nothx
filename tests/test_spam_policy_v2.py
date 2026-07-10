"""High-recall spam policy and raw-header regression coverage."""

from __future__ import annotations

import email
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from nothx import db
from nothx.authres import dkim_covers_unsubscribe, parse_authentication_results
from nothx.classifier.engine import ClassificationEngine
from nothx.config import AccountConfig, Config
from nothx.imap import IMAPConnection
from nothx.models import (
    Action,
    AuthResult,
    Classification,
    EmailHeader,
    EmailType,
    SenderStats,
)
from nothx.provider_signals import parse_provider_signals
from nothx.scanner import _stats_for_emails

FIXTURES = Path(__file__).parent / "fixtures" / "headers"


def _parsed_fixture(name: str, provider: str = "gmail") -> EmailHeader:
    raw = (FIXTURES / name).read_bytes()
    message = email.message_from_bytes(raw)
    connection = IMAPConnection(
        AccountConfig(provider=provider, email="owner@example.com", password="test")
    )
    parsed = connection._parse_header(message, is_seen=False)
    assert parsed is not None
    parsed.account_key = "owner@example.com"
    parsed.uidvalidity = 10
    parsed.uid = 1
    return parsed


@pytest.fixture
def policy_engine(tmp_path: Path):
    with patch("nothx.db.get_db_path", return_value=tmp_path / "policy.db"):
        db.init_db()
        config = Config()
        config.ai.enabled = False
        yield ClassificationEngine(config)


def test_authenticated_raw_subscription_has_strict_one_click_evidence():
    header = _parsed_fixture("authenticated_subscription.eml")

    assert header.normalized_list_id == "daily.news.example"
    assert header.authentication.dkim is AuthResult.PASS
    assert header.authentication.dmarc is AuthResult.PASS
    assert header.dkim_covers_unsubscribe is True
    assert header.has_compliant_one_click is True


def test_forwarded_broken_authentication_is_not_a_strong_failure():
    header = _parsed_fixture("forwarded_broken.eml")

    assert header.authentication.arc is AuthResult.PASS
    assert header.dkim_pass is False
    assert header.strongly_failed_authentication is False


def test_forwarded_broken_authentication_is_reviewed_before_ai(policy_engine):
    header = _parsed_fixture("forwarded_broken.eml")
    stats = _stats_for_emails(header.domain, [header])
    policy_engine.ai.is_available = Mock(return_value=True)
    policy_engine.ai.classify_single = Mock()

    result = policy_engine.classify(stats)

    assert result.action is Action.REVIEW
    assert result.source == "auth_policy"
    policy_engine.ai.classify_single.assert_not_called()


def test_outlook_threat_header_blocks_even_a_protected_looking_sender(policy_engine):
    header = _parsed_fixture("phishing_outlook.eml", provider="outlook")
    stats = _stats_for_emails(header.domain, [header])

    result = policy_engine.classify(stats)

    assert header.provider_threat == "PHSH"
    assert result.action is Action.BLOCK
    assert result.source == "provider_policy"


def test_transactional_bulk_signal_never_implies_automatic_unsubscribe(policy_engine):
    header = _parsed_fixture("transactional_bulk.eml")
    stats = _stats_for_emails(header.domain, [header])
    policy_engine.ai.is_available = Mock(return_value=True)
    policy_engine.ai.classify_single = Mock()

    result = policy_engine.classify(stats)

    assert stats.bulk_precedence is True
    assert stats.authenticated_emails == 1
    assert result.action is Action.KEEP
    assert result.source == "transactional_policy"
    policy_engine.ai.classify_single.assert_not_called()


def test_transactional_bulk_headers_never_reach_batch_ai(policy_engine):
    header = _parsed_fixture("transactional_bulk.eml")
    stats = _stats_for_emails(header.domain, [header])
    policy_engine.ai.is_available = Mock(return_value=True)
    policy_engine.ai.classify_batch = Mock(return_value={})

    results = policy_engine.classify_batch([stats], persist=False)

    assert results[stats.classification_key].action is Action.KEEP
    policy_engine.ai.classify_batch.assert_not_called()


def test_authenticated_cold_outreach_without_a_method_is_locally_blocked(policy_engine):
    header = _parsed_fixture("cold_outreach.eml")
    stats = _stats_for_emails(header.domain, [header])

    result = policy_engine.classify(stats)

    assert result.action is Action.BLOCK
    assert result.email_type is EmailType.COLD_OUTREACH


def test_cold_outreach_is_resolved_before_ai(policy_engine):
    header = _parsed_fixture("cold_outreach.eml")
    stats = _stats_for_emails(header.domain, [header])
    policy_engine.ai.is_available = Mock(return_value=True)
    policy_engine.ai.classify_single = Mock()

    result = policy_engine.classify(stats)

    assert result.action is Action.BLOCK
    policy_engine.ai.classify_single.assert_not_called()


def test_lone_meeting_word_is_not_cold_outreach(policy_engine):
    sender = SenderStats(
        domain="colleague.example",
        total_emails=1,
        seen_emails=0,
        sample_subjects=["Meeting tomorrow"],
        authenticated_emails=1,
    )

    result = policy_engine.classify(sender)

    assert result.action is not Action.BLOCK
    assert result.email_type is not EmailType.COLD_OUTREACH


def test_protected_domain_is_review_not_a_terminal_keep(policy_engine):
    header = _parsed_fixture("protected_bank_marketing.eml")
    stats = _stats_for_emails(header.domain, [header])
    recommendation = Classification(
        email_type=EmailType.MARKETING,
        action=Action.UNSUB,
        confidence=0.95,
        reasoning="unwanted marketing",
        source="ai",
    )

    result = policy_engine._apply_action_policy(stats, recommendation)

    assert result.action is Action.REVIEW
    assert result.source == "safety_policy"


def test_malformed_duplicate_unsubscribe_headers_cannot_be_one_click():
    header = _parsed_fixture("malformed_unsubscribe.eml")

    assert header.normalized_list_id is None
    assert header.subscription_identity.kind == "from"
    assert header.list_unsubscribe_count == 2
    assert header.list_unsubscribe_post_count == 2
    assert header.has_compliant_one_click is False


def test_account_and_list_id_are_both_part_of_identity():
    base = EmailHeader(
        sender="news@example.com",
        subject="News",
        date=datetime.now(UTC),
        message_id="one",
        account_key="first@example.net",
        list_id="List <one.example.com>",
    )
    other_list = EmailHeader(**{**base.__dict__, "list_id": "List <two.example.com>"})
    other_account = EmailHeader(**{**base.__dict__, "account_key": "second@example.net"})

    assert (
        len(
            {
                base.subscription_identity.key,
                other_list.subscription_identity.key,
                other_account.subscription_identity.key,
            }
        )
        == 3
    )


def test_gmail_and_standard_flags_are_consumed_with_conflict_visible():
    header = _parsed_fixture("authenticated_subscription.eml")
    header.keywords = ("$Junk", "$NotJunk", "$canunsubscribe")
    header.gmail_labels = (r"\Spam",)

    assert header.server_junk is True
    assert header.server_not_junk is True
    assert header.server_can_unsubscribe is True


def test_conflicting_junk_flags_require_review(policy_engine):
    sender = SenderStats(
        domain="mixed.example",
        total_emails=1,
        junk_keyword_emails=1,
        not_junk_emails=1,
    )

    result = policy_engine.classify(sender)

    assert result.action is Action.REVIEW
    assert "conflicting" in result.reasoning.casefold()


def test_complete_auth_results_preserve_aligned_instances():
    verdicts = parse_authentication_results(
        [
            "mx.google.com; "
            "dkim=pass header.d=a.example header.s=one; "
            "dkim=pass header.d=b.example header.s=two; "
            "spf=softfail smtp.mailfrom=bounce@a.example; "
            "dmarc=temperror header.from=a.example"
        ],
        "gmail",
    )

    assert [item.result for item in verdicts.evidence.results] == [
        AuthResult.PASS,
        AuthResult.PASS,
        AuthResult.SOFTFAIL,
        AuthResult.TEMPERROR,
    ]
    assert verdicts.evidence.results[0].domain == "a.example"
    assert verdicts.evidence.results[0].selector == "one"
    # Do not cross-pair a passing domain from one result with another selector.
    signature = "v=1; d=a.example; s=two; h=from:list-unsubscribe:list-unsubscribe-post; bh=x; b=x"
    assert dkim_covers_unsubscribe([signature], verdicts) is False


def test_microsoft_scl_is_trusted_only_for_outlook():
    message = email.message_from_string("X-Forefront-Antispam-Report: CAT:NONE;SCL:6;BCL:7;\n\n")

    assert parse_provider_signals(message, "outlook").threat == "SCL:6"
    assert parse_provider_signals(message, "gmail").threat is None

    standalone = email.message_from_string("X-MS-Exchange-Organization-SCL: 9\n\n")
    assert parse_provider_signals(standalone, "outlook").threat == "SCL:9"


def test_unrelated_personal_headers_never_reach_ai(policy_engine):
    sender = SenderStats(
        domain="friend.example",
        total_emails=2,
        seen_emails=2,
        sample_subjects=["Dinner next week?"],
    )
    policy_engine.ai.is_available = Mock(return_value=True)
    policy_engine.ai.classify_batch = Mock(return_value={})

    policy_engine.classify_batch([sender], persist=False)

    policy_engine.ai.classify_batch.assert_not_called()


def test_ai_block_with_unknown_authentication_is_review_only(policy_engine):
    sender = SenderStats(
        domain="bulk.example",
        total_emails=10,
        has_unsubscribe=True,
        list_id="list.bulk.example",
    )
    policy_engine.ai.is_available = Mock(return_value=True)
    policy_engine.ai.classify_single = Mock(
        return_value=Classification(
            email_type=EmailType.MARKETING,
            action=Action.BLOCK,
            confidence=0.99,
            reasoning="unwanted",
            source="ai",
        )
    )

    result = policy_engine.classify(sender)

    assert result.action is Action.REVIEW
    assert result.source == "auth_policy"


def test_policy_transformation_preserves_original_ai_recommendation(policy_engine):
    sender = SenderStats(
        domain="marketing.example",
        total_emails=10,
        has_unsubscribe=True,
    )
    ai_result = Classification(
        email_type=EmailType.MARKETING,
        action=Action.UNSUB,
        confidence=0.97,
        reasoning="unwanted",
        source="ai",
        recommended_action=Action.UNSUB,
        original_source="ai",
    )

    result = policy_engine._apply_action_policy(sender, ai_result)

    assert result.action is Action.REVIEW
    assert result.recommended_action is Action.UNSUB
    assert result.original_source == "ai"
