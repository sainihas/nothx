"""Tests for unsubscribe execution."""

import tempfile
import urllib.error
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db, unsubscriber
from nothx.config import Config
from nothx.models import EmailHeader, SenderStatus, UnsubMethod
from nothx.safefetch import FetchResponse, SSRFBlockedError
from nothx.unsubscriber import (
    UnsafeUnsubscribeError,
    _check_confirmation_indicators,
    _check_success_indicators,
    _get_smtp_config,
    _has_one_click,
    unsubscribe,
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            yield db_path


@pytest.fixture(autouse=True)
def fast_rate_limiter(monkeypatch):
    """Never wait on the rate limiter in tests."""
    monkeypatch.setattr(
        unsubscriber._http_rate_limiter, "acquire", lambda timeout=None: True
    )


def make_header(
    sender: str = "deals@shop.com",
    list_unsubscribe: str | None = "<https://shop.com/unsub>",
    list_unsubscribe_post: str | None = None,
) -> EmailHeader:
    return EmailHeader(
        sender=sender,
        subject="Sale",
        date=datetime(2026, 1, 1),
        message_id="<x@shop.com>",
        list_unsubscribe=list_unsubscribe,
        list_unsubscribe_post=list_unsubscribe_post,
    )


def fake_fetch(status: int = 200, body: str = "", url: str = "https://shop.com/unsub"):
    def _fetch(u, **kwargs):
        return FetchResponse(status=status, body=body, final_url=u, redirects=0)

    return _fetch


class TestOneClickDetection:
    def test_correct_value(self):
        header = make_header(list_unsubscribe_post="List-Unsubscribe=One-Click")
        assert _has_one_click(header) is True

    def test_case_insensitive(self):
        header = make_header(list_unsubscribe_post="list-unsubscribe=one-click")
        assert _has_one_click(header) is True

    def test_wrong_value_rejected(self):
        """Mere presence of the header is not enough (RFC 8058)."""
        header = make_header(list_unsubscribe_post="No")
        assert _has_one_click(header) is False

    def test_absent(self):
        assert _has_one_click(make_header()) is False


class TestOneClickExecution:
    def test_post_2xx_succeeds(self, temp_db, monkeypatch):
        captured = {}

        def _fetch(url, **kwargs):
            captured.update(kwargs, url=url)
            return FetchResponse(status=200, body="", final_url=url, redirects=0)

        monkeypatch.setattr(unsubscriber, "safe_fetch", _fetch)
        header = make_header(list_unsubscribe_post="List-Unsubscribe=One-Click")
        result = unsubscribe(header, Config())

        assert result.success is True
        assert result.method == UnsubMethod.ONE_CLICK
        # Exact RFC 8058 semantics
        assert captured["method"] == "POST"
        assert captured["data"] == b"List-Unsubscribe=One-Click"
        assert captured["follow_redirects"] is False
        assert captured["allow_http"] is False

    def test_post_ignores_success_phrases_in_body(self, temp_db, monkeypatch):
        """One-click success is 2xx only; body text is irrelevant."""
        monkeypatch.setattr(
            unsubscriber, "safe_fetch", fake_fetch(status=200, body="click here to confirm")
        )
        header = make_header(list_unsubscribe_post="List-Unsubscribe=One-Click")
        assert unsubscribe(header, Config()).success is True

    def test_no_get_fallback_on_oneclick_url(self, temp_db, monkeypatch):
        """When the one-click POST fails, we must not GET the same URL."""
        calls = []

        def _fetch(url, **kwargs):
            calls.append((kwargs.get("method", "GET"), url))
            raise urllib.error.HTTPError(url, 400, "bad", {}, None)

        monkeypatch.setattr(unsubscriber, "safe_fetch", _fetch)
        header = make_header(list_unsubscribe_post="List-Unsubscribe=One-Click")
        result = unsubscribe(header, Config())

        assert result.success is False
        assert calls == [("POST", "https://shop.com/unsub")]

    def test_wrong_post_value_falls_through_to_get(self, temp_db, monkeypatch):
        calls = []

        def _fetch(url, **kwargs):
            calls.append(kwargs.get("method", "GET"))
            return FetchResponse(
                status=200, body="you have been unsubscribed", final_url=url, redirects=0
            )

        monkeypatch.setattr(unsubscriber, "safe_fetch", _fetch)
        header = make_header(list_unsubscribe_post="Maybe")
        result = unsubscribe(header, Config())

        assert calls == ["GET"]
        assert result.success is True
        assert result.method == UnsubMethod.GET


class TestGetExecution:
    def test_200_alone_is_not_success(self, temp_db, monkeypatch):
        monkeypatch.setattr(unsubscriber, "safe_fetch", fake_fetch(status=200, body="Welcome!"))
        result = unsubscribe(make_header(), Config())
        assert result.success is False

    def test_200_with_positive_phrase_succeeds(self, temp_db, monkeypatch):
        monkeypatch.setattr(
            unsubscriber,
            "safe_fetch",
            fake_fetch(status=200, body="You have been unsubscribed."),
        )
        result = unsubscribe(make_header(), Config())
        assert result.success is True

    def test_confirmation_page_detected(self, temp_db, monkeypatch):
        monkeypatch.setattr(
            unsubscriber,
            "safe_fetch",
            fake_fetch(status=200, body="Are you sure? Click the button to unsubscribe."),
        )
        result = unsubscribe(make_header(), Config())
        assert result.success is False
        assert result.needs_confirmation is True

    def test_ssrf_blocked_reported(self, temp_db, monkeypatch):
        def _fetch(url, **kwargs):
            raise SSRFBlockedError("Host resolves to forbidden address 127.0.0.1")

        monkeypatch.setattr(unsubscriber, "safe_fetch", _fetch)
        result = unsubscribe(make_header(), Config())
        assert result.success is False
        assert "Blocked unsafe URL" in (result.error or "")


class TestAttemptLogging:
    def test_failure_is_logged(self, temp_db, monkeypatch):
        monkeypatch.setattr(unsubscriber, "safe_fetch", fake_fetch(status=200, body="nope"))
        unsubscribe(make_header(), Config())

        with db.get_db() as conn:
            rows = conn.execute("SELECT * FROM unsub_log").fetchall()
        assert len(rows) == 1
        assert rows[0]["success"] == 0

        sender = db.get_sender("shop.com")
        assert sender is None or sender.get("status") != "unsubscribed"

    def test_each_target_logged(self, temp_db, monkeypatch):
        monkeypatch.setattr(unsubscriber, "safe_fetch", fake_fetch(status=200, body="nope"))
        header = make_header(
            list_unsubscribe="<https://a.shop.com/u>, <https://b.shop.com/u>"
        )
        unsubscribe(header, Config())

        with db.get_db() as conn:
            rows = conn.execute("SELECT * FROM unsub_log").fetchall()
        assert len(rows) == 2

    def test_status_set_once_after_success(self, temp_db, monkeypatch):
        monkeypatch.setattr(
            unsubscriber, "safe_fetch", fake_fetch(status=200, body="no longer receive")
        )
        db.upsert_sender("shop.com", 5, 0, ["Sale"], True)
        unsubscribe(make_header(), Config())
        assert db.get_sender("shop.com")["status"] == "unsubscribed"

    def test_no_method_available_logged(self, temp_db):
        result = unsubscribe(make_header(list_unsubscribe=None), Config())
        assert result.success is False
        assert "No unsubscribe method" in (result.error or "")


class TestProtectedDomains:
    def test_protected_domain_raises(self, temp_db):
        header = make_header(sender="offers@mybank.com")
        with pytest.raises(UnsafeUnsubscribeError):
            unsubscribe(header, Config())

    def test_gov_protected(self, temp_db):
        header = make_header(sender="noreply@irs.gov")
        with pytest.raises(UnsafeUnsubscribeError):
            unsubscribe(header, Config())


class TestMailto:
    def test_mailto_preferred_over_get(self, temp_db, monkeypatch):
        """Mailto is attempted before GET (GET links are the risky ones)."""
        get_calls = []
        monkeypatch.setattr(
            unsubscriber,
            "safe_fetch",
            lambda url, **kw: get_calls.append(url),
        )
        sent = {}

        def fake_mailto(mailto, account, config):
            sent["mailto"] = mailto
            from nothx.models import UnsubResult

            return UnsubResult(success=True, method=UnsubMethod.MAILTO)

        monkeypatch.setattr(unsubscriber, "_execute_mailto", fake_mailto)
        from nothx.config import AccountConfig

        header = make_header(
            list_unsubscribe="<https://shop.com/unsub>, <mailto:unsub@shop.com>"
        )
        account = AccountConfig(provider="gmail", email="me@x.com", password="pw")
        result = unsubscribe(header, Config(), account)

        assert result.method == UnsubMethod.MAILTO
        assert sent["mailto"] == "mailto:unsub@shop.com"
        assert get_calls == []

    def test_invalid_mailto_address(self, temp_db):
        from nothx.config import AccountConfig

        account = AccountConfig(provider="gmail", email="me@x.com", password="pw")
        result = unsubscriber._execute_mailto("mailto:not-an-address", account, Config())
        assert result.success is False
        assert "Invalid mailto address" in (result.error or "")

    def test_mailto_params_preserved(self, temp_db, monkeypatch):
        sent = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def ehlo(self):
                pass

            def starttls(self, context=None):
                pass

            def login(self, *args):
                pass

            def send_message(self, msg):
                sent["subject"] = msg["Subject"]
                sent["to"] = msg["To"]

        monkeypatch.setattr(unsubscriber.smtplib, "SMTP_SSL", FakeSMTP)
        from nothx.config import AccountConfig

        account = AccountConfig(provider="gmail", email="me@x.com", password="pw")
        result = unsubscriber._execute_mailto(
            "mailto:unsub@shop.com?subject=remove%20me", account, Config()
        )
        assert result.success is True
        assert sent["to"] == "unsub@shop.com"
        assert sent["subject"] == "remove me"

    def test_header_injection_stripped(self, temp_db, monkeypatch):
        sent = {}

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def login(self, *args):
                pass

            def send_message(self, msg):
                sent["subject"] = msg["Subject"]

        monkeypatch.setattr(unsubscriber.smtplib, "SMTP_SSL", FakeSMTP)
        from nothx.config import AccountConfig

        account = AccountConfig(provider="gmail", email="me@x.com", password="pw")
        result = unsubscriber._execute_mailto(
            "mailto:unsub@shop.com?subject=hi%0d%0aBcc:victim@x.com", account, Config()
        )
        assert result.success is True
        assert "\n" not in sent["subject"]
        assert "\r" not in sent["subject"]


class TestSmtpConfig:
    def test_outlook_uses_starttls_587(self):
        server, port, starttls = _get_smtp_config("outlook")
        assert port == 587
        assert starttls is True

    def test_unknown_provider_raises(self):
        with pytest.raises(unsubscriber.InvalidProviderError):
            _get_smtp_config("fastmail")


class TestIndicators:
    def test_success_phrases(self):
        assert _check_success_indicators("You have been UNSUBSCRIBED successfully")
        assert not _check_success_indicators("Welcome to our newsletter")

    def test_removed_from_requires_context(self):
        """Bare 'removed from' was a false-positive source."""
        assert not _check_success_indicators("Email removed from spam filter backlog")
        assert _check_success_indicators("Your address has been removed from our list")

    def test_confirmation_phrases(self):
        assert _check_confirmation_indicators("Please confirm your choice")
        assert _check_confirmation_indicators("Are you sure you want to leave?")
        assert not _check_confirmation_indicators("You have been unsubscribed")
