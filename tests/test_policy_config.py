"""Tests for Commit 5: policy, config, and db-offender behavior."""

import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from nothx import db
from nothx.config import AccountConfig, Config
from nothx.logging import _redact
from nothx.models import EmailHeader, SenderStatus, UnsubMethod


@pytest.fixture
def temp_home():
    with tempfile.TemporaryDirectory() as tmpdir:
        home = Path(tmpdir)
        with patch("nothx.config.Path.home", return_value=home):
            yield home


class TestConfigPermissions:
    def test_dir_is_owner_only(self, temp_home):
        from nothx.config import get_config_dir

        d = get_config_dir()
        mode = stat.S_IMODE(d.stat().st_mode)
        assert mode == 0o700

    def test_config_file_is_owner_only(self, temp_home):
        config = Config(accounts={"main": AccountConfig("gmail", "me@x.com", "secret")})
        config.save()
        from nothx.config import get_config_path

        mode = stat.S_IMODE(get_config_path().stat().st_mode)
        assert mode == 0o600

    def test_overwrites_loose_permissions(self, temp_home):
        from nothx.config import get_config_path

        path = get_config_path()
        path.write_text("{}")
        path.chmod(0o644)
        Config().save()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


class TestLogRedaction:
    def test_sensitive_keys_redacted(self):
        assert _redact("password", "hunter2") == "***REDACTED***"
        assert _redact("api_key", "sk-abc") == "***REDACTED***"
        assert _redact("api-key", "sk-abc") == "***REDACTED***"
        assert _redact("auth_token", "t") == "***REDACTED***"
        assert _redact("client_secret", "s") == "***REDACTED***"

    def test_normal_keys_untouched(self):
        assert _redact("domain", "example.com") == "example.com"
        assert _redact("count", 5) == 5


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        with patch("nothx.db.get_db_path", return_value=db_path):
            db.init_db()
            yield db_path


class TestReviewRetry:
    """A manual 'unsub' choice must run a real attempt, not mislabel success."""

    def _sender_row(self):
        db.upsert_sender("shop.com", 10, 0, ["Sale"], True)
        db.update_sender_status("shop.com", SenderStatus.FAILED)
        return db.get_sender("shop.com")

    def test_failed_retry_that_fails_again_stays_failed(self, temp_db, monkeypatch):
        from nothx import cli
        from nothx.models import EmailHeader

        sender = self._sender_row()
        header = EmailHeader(
            sender="deals@shop.com",
            subject="Sale",
            date=datetime(2026, 1, 1),
            message_id="<x>",
            list_unsubscribe="<https://shop.com/u>",
        )
        monkeypatch.setattr("nothx.scanner.get_emails_for_domain", lambda *a, **k: [header])
        # The retry attempt fails (server 200 with no confirmation phrase)
        monkeypatch.setattr(
            "nothx.unsubscriber._http_rate_limiter.acquire", lambda timeout=None: True
        )
        from nothx.safefetch import FetchResponse

        monkeypatch.setattr(
            "nothx.unsubscriber.safe_fetch",
            lambda url, **k: FetchResponse(status=200, body="welcome", final_url=url, redirects=0),
        )
        config = Config(accounts={"main": AccountConfig("gmail", "me@x.com", "pw")})

        cli._change_sender_status("shop.com", "unsub", sender=sender, config=config)

        # NOT mislabeled as unsubscribed; stays failed and visible in review.
        assert db.get_sender("shop.com")["status"] == "failed"
        assert any(r["domain"] == "shop.com" for r in db.get_senders_for_review())

    def test_retry_success_marks_unsubscribed(self, temp_db, monkeypatch):
        from nothx import cli
        from nothx.models import EmailHeader
        from nothx.safefetch import FetchResponse

        sender = self._sender_row()
        header = EmailHeader(
            sender="deals@shop.com",
            subject="Sale",
            date=datetime(2026, 1, 1),
            message_id="<x>",
            list_unsubscribe="<https://shop.com/u>",
        )
        monkeypatch.setattr("nothx.scanner.get_emails_for_domain", lambda *a, **k: [header])
        monkeypatch.setattr(
            "nothx.unsubscriber._http_rate_limiter.acquire", lambda timeout=None: True
        )
        monkeypatch.setattr(
            "nothx.unsubscriber.safe_fetch",
            lambda url, **k: FetchResponse(
                status=200, body="you have been unsubscribed", final_url=url, redirects=0
            ),
        )
        config = Config(accounts={"main": AccountConfig("gmail", "me@x.com", "pw")})

        cli._change_sender_status("shop.com", "unsub", sender=sender, config=config)
        assert db.get_sender("shop.com")["status"] == "unsubscribed"

    def test_no_config_keeps_optimistic_behavior(self, temp_db):
        from nothx import cli

        sender = self._sender_row()
        cli._change_sender_status("shop.com", "unsub", sender=sender)  # no config
        # Without config, no network attempt — legacy optimistic status set.
        assert db.get_sender("shop.com")["status"] == "unsubscribed"


class TestPostUnsubOffenders:
    def test_detects_sender_still_mailing(self, temp_db):
        # Unsubscribed 30 days ago, but last_seen is now -> offender
        old = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        db.upsert_sender(
            "spam.com",
            total_emails=20,
            seen_emails=0,
            sample_subjects=["Deal"],
            has_unsubscribe=True,
            last_seen=datetime.now(UTC),
        )
        db.update_sender_status("spam.com", SenderStatus.UNSUBSCRIBED)
        with db.get_db() as conn:
            conn.execute(
                "INSERT INTO unsub_log (domain, attempted_at, success, method) VALUES (?, ?, 1, ?)",
                ("spam.com", old, UnsubMethod.ONE_CLICK.value),
            )
        offenders = db.get_post_unsub_offenders(grace_days=7)
        assert any(o["domain"] == "spam.com" for o in offenders)

    def test_within_grace_not_flagged(self, temp_db):
        # Unsubscribed recently; last_seen just after -> within grace, not an offender
        recent = datetime.now(UTC).isoformat()
        db.upsert_sender(
            "shop.com",
            total_emails=5,
            seen_emails=0,
            sample_subjects=["Sale"],
            has_unsubscribe=True,
            last_seen=datetime.now(UTC),
        )
        db.update_sender_status("shop.com", SenderStatus.UNSUBSCRIBED)
        with db.get_db() as conn:
            conn.execute(
                "INSERT INTO unsub_log (domain, attempted_at, success, method) VALUES (?, ?, 1, ?)",
                ("shop.com", recent, UnsubMethod.ONE_CLICK.value),
            )
        offenders = db.get_post_unsub_offenders(grace_days=7)
        assert not any(o["domain"] == "shop.com" for o in offenders)


class TestAuthGatedUnsubscribe:
    def test_auth_failure_blocks_fetch(self, temp_db, monkeypatch):
        from nothx import unsubscriber

        called = []
        monkeypatch.setattr(unsubscriber, "safe_fetch", lambda *a, **k: called.append(a))
        header = EmailHeader(
            sender="deals@shop.com",
            subject="Sale",
            date=datetime(2026, 1, 1),
            message_id="<x>",
            list_unsubscribe="<https://shop.com/u>",
            dkim_pass=False,  # explicit auth failure
        )
        result = unsubscriber.unsubscribe(header, Config())
        assert result.success is False
        assert "authentication" in (result.error or "").lower()
        assert called == []  # never fetched the URL

    def test_unknown_auth_allowed(self, temp_db, monkeypatch):
        from nothx import unsubscriber
        from nothx.safefetch import FetchResponse

        monkeypatch.setattr(unsubscriber._http_rate_limiter, "acquire", lambda timeout=None: True)
        monkeypatch.setattr(
            unsubscriber,
            "safe_fetch",
            lambda url, **k: FetchResponse(
                status=200, body="you have been unsubscribed", final_url=url, redirects=0
            ),
        )
        header = EmailHeader(
            sender="deals@shop.com",
            subject="Sale",
            date=datetime(2026, 1, 1),
            message_id="<x>",
            list_unsubscribe="<https://shop.com/u>",
            dkim_pass=None,  # unknown -> allowed
        )
        result = unsubscriber.unsubscribe(header, Config())
        assert result.success is True
