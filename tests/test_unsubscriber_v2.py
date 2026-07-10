"""Focused coverage for subscription-level unsubscribe execution."""

from __future__ import annotations

import logging
import smtplib
import urllib.error
from datetime import UTC, datetime, timedelta
from email.mime.text import MIMEText

import pytest

from nothx import unsubscriber
from nothx.config import AccountConfig, Config
from nothx.models import (
    AuthenticationEvidence,
    AuthResult,
    EmailHeader,
    FooterUnsubscribeCandidate,
    UnsubMethod,
    UnsubResult,
    UnsubscribeOutcome,
)
from nothx.safefetch import FetchResponse, ResolutionError, redacted_url


@pytest.fixture(autouse=True)
def no_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(unsubscriber._http_rate_limiter, "acquire", lambda timeout=None: True)


def consented_config() -> Config:
    return Config(unsubscribe_consent_version=unsubscriber.AUTOMATION_CONSENT_VERSION)


def trusted_auth() -> AuthenticationEvidence:
    return AuthenticationEvidence(
        dkim=AuthResult.PASS,
        dkim_domains=("mailer.example",),
        trusted=True,
    )


def header(
    url: str | None = "https://mailer.example/unsubscribe/token",
    *,
    days: int = 0,
    authenticated: bool = True,
    one_click: bool = False,
    can_unsubscribe: bool = False,
    footer: tuple[FooterUnsubscribeCandidate, ...] = (),
    uid: int | None = None,
    received_days: int | None = None,
) -> EmailHeader:
    return EmailHeader(
        sender="offers@mailer.example",
        subject="Offers",
        date=datetime(2026, 7, 1, tzinfo=UTC) + timedelta(days=days),
        received_at=(
            datetime(2026, 7, 1, tzinfo=UTC) + timedelta(days=received_days)
            if received_days is not None
            else None
        ),
        message_id=f"<{days}@mailer.example>",
        account_key="me@example.net",
        mailbox_name="INBOX",
        uidvalidity=123 if uid is not None else None,
        uid=uid,
        list_unsubscribe=f"<{url}>" if url else None,
        list_unsubscribe_post="List-Unsubscribe=One-Click" if one_click else None,
        list_unsubscribe_count=1 if url else 0,
        list_unsubscribe_post_count=1 if one_click else 0,
        keywords=("$canunsubscribe",) if can_unsubscribe else (),
        authentication=trusted_auth() if authenticated else AuthenticationEvidence(),
        footer_unsubscribe_candidates=footer,
    )


def failure(method: UnsubMethod) -> UnsubResult:
    return UnsubResult(success=False, method=method, error="safe failure")


class TestAutomaticGates:
    def test_missing_durable_consent_makes_no_request(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        monkeypatch.setattr(unsubscriber, "safe_fetch", lambda url, **kw: calls.append(url))

        result = unsubscriber.unsubscribe_subscription(
            [header(one_click=True, can_unsubscribe=True)], Config()
        )

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert calls == []

    def test_unknown_future_consent_version_does_not_authorize(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        monkeypatch.setattr(unsubscriber, "safe_fetch", lambda url, **kw: calls.append(url))
        config = Config(unsubscribe_consent_version=unsubscriber.AUTOMATION_CONSENT_VERSION + 1)

        result = unsubscriber.unsubscribe_subscription(
            [header(one_click=True, can_unsubscribe=True)], config
        )

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert calls == []

    @pytest.mark.parametrize(
        ("changes", "expected_method"),
        [
            ({"list_unsubscribe_count": 2}, "GET"),
            ({"list_unsubscribe_post_count": 2}, "GET"),
            ({"list_unsubscribe_post": "List-Unsubscribe=No"}, "GET"),
            ({"list_unsubscribe": "https://mailer.example/unsubscribe/token"}, "GET"),
            ({"list_unsubscribe": "<http://mailer.example/unsubscribe/token>"}, None),
            (
                {"list_unsubscribe": ("<https://mailer.example/a>, <https://mailer.example/b>")},
                "GET",
            ),
        ],
    )
    def test_malformed_one_click_is_never_posted(
        self,
        monkeypatch: pytest.MonkeyPatch,
        changes: dict[str, object],
        expected_method: str | None,
    ) -> None:
        item = header(one_click=True, can_unsubscribe=True)
        for name, value in changes.items():
            setattr(item, name, value)
        calls: list[str] = []

        def fake_fetch(url: str, **kwargs):
            calls.append(kwargs["method"])
            return FetchResponse(400, "", url, 0)

        monkeypatch.setattr(unsubscriber, "safe_fetch", fake_fetch)
        unsubscriber.unsubscribe_subscription([item], consented_config())

        assert "POST" not in calls
        if expected_method:
            assert calls and set(calls) == {expected_method}
        else:
            assert calls == []

    def test_one_click_requires_server_or_covering_dkim_evidence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        item = header(one_click=True, authenticated=False)
        calls: list[str] = []
        monkeypatch.setattr(unsubscriber, "safe_fetch", lambda url, **kw: calls.append(url))

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert calls == []

    def test_covering_but_unaligned_dkim_cannot_authorize_one_click(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        item = header(one_click=True, authenticated=False)
        item.dkim_covers_unsubscribe = True
        item.authentication = AuthenticationEvidence(
            dkim=AuthResult.PASS,
            dkim_domains=("attacker.example",),
            trusted=True,
        )
        calls: list[str] = []
        monkeypatch.setattr(unsubscriber, "safe_fetch", lambda url, **kw: calls.append(url))

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert calls == []

    @pytest.mark.parametrize("evidence", ["keyword", "dkim"])
    def test_compliant_one_click_posts_exact_body(
        self,
        monkeypatch: pytest.MonkeyPatch,
        evidence: str,
    ) -> None:
        item = header(
            one_click=True,
            can_unsubscribe=evidence == "keyword",
            authenticated=False,
            uid=9,
        )
        item.dkim_covers_unsubscribe = evidence == "dkim"
        if evidence == "dkim":
            item.authentication = trusted_auth()
        captured: dict[str, object] = {}

        def fake_fetch(url: str, **kwargs):
            captured.update(kwargs)
            return FetchResponse(204, "secret response", url, 0)

        monkeypatch.setattr(unsubscriber, "safe_fetch", fake_fetch)
        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert result.outcome is UnsubscribeOutcome.REQUESTED
        assert captured["method"] == "POST"
        assert captured["data"] == b"List-Unsubscribe=One-Click"
        assert captured["allow_http"] is False
        assert captured["follow_redirects"] is False
        assert result.response_snippet is None
        assert result.attempt_results[0].message_ref == item.message_ref

    @pytest.mark.parametrize(
        "signals",
        [
            {"keywords": ("$Junk",)},
            {"keywords": ("$Phishing",)},
            {"mailbox_role": "junk"},
            {"provider_threat": "phishing"},
        ],
    )
    def test_junk_or_phishing_is_blocked_with_zero_network(
        self,
        monkeypatch: pytest.MonkeyPatch,
        signals: dict[str, object],
    ) -> None:
        item = header(one_click=True, can_unsubscribe=True)
        for name, value in signals.items():
            setattr(item, name, value)
        calls: list[str] = []
        monkeypatch.setattr(unsubscriber, "safe_fetch", lambda url, **kw: calls.append(url))

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert result.outcome is UnsubscribeOutcome.BLOCKED
        assert calls == []

    def test_unknown_authentication_is_review_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        item = header(authenticated=False)
        calls: list[str] = []
        monkeypatch.setattr(unsubscriber, "safe_fetch", lambda url, **kw: calls.append(url))

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert result.needs_confirmation
        assert calls == []

    def test_unaligned_dkim_pass_is_review_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        item = header()
        item.authentication = AuthenticationEvidence(
            dkim=AuthResult.PASS,
            dkim_domains=("attacker.example",),
            trusted=True,
        )
        calls: list[str] = []
        monkeypatch.setattr(unsubscriber, "safe_fetch", lambda url, **kw: calls.append(url))

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert calls == []

    def test_trusted_dmarc_pass_allows_legacy_https_get(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        item = header()
        item.authentication = AuthenticationEvidence(dmarc=AuthResult.PASS, trusted=True)
        calls: list[str] = []
        monkeypatch.setattr(
            unsubscriber,
            "_execute_get",
            lambda url: calls.append(url) or UnsubResult(True, UnsubMethod.GET),
        )

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert result.outcome is UnsubscribeOutcome.REQUESTED
        assert calls == ["https://mailer.example/unsubscribe/token"]


class TestPlanning:
    def test_tiers_and_message_recency_are_stable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        newest = header("https://mailer.example/new", days=3)
        one_click = header(
            "https://mailer.example/one-click",
            days=2,
            one_click=True,
            can_unsubscribe=True,
        )
        footer_item = header(
            None,
            days=1,
            footer=(FooterUnsubscribeCandidate("https://mailer.example/footer", "html"),),
        )
        too_old = header(
            "https://mailer.example/old",
            days=0,
            one_click=True,
            can_unsubscribe=True,
        )
        calls: list[tuple[UnsubMethod, str]] = []

        def one_click_call(url: str) -> UnsubResult:
            calls.append((UnsubMethod.ONE_CLICK, url))
            return failure(UnsubMethod.ONE_CLICK)

        def get_call(url: str) -> UnsubResult:
            calls.append((UnsubMethod.GET, url))
            return failure(UnsubMethod.GET)

        monkeypatch.setattr(unsubscriber, "_execute_one_click", one_click_call)
        monkeypatch.setattr(unsubscriber, "_execute_get", get_call)

        unsubscriber.unsubscribe_subscription(
            [footer_item, too_old, newest, one_click], consented_config()
        )

        assert calls == [
            (UnsubMethod.ONE_CLICK, "https://mailer.example/one-click"),
            (UnsubMethod.GET, "https://mailer.example/new"),
            (UnsubMethod.GET, "https://mailer.example/footer"),
        ]

    def test_server_received_time_outranks_sender_date(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        future_dated_old = header(
            "https://mailer.example/old",
            days=100,
            received_days=1,
        )
        genuinely_new = header(
            "https://mailer.example/new",
            days=0,
            received_days=2,
        )
        calls: list[str] = []
        monkeypatch.setattr(
            unsubscriber,
            "_execute_get",
            lambda url: calls.append(url) or failure(UnsubMethod.GET),
        )

        unsubscriber.unsubscribe_subscription([future_dated_old, genuinely_new], consented_config())

        assert calls == [
            "https://mailer.example/new",
            "https://mailer.example/old",
        ]

    def test_five_distinct_endpoint_cap_and_dedup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        items = []
        for day in range(3):
            urls = ", ".join(f"<https://mailer.example/{day}-{index}>" for index in range(3))
            item = header(None, days=day)
            item.list_unsubscribe = urls
            item.list_unsubscribe_count = 1
            items.append(item)
        items[2].list_unsubscribe += ", <https://mailer.example/2-0>"
        calls: list[str] = []

        def get_call(url: str) -> UnsubResult:
            calls.append(url)
            return failure(UnsubMethod.GET)

        monkeypatch.setattr(unsubscriber, "_execute_get", get_call)
        result = unsubscriber.unsubscribe_subscription(items, consented_config())

        assert len(calls) == 5
        assert len(set(calls)) == 5
        assert result.attempts == 5
        assert len(result.attempt_results) == 5

    def test_footer_is_get_only_and_http_is_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        item = header(
            None,
            footer=(
                FooterUnsubscribeCandidate("https://mailer.example/footer-token", "html"),
                FooterUnsubscribeCandidate("http://mailer.example/insecure", "plain"),
            ),
        )
        get_calls: list[str] = []
        post_calls: list[str] = []
        monkeypatch.setattr(
            unsubscriber,
            "_execute_get",
            lambda url: get_calls.append(url) or failure(UnsubMethod.GET),
        )
        monkeypatch.setattr(
            unsubscriber,
            "_execute_one_click",
            lambda url: post_calls.append(url) or failure(UnsubMethod.ONE_CLICK),
        )

        unsubscriber.unsubscribe_subscription([item], consented_config())

        assert get_calls == ["https://mailer.example/footer-token"]
        assert post_calls == []

    def test_footer_form_without_candidate_needs_user(self) -> None:
        item = header(None)
        item.footer_requires_user = True

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert result.needs_confirmation

    def test_footer_form_with_candidate_never_automates_footer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        item = header(
            None,
            footer=(
                FooterUnsubscribeCandidate("https://mailer.example/form-adjacent-token", "html"),
            ),
        )
        item.footer_requires_user = True
        calls: list[str] = []
        monkeypatch.setattr(
            unsubscriber,
            "_execute_get",
            lambda url: calls.append(url) or UnsubResult(True, UnsubMethod.GET),
        )

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert calls == []
        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert result.needs_confirmation

    def test_footer_form_does_not_suppress_safe_header_method(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        header_target = "https://mailer.example/header-token"
        footer_target = "https://mailer.example/form-adjacent-token"
        item = header(
            header_target,
            footer=(FooterUnsubscribeCandidate(footer_target, "html"),),
        )
        item.footer_requires_user = True
        calls: list[str] = []
        monkeypatch.setattr(
            unsubscriber,
            "_execute_get",
            lambda url: calls.append(url) or UnsubResult(True, UnsubMethod.GET),
        )

        result = unsubscriber.unsubscribe_subscription([item], consented_config())

        assert calls == [header_target]
        assert result.outcome is UnsubscribeOutcome.REQUESTED

    def test_accepted_fingerprint_is_skipped_for_fresh_alternate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        first = "https://mailer.example/old-token"
        second = "https://mailer.example/new-token"
        item = header(None, uid=44)
        item.list_unsubscribe = f"<{first}>, <{second}>"
        item.list_unsubscribe_count = 1
        calls: list[str] = []
        monkeypatch.setattr(
            unsubscriber,
            "_execute_get",
            lambda url: calls.append(url) or UnsubResult(True, UnsubMethod.GET),
        )

        result = unsubscriber.unsubscribe_subscription(
            [item],
            consented_config(),
            exclude_fingerprints={unsubscriber._endpoint_fingerprint(first).hex()},
        )

        assert calls == [second]
        assert [attempt.outcome for attempt in result.attempt_results] == [
            "skipped",
            "accepted",
        ]
        assert result.attempt_results[0].error_code == "endpoint_already_accepted"
        assert result.attempt_results[1].message_ref == item.message_ref


class TestHTTPExecution:
    def test_retry_after_is_bounded_and_transient_status_retries(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0
        sleeps: list[float] = []

        def fake_fetch(url: str, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise urllib.error.HTTPError(
                    url,
                    429,
                    "rate limited",
                    {"Retry-After": "999"},
                    None,
                )
            return FetchResponse(204, "", url, 0)

        monkeypatch.setattr(unsubscriber, "safe_fetch", fake_fetch)
        monkeypatch.setattr(unsubscriber.time, "sleep", sleeps.append)

        result = unsubscriber._execute_get("https://mailer.example/u?secret=token")

        assert result.success
        assert calls == 2
        assert sleeps == [unsubscriber.MAX_RETRY_AFTER]

    def test_dns_resolution_failures_are_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = 0

        def fake_fetch(url: str, **kwargs):
            nonlocal calls
            calls += 1
            if calls < 3:
                raise ResolutionError("temporary resolver failure")
            return FetchResponse(204, "", url, 0)

        monkeypatch.setattr(unsubscriber, "safe_fetch", fake_fetch)
        monkeypatch.setattr(unsubscriber.time, "sleep", lambda seconds: None)

        result = unsubscriber._execute_get("https://mailer.example/u")

        assert result.success
        assert calls == 3

    def test_permanent_4xx_is_not_retried(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = 0

        def fake_fetch(url: str, **kwargs):
            nonlocal calls
            calls += 1
            raise urllib.error.HTTPError(url, 410, "gone", {}, None)

        monkeypatch.setattr(unsubscriber, "safe_fetch", fake_fetch)

        result = unsubscriber._execute_one_click("https://mailer.example/u?secret=token")

        assert calls == 1
        assert result.http_status == 410
        assert result.error == "HTTP 410"

    def test_result_and_logs_never_expose_url_or_body(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        secret_url = "https://mailer.example/opaque-path-token?recipient=private-token"
        secret_body = "private response body"
        monkeypatch.setattr(
            unsubscriber,
            "safe_fetch",
            lambda url, **kw: FetchResponse(200, secret_body, url, 0),
        )

        with caplog.at_level(logging.DEBUG):
            result = unsubscriber.unsubscribe_subscription([header(secret_url)], consented_config())

        exported = repr(result) + caplog.text
        assert "private-token" not in exported
        assert "opaque-path-token" not in exported
        assert secret_body not in exported
        assert result.target_display == redacted_url(secret_url)
        assert result.response_snippet is None

    def test_forms_and_preference_centers_need_user(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            unsubscriber,
            "safe_fetch",
            lambda url, **kw: FetchResponse(
                200,
                "<form>Manage preferences</form>",
                url,
                0,
            ),
        )

        result = unsubscriber.unsubscribe_subscription([header()], consented_config())

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert result.attempt_results[0].outcome == "needs_user"


class TestMailtoHardening:
    def account(self, **changes: object) -> AccountConfig:
        values: dict[str, object] = {
            "provider": "gmail",
            "email": "me@example.net",
            "password": "app-password",
        }
        values.update(changes)
        return AccountConfig(**values)  # type: ignore[arg-type]

    def test_mailto_display_masks_recipient_and_token_bearing_host(self) -> None:
        display = unsubscriber._redact_target(
            "mailto:recipient-secret@token-bearing.mailer.example?body=private"
        )

        assert display.startswith("mailto:*@host-")
        assert "recipient-secret" not in display
        assert "token-bearing" not in display
        assert "mailer.example" not in display
        assert "private" not in display

    @pytest.mark.parametrize(
        "target",
        [
            "mailto:unsub@mailer.example?cc=attacker@example.org",
            "mailto:unsub@mailer.example?subject=a&subject=b",
            "mailto:unsub@mailer.example?subject=bad%ZZ",
            "mailto:unsub@mailer.example,attacker@example.org",
            "mailto:Name%20%3Cattacker@example.org%3E",
            "mailto:unsub@mailer.example?subject=hi%0d%0aBcc:x@example.org",
        ],
    )
    def test_rejects_unsafe_mailto_without_sending(
        self, monkeypatch: pytest.MonkeyPatch, target: str
    ) -> None:
        calls: list[MIMEText] = []
        monkeypatch.setattr(
            unsubscriber,
            "_send_mailto_message",
            lambda message, account: calls.append(message),
        )

        result = unsubscriber._execute_mailto(target, self.account(), Config())

        assert not result.success
        assert calls == []
        assert "attacker" not in (result.error or "")

    def test_builds_bounded_message_with_required_headers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent: list[MIMEText] = []
        monkeypatch.setattr(
            unsubscriber,
            "_send_mailto_message",
            lambda message, account: sent.append(message),
        )

        result = unsubscriber._execute_mailto(
            "mailto:unsub@mailer.example?subject=remove%20me&body=unsubscribe",
            self.account(),
            Config(),
        )

        assert result.success
        assert result.response_snippet is None
        assert sent[0]["To"] == "unsub@mailer.example"
        assert sent[0]["Subject"] == "remove me"
        assert sent[0]["Auto-Submitted"] == "auto-generated"
        assert sent[0]["Date"]
        assert sent[0]["Message-ID"]

    def test_pre_send_network_failure_retries_with_fresh_connection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        constructions = 0
        sends = 0

        class FakeSMTP:
            def login(self, email: str, password: str) -> None:
                pass

            def send_message(self, message: MIMEText) -> None:
                nonlocal sends
                sends += 1

            def quit(self) -> None:
                pass

            def close(self) -> None:
                pass

        def factory(*args, **kwargs):
            nonlocal constructions
            constructions += 1
            if constructions == 1:
                raise TimeoutError("pre-send timeout")
            return FakeSMTP()

        monkeypatch.setattr(unsubscriber.smtplib, "SMTP_SSL", factory)
        monkeypatch.setattr(unsubscriber.time, "sleep", lambda seconds: None)

        unsubscriber._send_mailto_message(MIMEText("unsubscribe"), self.account())

        assert constructions == 2
        assert sends == 1

    def test_send_failure_is_ambiguous_and_never_retried(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        constructions = 0
        sends = 0

        class FakeSMTP:
            def login(self, email: str, password: str) -> None:
                pass

            def send_message(self, message: MIMEText) -> None:
                nonlocal sends
                sends += 1
                raise TimeoutError("may already be accepted")

            def quit(self) -> None:
                pass

            def close(self) -> None:
                pass

        def factory(*args, **kwargs):
            nonlocal constructions
            constructions += 1
            return FakeSMTP()

        monkeypatch.setattr(unsubscriber.smtplib, "SMTP_SSL", factory)

        result = unsubscriber._execute_mailto(
            "mailto:unsub@mailer.example", self.account(), Config()
        )

        assert not result.success
        assert result.needs_confirmation
        assert constructions == 1
        assert sends == 1

    def test_ambiguous_mailto_stops_subscription_fallbacks(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        item = header(None)
        item.list_unsubscribe = "<mailto:unsub@mailer.example>, <https://mailer.example/alternate>"
        get_calls: list[str] = []
        monkeypatch.setattr(
            unsubscriber,
            "_execute_mailto",
            lambda target, account, config: unsubscriber._mark_attempt(
                UnsubResult(
                    False,
                    UnsubMethod.MAILTO,
                    needs_confirmation=True,
                    error="ambiguous",
                ),
                "ambiguous",
                "smtp_ambiguous_send",
                ambiguous_send=True,
            ),
        )
        monkeypatch.setattr(
            unsubscriber,
            "_execute_get",
            lambda target: get_calls.append(target) or failure(UnsubMethod.GET),
        )

        result = unsubscriber.unsubscribe_subscription(
            [item], consented_config(), account=self.account()
        )

        assert result.outcome is UnsubscribeOutcome.NEEDS_USER
        assert result.attempt_results[0].outcome == "ambiguous"
        assert result.attempt_results[0].ambiguous_send
        assert get_calls == []

    def test_oauth_auth_failure_refreshes_once_on_new_connection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        instances: list[FakeOAuthSMTP] = []
        token_calls: list[bool] = []

        class FakeOAuthSMTP:
            def __init__(self, fail_auth: bool):
                self.fail_auth = fail_auth
                self.closed = False
                self.initial_response_ok: bool | None = None
                self.response = ""

            def ehlo(self) -> None:
                pass

            def starttls(self, context=None) -> None:
                pass

            def auth(self, mechanism, callback, initial_response_ok=False) -> None:
                self.initial_response_ok = initial_response_ok
                self.response = callback()
                if self.fail_auth:
                    raise smtplib.SMTPAuthenticationError(535, b"bad token")

            def send_message(self, message: MIMEText) -> None:
                pass

            def quit(self) -> None:
                self.closed = True

            def close(self) -> None:
                self.closed = True

        def smtp_factory(*args, **kwargs):
            instance = FakeOAuthSMTP(fail_auth=not instances)
            instances.append(instance)
            return instance

        def get_token(email: str, client_id: str, force_refresh: bool = False) -> str:
            token_calls.append(force_refresh)
            return "fresh-token" if force_refresh else "stale-token"

        monkeypatch.setattr(unsubscriber.smtplib, "SMTP", smtp_factory)
        monkeypatch.setattr(unsubscriber.msauth, "get_access_token", get_token)
        account = self.account(
            provider="outlook",
            password="",
            auth="oauth",
            client_id="client-id",
        )

        unsubscriber._send_mailto_message(MIMEText("unsubscribe"), account)

        assert token_calls == [False, True]
        assert len(instances) == 2
        assert all(instance.closed for instance in instances)
        assert instances[1].initial_response_ok is True
        assert "fresh-token" in instances[1].response
