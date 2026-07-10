"""Tests for Microsoft consumer OAuth and token persistence."""

from __future__ import annotations

import base64
import json
import os
import stat
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs

import pytest

from nothx import msauth
from nothx.errors import (
    ErrorCode,
    OAuthCancelledError,
    OAuthError,
    OAuthReconsentRequired,
    OAuthTransientError,
)


@pytest.fixture
def token_dir(tmp_path: Path) -> Path:
    config_dir = tmp_path / ".nothx"
    config_dir.mkdir(mode=0o700)
    with patch("nothx.msauth.get_config_dir", return_value=config_dir):
        yield config_dir


def _http_response(payload: object) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return response


DEVICE_FLOW_RESPONSE = {
    "user_code": "ABCD-EFGH",
    "device_code": "device-secret",
    "verification_uri": "https://microsoft.com/devicelogin",
    "interval": 5,
    "expires_in": 900,
}

TOKEN_RESPONSE = {
    "access_token": "access-1",
    "refresh_token": "refresh-1",
    "expires_in": 3600,
    "token_type": "Bearer",
    "scope": f"{msauth.IMAP_SCOPE} {msauth.SMTP_SCOPE}",
}


class TestDeviceFlow:
    @patch("nothx.msauth.urllib.request.urlopen")
    def test_start_requests_exact_consumer_scopes(self, urlopen: MagicMock) -> None:
        urlopen.return_value = _http_response(DEVICE_FLOW_RESPONSE)

        flow = msauth.start_device_flow(" client-123 ")

        assert flow["device_code"] == "device-secret"
        request = urlopen.call_args.args[0]
        assert request.full_url == msauth.DEVICE_CODE_URL
        assert "/consumers/" in request.full_url
        params = parse_qs(request.data.decode())
        assert params == {"client_id": ["client-123"], "scope": [msauth.SCOPE]}
        assert msauth.REQUIRED_SCOPES == (
            "https://outlook.office.com/IMAP.AccessAsUser.All",
            "https://outlook.office.com/SMTP.Send",
            "offline_access",
        )

    @patch("nothx.msauth._post_form")
    def test_start_rejects_oauth_error(self, post: MagicMock) -> None:
        post.return_value = {
            "error": "invalid_client",
            "error_description": "The client ID is invalid",
        }

        with pytest.raises(OAuthError) as exc_info:
            msauth.start_device_flow("bad-client")

        assert exc_info.value.code is ErrorCode.OAUTH_DEVICE_FLOW_FAILED
        assert exc_info.value.details["error"] == "invalid_client"

    @patch("nothx.msauth.time.sleep")
    @patch("nothx.msauth._post_form")
    def test_poll_pending_then_success(self, post: MagicMock, sleep: MagicMock) -> None:
        post.side_effect = [{"error": "authorization_pending"}, dict(TOKEN_RESPONSE)]

        token = msauth.poll_for_token("client", "device", 5, 900)

        assert token["access_token"] == "access-1"
        sleep.assert_called_once_with(5.0)

    @patch("nothx.msauth.time.sleep")
    @patch("nothx.msauth._post_form")
    def test_poll_slow_down_and_transient_service_error(
        self, post: MagicMock, sleep: MagicMock
    ) -> None:
        post.side_effect = [
            {"error": "slow_down"},
            {"error": "temporarily_unavailable"},
            dict(TOKEN_RESPONSE),
        ]

        token = msauth.poll_for_token("client", "device", 2, 900)

        assert token["access_token"] == "access-1"
        assert sleep.call_args_list[0].args == (7.0,)
        assert sleep.call_args_list[1].args == (7.0,)

    @patch("nothx.msauth.time.sleep")
    @patch("nothx.msauth._post_form")
    def test_poll_recovers_from_transient_transport(
        self, post: MagicMock, sleep: MagicMock
    ) -> None:
        post.side_effect = [
            OAuthTransientError(
                code=ErrorCode.OAUTH_NETWORK_ERROR,
                message="temporary network error",
            ),
            dict(TOKEN_RESPONSE),
        ]

        token = msauth.poll_for_token("client", "device", 3, 900)

        assert token["access_token"] == "access-1"
        sleep.assert_called_once_with(3.0)

    @patch("nothx.msauth.time.sleep")
    @patch("nothx.msauth._post_form")
    def test_poll_retries_json_http_rate_limit(self, post: MagicMock, sleep: MagicMock) -> None:
        post.side_effect = [
            {"error": "rate_limited", "_http_status": 429},
            dict(TOKEN_RESPONSE),
        ]

        assert msauth.poll_for_token("client", "device", 4, 900)["access_token"] == ("access-1")
        sleep.assert_called_once_with(4.0)

    @patch("nothx.msauth._post_form")
    def test_poll_supports_cancellation(self, post: MagicMock) -> None:
        with pytest.raises(OAuthCancelledError) as exc_info:
            msauth.poll_for_token(
                "client",
                "device",
                5,
                900,
                cancel_check=lambda: True,
            )

        assert exc_info.value.code is ErrorCode.OAUTH_FLOW_CANCELLED
        post.assert_not_called()

    @patch("nothx.msauth._post_form")
    def test_poll_rejects_declined_and_expired_flows(self, post: MagicMock) -> None:
        post.return_value = {"error": "authorization_declined"}
        with pytest.raises(OAuthError, match="authorization_declined"):
            msauth.poll_for_token("client", "device", 5, 900)

        post.reset_mock()
        with pytest.raises(OAuthError, match="expired"):
            msauth.poll_for_token("client", "device", 5, 0)
        post.assert_not_called()


class TestHTTPAndRefresh:
    @patch("nothx.msauth.urllib.request.urlopen")
    def test_network_error_is_retryable(self, urlopen: MagicMock) -> None:
        urlopen.side_effect = urllib.error.URLError("offline")

        with pytest.raises(OAuthTransientError) as exc_info:
            msauth.start_device_flow("client")

        assert exc_info.value.code is ErrorCode.OAUTH_NETWORK_ERROR

    @patch("nothx.msauth._post_form")
    def test_refresh_requests_all_scopes(self, post: MagicMock) -> None:
        post.return_value = dict(TOKEN_RESPONSE)

        token = msauth.refresh_token("client", "old-refresh")

        assert token["access_token"] == "access-1"
        params = post.call_args.args[1]
        assert params["refresh_token"] == "old-refresh"
        assert params["scope"] == msauth.SCOPE

    @patch("nothx.msauth.time.sleep")
    @patch("nothx.msauth._post_form")
    def test_refresh_retries_transient_failure(self, post: MagicMock, sleep: MagicMock) -> None:
        post.side_effect = [
            OAuthTransientError(
                code=ErrorCode.OAUTH_NETWORK_ERROR,
                message="offline",
            ),
            dict(TOKEN_RESPONSE),
        ]

        assert msauth.refresh_token("client", "refresh")["access_token"] == "access-1"
        sleep.assert_called_once_with(1)

    @patch("nothx.msauth._post_form")
    def test_refresh_does_not_retry_permanent_failure(self, post: MagicMock) -> None:
        post.return_value = {"error": "invalid_grant"}

        with pytest.raises(OAuthError) as exc_info:
            msauth.refresh_token("client", "revoked")

        assert exc_info.value.code is ErrorCode.OAUTH_TOKEN_REFRESH_FAILED
        assert post.call_count == 1


class TestTokenCache:
    def test_round_trip_records_provenance_and_secure_permissions(self, token_dir: Path) -> None:
        msauth.save_token("User@Live.com", TOKEN_RESPONSE, "client-123")

        cached = msauth.load_token("user@live.com")
        assert cached is not None
        assert cached["client_id"] == "client-123"
        assert cached["scope"] == TOKEN_RESPONSE["scope"]
        assert cached["requested_scope"] == msauth.SCOPE
        assert cached["refresh_token"] == "refresh-1"
        assert cached["expires_at"] > 0

        path = token_dir / "tokens.json"
        assert path.stat().st_mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR
        raw = json.loads(path.read_text())
        assert raw["version"] == msauth.CACHE_VERSION
        assert raw["accounts"]["user@live.com"]["client_id"] == "client-123"
        assert not list(token_dir.glob(".tokens-*"))

    def test_atomic_replacement_tightens_existing_permissions(self, token_dir: Path) -> None:
        path = token_dir / "tokens.json"
        path.write_text("{}")
        path.chmod(0o644)

        msauth.save_token("user@live.com", TOKEN_RESPONSE, "client")

        assert path.stat().st_mode & 0o777 == 0o600

    def test_replace_failure_does_not_close_a_reused_descriptor(self, token_dir: Path) -> None:
        """fdopen owns the temp fd, even if its number is reused after close."""
        victim = token_dir / "victim"
        victim.write_text("still open")
        victim_fds: list[int] = []

        def fail_after_reuse(*_args: object) -> None:
            victim_fds.append(os.open(victim, os.O_RDONLY))
            raise OSError("replace failed")

        with (
            patch("nothx.msauth.os.replace", side_effect=fail_after_reuse),
            pytest.raises(OSError, match="replace failed"),
        ):
            msauth.save_token("user@live.com", TOKEN_RESPONSE, "client")

        assert victim_fds
        victim_fd = victim_fds[0]
        try:
            assert os.fstat(victim_fd).st_size == len("still open")
        finally:
            os.close(victim_fd)

    def test_rotated_refresh_token_is_saved_and_missing_rotation_is_preserved(
        self, token_dir: Path
    ) -> None:
        msauth.save_token("user@live.com", TOKEN_RESPONSE, "client")
        rotated = dict(TOKEN_RESPONSE, access_token="access-2", refresh_token="refresh-2")
        msauth.save_token("user@live.com", rotated, "client")
        no_rotation = {
            "access_token": "access-3",
            "expires_in": 3600,
            "scope": TOKEN_RESPONSE["scope"],
        }
        msauth.save_token("user@live.com", no_rotation, "client")

        cached = msauth.load_token("user@live.com")
        assert cached is not None
        assert cached["access_token"] == "access-3"
        assert cached["refresh_token"] == "refresh-2"

    def test_client_change_never_carries_old_refresh_token(self, token_dir: Path) -> None:
        msauth.save_token("user@live.com", TOKEN_RESPONSE, "old-client")
        no_refresh = {
            "access_token": "new-access",
            "expires_in": 3600,
            "scope": TOKEN_RESPONSE["scope"],
        }

        msauth.save_token("user@live.com", no_refresh, "new-client")

        cached = msauth.load_token("user@live.com")
        assert cached is not None
        assert cached["client_id"] == "new-client"
        assert cached["refresh_token"] is None

    def test_corrupt_cache_fails_closed_and_is_never_replaced(self, token_dir: Path) -> None:
        path = token_dir / "tokens.json"
        original = b'{"accounts":{"other@live.com":{"refresh_token":"keep-me"}}'
        path.write_bytes(original)

        with pytest.raises(OAuthError) as load_error:
            msauth.load_token("user@live.com")
        with pytest.raises(OAuthError) as save_error:
            msauth.save_token("user@live.com", TOKEN_RESPONSE, "client")

        assert load_error.value.code is ErrorCode.OAUTH_CACHE_ERROR
        assert save_error.value.code is ErrorCode.OAUTH_CACHE_ERROR
        assert path.read_bytes() == original

    def test_unreadable_cache_cannot_discard_other_accounts(self, token_dir: Path) -> None:
        msauth.save_token("one@live.com", TOKEN_RESPONSE, "client")
        msauth.save_token(
            "two@live.com",
            dict(TOKEN_RESPONSE, access_token="access-2", refresh_token="refresh-2"),
            "client",
        )
        path = token_dir / "tokens.json"
        original = path.read_bytes()
        real_open = msauth.os.open

        def deny_token_cache(candidate, flags, mode=0o777, *, dir_fd=None):
            if Path(candidate) == path:
                raise PermissionError("token cache is unreadable")
            if dir_fd is None:
                return real_open(candidate, flags, mode)
            return real_open(candidate, flags, mode, dir_fd=dir_fd)

        with (
            patch("nothx.msauth.os.open", side_effect=deny_token_cache),
            pytest.raises(OAuthError) as exc_info,
        ):
            msauth.save_token("three@live.com", TOKEN_RESPONSE, "client")

        assert exc_info.value.code is ErrorCode.OAUTH_CACHE_ERROR
        assert path.read_bytes() == original
        assert msauth.load_token("one@live.com") is not None
        assert msauth.load_token("two@live.com") is not None
        assert msauth.load_token("three@live.com") is None

    def test_structurally_invalid_account_entry_prevents_partial_rewrite(
        self, token_dir: Path
    ) -> None:
        path = token_dir / "tokens.json"
        original = json.dumps(
            {
                "version": msauth.CACHE_VERSION,
                "accounts": {
                    "one@live.com": dict(TOKEN_RESPONSE),
                    "two@live.com": "corrupt-account-record",
                },
            }
        ).encode()
        path.write_bytes(original)

        with pytest.raises(OAuthError) as exc_info:
            msauth.save_token("three@live.com", TOKEN_RESPONSE, "client")

        assert exc_info.value.code is ErrorCode.OAUTH_CACHE_ERROR
        assert path.read_bytes() == original

    def test_read_repairs_legacy_permissive_mode(self, token_dir: Path) -> None:
        path = token_dir / "tokens.json"
        path.write_text(json.dumps({}))
        path.chmod(0o644)

        assert msauth.load_token("missing@live.com") is None
        assert path.stat().st_mode & 0o777 == 0o600

    def test_legacy_flat_cache_requires_explicit_reconsent(self, token_dir: Path) -> None:
        legacy = {
            "user@live.com": {
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "expires_at": 9999999999,
            }
        }
        (token_dir / "tokens.json").write_text(json.dumps(legacy))

        status = msauth.get_consent_status("user@live.com", "client")

        assert status.ready is False
        assert status.reason == "client_id_changed"
        with pytest.raises(OAuthReconsentRequired):
            msauth.get_access_token("user@live.com", "client")

    def test_delete_and_clear_are_idempotent(self, token_dir: Path) -> None:
        msauth.save_token("one@live.com", TOKEN_RESPONSE, "client")
        msauth.save_token("two@live.com", TOKEN_RESPONSE, "client")

        msauth.delete_token("ONE@LIVE.COM")
        msauth.delete_token("missing@live.com")
        assert msauth.load_token("one@live.com") is None
        assert msauth.load_token("two@live.com") is not None

        msauth.clear_token_cache()
        msauth.clear_token_cache()
        assert not (token_dir / "tokens.json").exists()

    def test_rejects_token_without_access_credential(self, token_dir: Path) -> None:
        with pytest.raises(OAuthError) as exc_info:
            msauth.save_token("user@live.com", {"refresh_token": "secret"}, "client")

        assert exc_info.value.code is ErrorCode.OAUTH_CACHE_ERROR


class TestConsentAndAccess:
    def test_scope_helpers_are_case_insensitive_and_precise(self) -> None:
        granted = f"{msauth.IMAP_SCOPE.lower()} {msauth.SMTP_SCOPE} unrelated"
        assert msauth.has_required_scopes(granted)
        assert msauth.missing_required_scopes(msauth.IMAP_SCOPE) == (msauth.SMTP_SCOPE,)

    def test_missing_smtp_requires_reconsent(self, token_dir: Path) -> None:
        imap_only = dict(TOKEN_RESPONSE, scope=msauth.IMAP_SCOPE)
        msauth.save_token("user@live.com", imap_only, "client")

        status = msauth.get_consent_status("user@live.com", "client")

        assert status.reason == "missing_scopes"
        assert status.missing_scopes == (msauth.SMTP_SCOPE,)
        assert msauth.requires_reconsent("user@live.com", "client")

    def test_missing_offline_access_requires_reconsent(self, token_dir: Path) -> None:
        no_refresh = dict(TOKEN_RESPONSE)
        no_refresh.pop("refresh_token")
        msauth.save_token("user@live.com", no_refresh, "client")

        assert msauth.get_consent_status("user@live.com", "client").reason == (
            "offline_access_missing"
        )

    def test_fresh_fully_consented_token_does_not_refresh(self, token_dir: Path) -> None:
        msauth.save_token("user@live.com", TOKEN_RESPONSE, "client")

        with patch("nothx.msauth.refresh_token") as refresh:
            assert msauth.get_access_token("user@live.com", "client") == "access-1"

        refresh.assert_not_called()

    def test_expired_token_refreshes_and_persists_rotation(self, token_dir: Path) -> None:
        expired = dict(TOKEN_RESPONSE, expires_in=0)
        msauth.save_token("user@live.com", expired, "client")
        refreshed = {
            "access_token": "access-2",
            "refresh_token": "refresh-2",
            "expires_in": 3600,
            # Microsoft may omit scope on a refresh; retain the prior grant.
        }

        with patch("nothx.msauth.refresh_token", return_value=refreshed) as refresh:
            token = msauth.get_access_token("user@live.com", "client")

        assert token == "access-2"
        refresh.assert_called_once_with("client", "refresh-1")
        cached = msauth.load_token("user@live.com")
        assert cached is not None
        assert cached["refresh_token"] == "refresh-2"
        assert cached["scope"] == TOKEN_RESPONSE["scope"]

    def test_force_refresh_and_missing_token_errors(self, token_dir: Path) -> None:
        with pytest.raises(OAuthError) as exc_info:
            msauth.get_access_token("missing@live.com", "client")
        assert exc_info.value.code is ErrorCode.OAUTH_TOKEN_MISSING

        msauth.save_token("user@live.com", TOKEN_RESPONSE, "client")
        with patch("nothx.msauth.refresh_token", return_value=dict(TOKEN_RESPONSE)) as refresh:
            msauth.get_access_token("user@live.com", "client", force_refresh=True)
        refresh.assert_called_once()


class TestXOAuth2:
    def test_builds_imap_bytes_and_smtp_base64(self) -> None:
        expected = b"user=user@live.com\x01auth=Bearer access-token\x01\x01"

        assert msauth.build_xoauth2_bytes("user@live.com", "access-token") == expected
        assert (
            base64.b64decode(msauth.build_xoauth2_base64("user@live.com", "access-token"))
            == expected
        )

    def test_rejects_sasl_delimiter_in_values(self) -> None:
        with pytest.raises(ValueError):
            msauth.build_xoauth2_bytes("user\x01@example.com", "token")
