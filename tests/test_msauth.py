"""Tests for Microsoft OAuth2 device code flow and token caching."""

import json
import stat
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nothx import msauth
from nothx.errors import ErrorCode, OAuthError


@pytest.fixture
def temp_tokens_dir():
    """Create a temporary config directory for token cache testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_dir = Path(tmpdir) / ".nothx"
        config_dir.mkdir(parents=True, exist_ok=True)
        with patch("nothx.msauth.get_config_dir", return_value=config_dir):
            yield config_dir


def _http_response(payload: dict) -> MagicMock:
    """Build a mock urlopen context manager returning a JSON payload."""
    cm = MagicMock()
    cm.__enter__.return_value.read.return_value = json.dumps(payload).encode()
    return cm


DEVICE_FLOW_RESPONSE = {
    "user_code": "ABC123",
    "device_code": "device-secret",
    "verification_uri": "https://microsoft.com/devicelogin",
    "interval": 5,
    "expires_in": 900,
}

TOKEN_RESPONSE = {
    "access_token": "access-token-1",
    "refresh_token": "refresh-token-1",
    "expires_in": 3600,
}


class TestStartDeviceFlow:
    """Tests for starting the device code flow."""

    @patch("nothx.msauth.urllib.request.urlopen")
    def test_happy_path(self, mock_urlopen):
        """Test successful device code request."""
        mock_urlopen.return_value = _http_response(DEVICE_FLOW_RESPONSE)

        flow = msauth.start_device_flow("client-123")

        assert flow["user_code"] == "ABC123"
        assert flow["device_code"] == "device-secret"
        assert flow["verification_uri"] == "https://microsoft.com/devicelogin"
        assert flow["interval"] == 5
        assert flow["expires_in"] == 900

        request = mock_urlopen.call_args[0][0]
        assert request.full_url == msauth.DEVICE_CODE_URL
        assert "/consumers/" in request.full_url
        body = request.data.decode()
        assert "client_id=client-123" in body
        assert "IMAP.AccessAsUser.All" in body
        assert "offline_access" in body

    @patch("nothx.msauth.urllib.request.urlopen")
    def test_error_response_raises(self, mock_urlopen):
        """Test that an OAuth error response raises OAuthError."""
        mock_urlopen.return_value = _http_response(
            {"error": "invalid_client", "error_description": "Bad client ID"}
        )

        with pytest.raises(OAuthError) as exc_info:
            msauth.start_device_flow("bad-client")

        assert exc_info.value.code == ErrorCode.OAUTH_DEVICE_FLOW_FAILED
        assert "invalid_client" in str(exc_info.value)

    @patch("nothx.msauth.urllib.request.urlopen")
    def test_network_error_raises(self, mock_urlopen):
        """Test that a network failure raises OAuthError."""
        mock_urlopen.side_effect = OSError("Connection refused")

        with pytest.raises(OAuthError) as exc_info:
            msauth.start_device_flow("client-123")

        assert exc_info.value.code == ErrorCode.OAUTH_DEVICE_FLOW_FAILED


class TestPollForToken:
    """Tests for polling the token endpoint."""

    @patch("nothx.msauth.time.sleep")
    @patch("nothx.msauth._post_form")
    def test_pending_then_success(self, mock_post, mock_sleep):
        """Test polling through authorization_pending to success."""
        mock_post.side_effect = [
            {"error": "authorization_pending"},
            dict(TOKEN_RESPONSE),
        ]

        token = msauth.poll_for_token("client-123", "device-secret", 5, 900)

        assert token["access_token"] == "access-token-1"
        assert token["refresh_token"] == "refresh-token-1"
        mock_sleep.assert_called_once_with(5)

        params = mock_post.call_args[0][1]
        assert params["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
        assert params["device_code"] == "device-secret"
        assert params["client_id"] == "client-123"

    @patch("nothx.msauth.time.sleep")
    @patch("nothx.msauth._post_form")
    def test_slow_down_increases_interval(self, mock_post, mock_sleep):
        """Test that slow_down increases the polling interval."""
        mock_post.side_effect = [
            {"error": "slow_down"},
            dict(TOKEN_RESPONSE),
        ]

        token = msauth.poll_for_token("client-123", "device-secret", 5, 900)

        assert token["access_token"] == "access-token-1"
        mock_sleep.assert_called_once_with(10)

    @patch("nothx.msauth._post_form")
    def test_declined_raises(self, mock_post):
        """Test that a declined sign-in raises OAuthError."""
        mock_post.return_value = {"error": "authorization_declined"}

        with pytest.raises(OAuthError) as exc_info:
            msauth.poll_for_token("client-123", "device-secret", 5, 900)

        assert exc_info.value.code == ErrorCode.OAUTH_DEVICE_FLOW_FAILED
        assert "authorization_declined" in str(exc_info.value)

    @patch("nothx.msauth._post_form")
    def test_expired_flow_raises(self, mock_post):
        """Test that an already-expired flow raises without polling."""
        with pytest.raises(OAuthError) as exc_info:
            msauth.poll_for_token("client-123", "device-secret", 5, 0)

        assert exc_info.value.code == ErrorCode.OAUTH_DEVICE_FLOW_FAILED
        mock_post.assert_not_called()


class TestRefreshToken:
    """Tests for the refresh token grant."""

    @patch("nothx.msauth._post_form")
    def test_happy_path(self, mock_post):
        """Test successful token refresh."""
        mock_post.return_value = dict(TOKEN_RESPONSE)

        token = msauth.refresh_token("client-123", "old-refresh")

        assert token["access_token"] == "access-token-1"
        params = mock_post.call_args[0][1]
        assert params["grant_type"] == "refresh_token"
        assert params["refresh_token"] == "old-refresh"
        assert params["client_id"] == "client-123"

    @patch("nothx.msauth._post_form")
    def test_failure_raises(self, mock_post):
        """Test that a failed refresh raises OAuthError."""
        mock_post.return_value = {"error": "invalid_grant"}

        with pytest.raises(OAuthError) as exc_info:
            msauth.refresh_token("client-123", "revoked-refresh")

        assert exc_info.value.code == ErrorCode.OAUTH_TOKEN_REFRESH_FAILED


class TestTokenCache:
    """Tests for the on-disk token cache."""

    def test_save_and_load_roundtrip(self, temp_tokens_dir):
        """Test saving and loading a token."""
        msauth.save_token("user@live.com", dict(TOKEN_RESPONSE))

        cached = msauth.load_token("user@live.com")

        assert cached is not None
        assert cached["access_token"] == "access-token-1"
        assert cached["refresh_token"] == "refresh-token-1"
        assert cached["expires_at"] == pytest.approx(time.time() + 3600, abs=5)

    def test_save_sets_permissions(self, temp_tokens_dir):
        """Test that the token cache is written with 0600 permissions."""
        msauth.save_token("user@live.com", dict(TOKEN_RESPONSE))

        tokens_path = temp_tokens_dir / "tokens.json"
        assert tokens_path.stat().st_mode & 0o777 == stat.S_IRUSR | stat.S_IWUSR

    def test_save_keeps_previous_refresh_token(self, temp_tokens_dir):
        """Test that a response without refresh_token keeps the old one."""
        msauth.save_token("user@live.com", dict(TOKEN_RESPONSE))
        msauth.save_token("user@live.com", {"access_token": "access-token-2", "expires_in": 3600})

        cached = msauth.load_token("user@live.com")

        assert cached is not None
        assert cached["access_token"] == "access-token-2"
        assert cached["refresh_token"] == "refresh-token-1"

    def test_load_missing_returns_none(self, temp_tokens_dir):
        """Test loading a token that was never cached."""
        assert msauth.load_token("nobody@live.com") is None

    def test_delete_token(self, temp_tokens_dir):
        """Test deleting a cached token."""
        msauth.save_token("user@live.com", dict(TOKEN_RESPONSE))

        msauth.delete_token("user@live.com")

        assert msauth.load_token("user@live.com") is None

    def test_delete_token_missing_is_noop(self, temp_tokens_dir):
        """Test that deleting a never-cached token does nothing."""
        msauth.delete_token("nobody@live.com")  # Should not raise


class TestGetAccessToken:
    """Tests for get_access_token (cache + automatic refresh)."""

    @patch("nothx.msauth.refresh_token")
    def test_returns_cached_token_when_fresh(self, mock_refresh, temp_tokens_dir):
        """Test that a fresh cached token is returned without refresh."""
        msauth.save_token("user@live.com", dict(TOKEN_RESPONSE))

        token = msauth.get_access_token("user@live.com", "client-123")

        assert token == "access-token-1"
        mock_refresh.assert_not_called()

    @patch("nothx.msauth.refresh_token")
    def test_refreshes_expired_token(self, mock_refresh, temp_tokens_dir):
        """Test refresh on expiry, persisting the rotated refresh token."""
        msauth.save_token(
            "user@live.com",
            {"access_token": "stale", "refresh_token": "old-refresh", "expires_in": 0},
        )
        mock_refresh.return_value = {
            "access_token": "fresh",
            "refresh_token": "rotated-refresh",
            "expires_in": 3600,
        }

        token = msauth.get_access_token("user@live.com", "client-123")

        assert token == "fresh"
        mock_refresh.assert_called_once_with("client-123", "old-refresh")

        cached = msauth.load_token("user@live.com")
        assert cached is not None
        assert cached["refresh_token"] == "rotated-refresh"

    @patch("nothx.msauth.refresh_token")
    def test_force_refresh(self, mock_refresh, temp_tokens_dir):
        """Test that force_refresh bypasses a still-valid cached token."""
        msauth.save_token("user@live.com", dict(TOKEN_RESPONSE))
        mock_refresh.return_value = {
            "access_token": "forced",
            "refresh_token": "rotated-refresh",
            "expires_in": 3600,
        }

        token = msauth.get_access_token("user@live.com", "client-123", force_refresh=True)

        assert token == "forced"
        mock_refresh.assert_called_once()

    def test_missing_token_raises(self, temp_tokens_dir):
        """Test that a never-cached account raises OAuthError."""
        with pytest.raises(OAuthError) as exc_info:
            msauth.get_access_token("nobody@live.com", "client-123")

        assert exc_info.value.code == ErrorCode.OAUTH_TOKEN_MISSING

    def test_expired_without_refresh_token_raises(self, temp_tokens_dir):
        """Test that an expired token with no refresh token raises OAuthError."""
        msauth.save_token("user@live.com", {"access_token": "stale", "expires_in": 0})

        with pytest.raises(OAuthError) as exc_info:
            msauth.get_access_token("user@live.com", "client-123")

        assert exc_info.value.code == ErrorCode.OAUTH_TOKEN_REFRESH_FAILED
