"""Tests for IMAP connections (OAuth and password authentication)."""

import imaplib
import logging
from unittest.mock import MagicMock, patch

import pytest

from nothx.config import AccountConfig
from nothx.errors import ErrorCode, IMAPError, OAuthError
from nothx.imap import IMAP_SERVERS, OUTLOOK_OAUTH_SERVER, IMAPConnection


def _oauth_account() -> AccountConfig:
    return AccountConfig(
        provider="outlook",
        email="user@live.com",
        auth="oauth",
        client_id="client-123",
    )


def _password_outlook_account() -> AccountConfig:
    return AccountConfig(provider="outlook", email="user@live.com", password="app-password")


class TestServerSelection:
    """Tests for IMAP server host selection."""

    def test_oauth_outlook_uses_modern_host(self):
        """Test that OAuth outlook accounts connect to outlook.office365.com."""
        conn = IMAPConnection(_oauth_account())
        assert conn.server == OUTLOOK_OAUTH_SERVER

    def test_password_outlook_uses_legacy_host(self):
        """Test that password outlook accounts keep the legacy host."""
        conn = IMAPConnection(_password_outlook_account())
        assert conn.server == IMAP_SERVERS["outlook"]

    def test_gmail_host_unchanged(self):
        """Test that gmail accounts use the gmail host."""
        account = AccountConfig(provider="gmail", email="user@gmail.com", password="pw")
        conn = IMAPConnection(account)
        assert conn.server == IMAP_SERVERS["gmail"]


class TestOAuthConnection:
    """Tests for XOAUTH2 authentication."""

    @patch("nothx.imap.msauth.get_access_token", return_value="tok")
    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_xoauth2_sasl_string_format(self, mock_imap, mock_token):
        """Test the XOAUTH2 SASL string format."""
        conn = IMAPConnection(_oauth_account())

        assert conn.connect() is True

        mock_imap.return_value.authenticate.assert_called_once()
        mechanism, sasl_fn = mock_imap.return_value.authenticate.call_args[0]
        assert mechanism == "XOAUTH2"
        assert sasl_fn(b"") == b"user=user@live.com\x01auth=Bearer tok\x01\x01"
        mock_imap.return_value.login.assert_not_called()

    @patch("nothx.imap.msauth.get_access_token", side_effect=["stale", "fresh"])
    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_retry_once_on_auth_failure(self, mock_imap, mock_token):
        """Test that auth failure forces a token refresh and retries once."""
        first = MagicMock()
        first.authenticate.side_effect = imaplib.IMAP4.error("AUTHENTICATE failed")
        second = MagicMock()
        mock_imap.side_effect = [first, second]

        conn = IMAPConnection(_oauth_account())

        assert conn.connect() is True

        assert mock_token.call_count == 2
        assert mock_token.call_args_list[1].kwargs.get("force_refresh") is True
        second.authenticate.assert_called_once()
        _, sasl_fn = second.authenticate.call_args[0]
        assert sasl_fn(b"") == b"user=user@live.com\x01auth=Bearer fresh\x01\x01"

    @patch("nothx.imap.msauth.get_access_token", side_effect=["stale", "fresh"])
    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_retry_failure_raises_auth_error(self, mock_imap, mock_token):
        """Test that failure after the retry raises IMAP_AUTH_FAILED."""
        mock_imap.return_value.authenticate.side_effect = imaplib.IMAP4.error("AUTHENTICATE failed")

        conn = IMAPConnection(_oauth_account())

        with pytest.raises(IMAPError) as exc_info:
            conn.connect()

        assert exc_info.value.code == ErrorCode.IMAP_AUTH_FAILED
        assert mock_token.call_count == 2

    @patch(
        "nothx.imap.msauth.get_access_token",
        side_effect=OAuthError(code=ErrorCode.OAUTH_TOKEN_REFRESH_FAILED, message="refresh failed"),
    )
    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_oauth_error_wrapped_as_imap_error(self, mock_imap, mock_token):
        """Test that OAuth failures surface as IMAP auth errors."""
        conn = IMAPConnection(_oauth_account())

        with pytest.raises(IMAPError) as exc_info:
            conn.connect()

        assert exc_info.value.code == ErrorCode.IMAP_AUTH_FAILED
        assert "refresh failed" in str(exc_info.value)

    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_missing_client_id_raises(self, mock_imap):
        """Test that an OAuth account without client_id raises IMAP_AUTH_FAILED."""
        account = AccountConfig(provider="outlook", email="user@live.com", auth="oauth")
        conn = IMAPConnection(account)

        with pytest.raises(IMAPError) as exc_info:
            conn.connect()

        assert exc_info.value.code == ErrorCode.IMAP_AUTH_FAILED
        assert "client_id" in str(exc_info.value)


class TestPasswordConnection:
    """Tests for password authentication (unchanged behavior)."""

    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_password_login_unchanged(self, mock_imap):
        """Test that password accounts still use plain IMAP login."""
        account = AccountConfig(provider="gmail", email="user@gmail.com", password="pw")
        conn = IMAPConnection(account)

        assert conn.connect() is True

        mock_imap.return_value.login.assert_called_once_with("user@gmail.com", "pw")
        mock_imap.return_value.authenticate.assert_not_called()

    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_outlook_password_warns(self, mock_imap, caplog):
        """Test that outlook password accounts log a loud deprecation warning."""
        conn = IMAPConnection(_password_outlook_account())

        with caplog.at_level(logging.WARNING, logger="nothx.imap"):
            conn.connect()

        assert "app passwords" in caplog.text
        assert "OAuth" in caplog.text

    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_gmail_password_does_not_warn(self, mock_imap, caplog):
        """Test that gmail password accounts do not get the outlook warning."""
        account = AccountConfig(provider="gmail", email="user@gmail.com", password="pw")
        conn = IMAPConnection(account)

        with caplog.at_level(logging.WARNING, logger="nothx.imap"):
            conn.connect()

        assert "app passwords" not in caplog.text

    @patch("nothx.imap.imaplib.IMAP4_SSL")
    def test_outlook_password_auth_failure_mentions_oauth(self, mock_imap):
        """Test that outlook password auth failures point to OAuth setup."""
        mock_imap.return_value.login.side_effect = imaplib.IMAP4.error(
            "LOGIN failed: authentication failure"
        )

        conn = IMAPConnection(_password_outlook_account())

        with pytest.raises(IMAPError) as exc_info:
            conn.connect()

        assert exc_info.value.code == ErrorCode.IMAP_AUTH_FAILED
        assert "oauth" in str(exc_info.value).lower()
