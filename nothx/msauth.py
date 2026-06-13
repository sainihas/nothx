"""Microsoft identity platform OAuth2 (device code flow) for nothx.

Personal Microsoft accounts (outlook.com / live.com / hotmail.com) no longer
accept IMAP basic auth or app passwords. IMAP access requires OAuth2 with the
SASL XOAUTH2 mechanism. This module implements the device code flow against
the /consumers tenant — the best fit for a CLI since no redirect server is
needed — plus a local token cache with automatic refresh.

The Azure app client_id comes from user configuration (a free, one-time app
registration). This is a public client flow: no client secret is involved.
"""

import json
import logging
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .config import get_config_dir
from .errors import ErrorCode, OAuthError

logger = logging.getLogger("nothx.msauth")

# Microsoft identity platform endpoints (consumers tenant = personal accounts)
AUTHORITY = "https://login.microsoftonline.com/consumers/oauth2/v2.0"
DEVICE_CODE_URL = f"{AUTHORITY}/devicecode"
TOKEN_URL = f"{AUTHORITY}/token"

# Scope for IMAP access plus a refresh token
SCOPE = "https://outlook.office365.com/IMAP.AccessAsUser.All offline_access"

# Timeout for HTTP requests
REQUEST_TIMEOUT = 30

# Refresh access tokens this many seconds before they actually expire
EXPIRY_MARGIN = 60


def get_tokens_path() -> Path:
    """Get the path to tokens.json (OAuth token cache)."""
    return get_config_dir() / "tokens.json"


def _post_form(url: str, params: dict[str, str]) -> dict[str, Any]:
    """POST form-encoded params and return the parsed JSON response.

    OAuth error responses (HTTP 4xx with a JSON body containing "error")
    are returned as dicts so callers can inspect the error code — e.g.
    "authorization_pending" during device-code polling is not a failure.
    """
    data = urllib.parse.urlencode(params).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise OAuthError(
                code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
                message=f"Microsoft identity platform returned HTTP {e.code}",
                details={"url": url, "http_status": e.code},
                cause=e,
            ) from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message=f"Failed to reach Microsoft identity platform: {e}",
            details={"url": url},
            cause=e,
        ) from e
    except json.JSONDecodeError as e:
        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message="Invalid JSON response from Microsoft identity platform",
            details={"url": url},
            cause=e,
        ) from e


def start_device_flow(client_id: str) -> dict[str, Any]:
    """Start the device code flow.

    Returns a dict with user_code, verification_uri, device_code,
    interval, and expires_in.

    Raises:
        OAuthError: If the device code request fails.
    """
    response = _post_form(DEVICE_CODE_URL, {"client_id": client_id, "scope": SCOPE})

    if "device_code" not in response:
        error = response.get("error", "unknown_error")
        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message=f"Failed to start device code flow: {error}",
            details={
                "error": error,
                "error_description": response.get("error_description", ""),
            },
        )

    logger.debug("Started device code flow", extra={"client_id": client_id})
    return response


def poll_for_token(
    client_id: str, device_code: str, interval: int, expires_in: int
) -> dict[str, Any]:
    """Poll the token endpoint until the user completes sign-in.

    Returns the token dict (access_token, refresh_token, expires_in, ...).

    Raises:
        OAuthError: If the flow is declined, expires, or otherwise fails.
    """
    deadline = time.monotonic() + expires_in
    delay = max(interval, 1)

    while time.monotonic() < deadline:
        response = _post_form(
            TOKEN_URL,
            {
                "client_id": client_id,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
            },
        )

        if "access_token" in response:
            logger.debug("Device code flow completed successfully")
            return response

        error = response.get("error", "unknown_error")
        if error == "authorization_pending":
            time.sleep(delay)
            continue
        if error == "slow_down":
            delay += 5
            time.sleep(delay)
            continue

        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message=f"Device code flow failed: {error}",
            details={
                "error": error,
                "error_description": response.get("error_description", ""),
            },
        )

    raise OAuthError(
        code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
        message="Device code flow expired before sign-in was completed",
        details={"expires_in": expires_in},
    )


def refresh_token(client_id: str, refresh_token: str) -> dict[str, Any]:
    """Exchange a refresh token for a new token dict.

    Raises:
        OAuthError: If the refresh fails.
    """
    response = _post_form(
        TOKEN_URL,
        {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": SCOPE,
        },
    )

    if "access_token" not in response:
        error = response.get("error", "unknown_error")
        raise OAuthError(
            code=ErrorCode.OAUTH_TOKEN_REFRESH_FAILED,
            message=f"Token refresh failed: {error}",
            details={
                "error": error,
                "error_description": response.get("error_description", ""),
            },
        )

    logger.debug("Refreshed OAuth access token")
    return response


def _load_all_tokens() -> dict[str, Any]:
    """Load the token cache from disk."""
    tokens_path = get_tokens_path()
    if not tokens_path.exists():
        return {}
    try:
        with open(tokens_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to read token cache, starting fresh: %s", e)
        return {}


def _save_all_tokens(data: dict[str, Any]) -> None:
    """Save the token cache to disk with secure permissions (0600)."""
    tokens_path = get_tokens_path()
    with open(tokens_path, "w") as f:
        json.dump(data, f, indent=2)
    # Owner read/write only — tokens grant full IMAP access to the mailbox
    tokens_path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def save_token(email: str, token: dict[str, Any]) -> None:
    """Persist a token response for an account, computing absolute expiry."""
    tokens = _load_all_tokens()
    cached = {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token"),
        "expires_at": time.time() + int(token.get("expires_in", 0)),
    }
    # Keep the previous refresh token if the response didn't rotate it
    if not cached["refresh_token"]:
        previous = tokens.get(email, {})
        cached["refresh_token"] = previous.get("refresh_token")
    tokens[email] = cached
    _save_all_tokens(tokens)


def load_token(email: str) -> dict[str, Any] | None:
    """Load the cached token for an account, or None if not cached."""
    return _load_all_tokens().get(email)


def delete_token(email: str) -> None:
    """Remove the cached token for an account, if present."""
    tokens = _load_all_tokens()
    if email in tokens:
        del tokens[email]
        _save_all_tokens(tokens)


def get_access_token(email: str, client_id: str, force_refresh: bool = False) -> str:
    """Get a valid access token for an account, refreshing if needed.

    Rotated refresh tokens are persisted automatically.

    Raises:
        OAuthError: If no token is cached or the refresh fails.
    """
    cached = load_token(email)
    if not cached:
        raise OAuthError(
            code=ErrorCode.OAUTH_TOKEN_MISSING,
            message=(
                f"No cached OAuth token for {email}. "
                "Run 'nothx account add' to sign in with Microsoft."
            ),
            details={"email": email},
        )

    expires_at = float(cached.get("expires_at", 0))
    if not force_refresh and time.time() < expires_at - EXPIRY_MARGIN:
        return cached["access_token"]

    if not cached.get("refresh_token"):
        raise OAuthError(
            code=ErrorCode.OAUTH_TOKEN_REFRESH_FAILED,
            message=(
                f"OAuth token for {email} expired and no refresh token is cached. "
                "Run 'nothx account add' to sign in again."
            ),
            details={"email": email},
        )

    token = refresh_token(client_id, cached["refresh_token"])
    save_token(email, token)
    return token["access_token"]
