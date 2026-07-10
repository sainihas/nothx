"""Microsoft consumer OAuth2 device flow and secure token persistence.

Microsoft personal mail accounts require OAuth for IMAP and SMTP. This
module intentionally uses the ``consumers`` tenant and public-client device
flow: there is no client secret, redirect listener, or browser callback.

The token cache is separate from config.json, protected with owner-only
permissions, and replaced atomically so an interrupted write cannot leave a
partially serialized refresh token behind.
"""

from __future__ import annotations

import base64
import fcntl
import json
import logging
import os
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import get_config_dir
from .errors import (
    ErrorCode,
    OAuthCancelledError,
    OAuthError,
    OAuthReconsentRequired,
    OAuthTransientError,
)

logger = logging.getLogger("nothx.msauth")

AUTHORITY = "https://login.microsoftonline.com/consumers/oauth2/v2.0"
DEVICE_CODE_URL = f"{AUTHORITY}/devicecode"
TOKEN_URL = f"{AUTHORITY}/token"

IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All"
SMTP_SCOPE = "https://outlook.office.com/SMTP.Send"
OFFLINE_ACCESS_SCOPE = "offline_access"
REQUIRED_RESOURCE_SCOPES = (IMAP_SCOPE, SMTP_SCOPE)
REQUIRED_SCOPES = (*REQUIRED_RESOURCE_SCOPES, OFFLINE_ACCESS_SCOPE)
SCOPE = " ".join(REQUIRED_SCOPES)

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
REQUEST_TIMEOUT = 30
EXPIRY_MARGIN = 60
CACHE_VERSION = 1
_MAX_RESPONSE_BYTES = 64 * 1024
_TRANSIENT_OAUTH_ERRORS = {"server_error", "temporarily_unavailable"}


@dataclass(frozen=True)
class ConsentStatus:
    """Whether a cached token can support all nothx Outlook operations."""

    ready: bool
    reason: str | None = None
    missing_scopes: tuple[str, ...] = ()

    @property
    def requires_reconsent(self) -> bool:
        """Return whether an interactive device flow is required."""
        return not self.ready


def get_tokens_path() -> Path:
    """Return the dedicated OAuth token-cache path."""
    return get_config_dir() / "tokens.json"


def _oauth_error_details(response: Mapping[str, Any]) -> dict[str, Any]:
    """Return safe error metadata without token or response-body content."""
    return {
        "error": str(response.get("error", "unknown_error")),
        "error_description": str(response.get("error_description", ""))[:500],
    }


def _is_transient_response(response: Mapping[str, Any]) -> bool:
    error = str(response.get("error", ""))
    status = response.get("_http_status")
    return error in _TRANSIENT_OAUTH_ERRORS or (
        isinstance(status, int) and (status == 429 or 500 <= status <= 599)
    )


def _read_json_response(response: Any) -> dict[str, Any]:
    raw = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message="Microsoft identity response exceeded the safety limit",
        )
    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message="Microsoft identity platform returned invalid JSON",
            cause=exc,
        ) from exc
    if not isinstance(parsed, dict):
        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message="Microsoft identity platform returned an invalid response",
        )
    return parsed


def _post_form(url: str, params: Mapping[str, str]) -> dict[str, Any]:
    """POST a form to a fixed Microsoft endpoint and parse its JSON response."""
    if url not in {DEVICE_CODE_URL, TOKEN_URL}:
        raise ValueError("OAuth requests are restricted to Microsoft identity endpoints")

    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(params).encode("ascii"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return _read_json_response(response)
    except urllib.error.HTTPError as exc:
        # OAuth errors normally use a useful JSON body even with HTTP 400.
        try:
            parsed = _read_json_response(exc)
        except OAuthError:
            if exc.code == 429 or 500 <= exc.code <= 599:
                raise OAuthTransientError(
                    code=ErrorCode.OAUTH_NETWORK_ERROR,
                    message="Microsoft identity platform is temporarily unavailable",
                    details={"http_status": exc.code},
                    cause=exc,
                ) from exc
            raise OAuthError(
                code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
                message=f"Microsoft identity platform returned HTTP {exc.code}",
                details={"http_status": exc.code},
                cause=exc,
            ) from exc
        parsed["_http_status"] = exc.code
        return parsed
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise OAuthTransientError(
            code=ErrorCode.OAUTH_NETWORK_ERROR,
            message="Could not reach Microsoft identity platform",
            details={"error_type": type(exc).__name__},
            cause=exc,
        ) from exc


def start_device_flow(client_id: str) -> dict[str, Any]:
    """Start a Microsoft consumer device-code flow with the exact required scopes."""
    client_id = client_id.strip()
    if not client_id:
        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message="A Microsoft application client ID is required",
        )

    response = _post_form(DEVICE_CODE_URL, {"client_id": client_id, "scope": SCOPE})
    required_fields = ("device_code", "user_code", "verification_uri", "expires_in")
    if not all(response.get(field) for field in required_fields):
        details = _oauth_error_details(response)
        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message=f"Failed to start Microsoft sign-in: {details['error']}",
            details=details,
        )
    return response


def _cancelled(cancel_check: Callable[[], bool] | None) -> bool:
    return bool(cancel_check and cancel_check())


def _raise_cancelled() -> None:
    raise OAuthCancelledError(
        code=ErrorCode.OAUTH_FLOW_CANCELLED,
        message="Microsoft sign-in was cancelled",
    )


def _poll_sleep(
    delay: int,
    deadline: float,
    cancel_check: Callable[[], bool] | None,
) -> None:
    if _cancelled(cancel_check):
        _raise_cancelled()
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(min(float(delay), remaining))
    if _cancelled(cancel_check):
        _raise_cancelled()


def poll_for_token(
    client_id: str,
    device_code: str,
    interval: int,
    expires_in: int,
    *,
    cancel_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Poll until device authorization succeeds, expires, fails, or is cancelled.

    ``authorization_pending``, ``slow_down``, temporary service errors, and
    transient transport failures remain inside the bounded device-flow window.
    """
    deadline = time.monotonic() + max(int(expires_in), 0)
    delay = max(int(interval), 1)

    while time.monotonic() < deadline:
        if _cancelled(cancel_check):
            _raise_cancelled()
        try:
            response = _post_form(
                TOKEN_URL,
                {
                    "client_id": client_id,
                    "grant_type": DEVICE_CODE_GRANT,
                    "device_code": device_code,
                },
            )
        except OAuthTransientError:
            _poll_sleep(delay, deadline, cancel_check)
            continue

        if isinstance(response.get("access_token"), str) and response["access_token"]:
            return response

        error = str(response.get("error", "unknown_error"))
        if error == "authorization_pending":
            _poll_sleep(delay, deadline, cancel_check)
            continue
        if error == "slow_down":
            delay += 5
            _poll_sleep(delay, deadline, cancel_check)
            continue
        if _is_transient_response(response):
            _poll_sleep(delay, deadline, cancel_check)
            continue

        raise OAuthError(
            code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
            message=f"Microsoft sign-in failed: {error}",
            details=_oauth_error_details(response),
        )

    raise OAuthError(
        code=ErrorCode.OAUTH_DEVICE_FLOW_FAILED,
        message="Microsoft sign-in expired before it was completed",
        details={"expires_in": expires_in},
    )


def refresh_token(
    client_id: str,
    refresh_token_value: str,
    *,
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Exchange a refresh token, retrying only transient pre-response failures."""
    attempts = max(1, max_attempts)
    for attempt in range(1, attempts + 1):
        try:
            response = _post_form(
                TOKEN_URL,
                {
                    "client_id": client_id,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token_value,
                    "scope": SCOPE,
                },
            )
        except OAuthTransientError as exc:
            if attempt == attempts:
                raise OAuthError(
                    code=ErrorCode.OAUTH_TOKEN_REFRESH_FAILED,
                    message="Microsoft token refresh failed after transient errors",
                    details={"attempts": attempts},
                    cause=exc,
                ) from exc
            time.sleep(min(2 ** (attempt - 1), 8))
            continue

        if isinstance(response.get("access_token"), str) and response["access_token"]:
            return response

        error = str(response.get("error", "unknown_error"))
        if _is_transient_response(response) and attempt < attempts:
            time.sleep(min(2 ** (attempt - 1), 8))
            continue
        raise OAuthError(
            code=ErrorCode.OAUTH_TOKEN_REFRESH_FAILED,
            message=f"Microsoft token refresh failed: {error}",
            details=_oauth_error_details(response),
        )

    raise AssertionError("unreachable")


def _normalize_email(email: str) -> str:
    value = email.strip().casefold()
    if not value:
        raise ValueError("email must not be empty")
    return value


def _scope_values(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        values = value.split()
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        values = [item for item in value if isinstance(item, str)]
    else:
        values = []
    result: list[str] = []
    seen: set[str] = set()
    for item in values:
        scope = item.strip()
        key = scope.casefold()
        if scope and key not in seen:
            result.append(scope)
            seen.add(key)
    return tuple(result)


def _scope_string(value: object) -> str:
    return " ".join(_scope_values(value))


def missing_required_scopes(
    granted_scope: object,
    required_scopes: Sequence[str] = REQUIRED_RESOURCE_SCOPES,
) -> tuple[str, ...]:
    """Return required resource scopes absent from a token response/cache entry."""
    granted = {scope.casefold() for scope in _scope_values(granted_scope)}
    return tuple(scope for scope in required_scopes if scope.casefold() not in granted)


def has_required_scopes(
    granted_scope: object,
    required_scopes: Sequence[str] = REQUIRED_RESOURCE_SCOPES,
) -> bool:
    """Return whether all required resource scopes were granted."""
    return not missing_required_scopes(granted_scope, required_scopes)


def _empty_cache() -> dict[str, Any]:
    return {"version": CACHE_VERSION, "accounts": {}}


def _decode_cache(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("token cache root must be an object")

    # PR #28 used a flat {email: token} object. Read it conservatively so the
    # caller receives an explicit re-consent result instead of a crash. Those
    # entries lack client/scope provenance and are never silently upgraded.
    accounts_obj: object
    if "version" not in raw and "accounts" not in raw:
        accounts_obj = raw
    else:
        if raw.get("version") != CACHE_VERSION:
            raise ValueError("unsupported token cache version")
        accounts_obj = raw.get("accounts")
    if not isinstance(accounts_obj, dict):
        raise ValueError("token cache accounts must be an object")

    clean: dict[str, dict[str, Any]] = {}
    for email, token in accounts_obj.items():
        if isinstance(email, str) and isinstance(token, dict):
            clean[email.casefold()] = dict(token)
    return {"version": CACHE_VERSION, "accounts": clean}


def _read_cache_unlocked() -> dict[str, Any]:
    path = get_tokens_path()
    if not path.exists():
        return _empty_cache()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
        # Repair permissive modes left by older versions before reading a
        # bearer credential into this process.
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, encoding="utf-8") as cache_file:
            raw = json.load(cache_file)
        return _decode_cache(raw)
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        logger.warning(
            "Ignoring invalid OAuth token cache at %s (%s)",
            path,
            type(exc).__name__,
        )
        return _empty_cache()


def _write_cache_unlocked(cache: Mapping[str, Any]) -> None:
    path = get_tokens_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(stat.S_IRWXU)
    except OSError:
        pass

    fd, temporary_name = tempfile.mkstemp(prefix=".tokens-", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as cache_file:
            json.dump(cache, cache_file, indent=2, sort_keys=True)
            cache_file.flush()
            os.fsync(cache_file.fileno())
        os.replace(temporary_path, path)
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temporary_path.unlink()
        except OSError:
            pass
        raise


@contextmanager
def _cache_lock() -> Iterator[None]:
    path = get_tokens_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _load_all_tokens() -> dict[str, Any]:
    with _cache_lock():
        return dict(_read_cache_unlocked()["accounts"])


def _expires_at(token: Mapping[str, Any]) -> float:
    if "expires_at" in token:
        try:
            return float(token["expires_at"])
        except (TypeError, ValueError):
            return 0.0
    try:
        lifetime = max(float(token.get("expires_in", 0)), 0.0)
    except (TypeError, ValueError):
        lifetime = 0.0
    return time.time() + lifetime


def save_token(
    email: str,
    token: Mapping[str, Any],
    client_id: str | None = None,
    requested_scopes: Sequence[str] = REQUIRED_SCOPES,
) -> None:
    """Atomically persist a token response and any rotated refresh token.

    ``client_id`` should always be supplied for newly authorized accounts.
    Omitting it is accepted only to read/write PR #28-era data; the resulting
    entry deliberately requires re-consent before use.
    """
    access_token = token.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise OAuthError(
            code=ErrorCode.OAUTH_CACHE_ERROR,
            message="Cannot cache an OAuth response without an access token",
        )

    key = _normalize_email(email)
    with _cache_lock():
        cache = _read_cache_unlocked()
        accounts: dict[str, Any] = cache["accounts"]
        previous_obj = accounts.get(key)
        previous: dict[str, Any] = dict(previous_obj) if isinstance(previous_obj, dict) else {}

        resolved_client_id = client_id or token.get("client_id") or previous.get("client_id")
        same_client = bool(
            resolved_client_id
            and previous.get("client_id")
            and resolved_client_id == previous.get("client_id")
        )
        refresh = token.get("refresh_token")
        if not isinstance(refresh, str) or not refresh:
            refresh = previous.get("refresh_token") if same_client else None

        granted_scope = _scope_string(token.get("scope"))
        if not granted_scope and same_client:
            granted_scope = _scope_string(previous.get("scope"))

        requested_scope = _scope_string(requested_scopes)
        if not requested_scope and same_client:
            requested_scope = _scope_string(previous.get("requested_scope"))

        accounts[key] = {
            "access_token": access_token,
            "refresh_token": refresh,
            "expires_at": _expires_at(token),
            "client_id": resolved_client_id,
            "scope": granted_scope,
            "requested_scope": requested_scope,
            "token_type": str(token.get("token_type", "Bearer")),
            "updated_at": time.time(),
        }
        _write_cache_unlocked(cache)


def load_token(email: str) -> dict[str, Any] | None:
    """Load a cached token record, returning a defensive copy."""
    token = _load_all_tokens().get(_normalize_email(email))
    return dict(token) if isinstance(token, dict) else None


def delete_token(email: str) -> None:
    """Remove one account's cached token without affecting other accounts."""
    key = _normalize_email(email)
    with _cache_lock():
        cache = _read_cache_unlocked()
        if key in cache["accounts"]:
            del cache["accounts"][key]
            _write_cache_unlocked(cache)


def clear_token_cache() -> None:
    """Delete all cached OAuth tokens (used by the reset workflow)."""
    with _cache_lock():
        try:
            get_tokens_path().unlink()
        except FileNotFoundError:
            pass


def _consent_status_for_token(
    token: Mapping[str, Any] | None,
    client_id: str,
) -> ConsentStatus:
    if not token:
        return ConsentStatus(False, "token_missing")
    cached_client_id = token.get("client_id")
    if not cached_client_id or cached_client_id != client_id:
        return ConsentStatus(False, "client_id_changed")

    missing = missing_required_scopes(token.get("scope"))
    if missing:
        return ConsentStatus(False, "missing_scopes", missing)

    requested = {scope.casefold() for scope in _scope_values(token.get("requested_scope"))}
    if OFFLINE_ACCESS_SCOPE.casefold() not in requested or not token.get("refresh_token"):
        return ConsentStatus(False, "offline_access_missing")
    return ConsentStatus(True)


def get_consent_status(email: str, client_id: str) -> ConsentStatus:
    """Inspect cached consent without refreshing or making a network request."""
    return _consent_status_for_token(load_token(email), client_id)


def requires_reconsent(email: str, client_id: str) -> bool:
    """Return whether an existing cache entry needs an interactive sign-in."""
    return get_consent_status(email, client_id).requires_reconsent


def get_access_token(email: str, client_id: str, force_refresh: bool = False) -> str:
    """Return a fully consented access token, refreshing and rotating if needed."""
    cached = load_token(email)
    status = _consent_status_for_token(cached, client_id)
    if status.reason == "token_missing":
        raise OAuthError(
            code=ErrorCode.OAUTH_TOKEN_MISSING,
            message=f"No cached Microsoft sign-in exists for {email}",
            details={"email": email},
        )
    if not status.ready:
        raise OAuthReconsentRequired(
            code=ErrorCode.OAUTH_RECONSENT_REQUIRED,
            message=f"Microsoft authorization for {email} must be renewed",
            details={
                "email": email,
                "reason": status.reason,
                "missing_scopes": list(status.missing_scopes),
            },
        )
    assert cached is not None

    try:
        expires_at = float(cached.get("expires_at", 0))
    except (TypeError, ValueError):
        expires_at = 0
    access_token = cached.get("access_token")
    if (
        not force_refresh
        and isinstance(access_token, str)
        and access_token
        and time.time() < expires_at - EXPIRY_MARGIN
    ):
        return access_token

    refresh = cached.get("refresh_token")
    assert isinstance(refresh, str) and refresh
    refreshed = refresh_token(client_id, refresh)
    requested = _scope_values(cached.get("requested_scope")) or REQUIRED_SCOPES
    save_token(email, refreshed, client_id, requested)

    updated = load_token(email)
    updated_status = _consent_status_for_token(updated, client_id)
    if not updated_status.ready:
        raise OAuthReconsentRequired(
            code=ErrorCode.OAUTH_RECONSENT_REQUIRED,
            message=f"Microsoft no longer grants all required permissions for {email}",
            details={
                "email": email,
                "reason": updated_status.reason,
                "missing_scopes": list(updated_status.missing_scopes),
            },
        )
    assert updated is not None
    refreshed_access = updated.get("access_token")
    assert isinstance(refreshed_access, str) and refreshed_access
    return refreshed_access


def build_xoauth2_bytes(email: str, access_token: str) -> bytes:
    """Build the SASL XOAUTH2 initial response used by IMAP and SMTP."""
    if "\x01" in email or "\x01" in access_token:
        raise ValueError("XOAUTH2 values must not contain control-A")
    return f"user={email}\x01auth=Bearer {access_token}\x01\x01".encode()


def build_xoauth2_base64(email: str, access_token: str) -> str:
    """Build base64 XOAUTH2 text for SMTP's ``AUTH XOAUTH2`` command."""
    return base64.b64encode(build_xoauth2_bytes(email, access_token)).decode("ascii")
