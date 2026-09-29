"""Hardened HTTP fetching for attacker-controlled URLs.

Unsubscribe URLs come from email headers, i.e. from the sender. This module
guards every request against SSRF: scheme allowlisting, private/loopback/
link-local address blocking (for every resolved address), no environment
proxies, no cookies, no auth, and full re-validation on every redirect hop.
The actual socket is connected to one of the already validated IP addresses,
while TLS SNI and certificate verification continue to use the original
hostname.  This closes the DNS-rebinding gap between validation and connect.
"""

import hashlib
import http.client
import ipaddress
import logging
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger("nothx.safefetch")

DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_MAX_BODY = 4096


class SSRFBlockedError(Exception):
    """Raised when a URL fails safety validation."""

    pass


class ResolutionError(OSError):
    """A retryable DNS resolution failure, distinct from an SSRF verdict."""

    pass


@dataclass
class FetchResponse:
    """Result of a safe_fetch call."""

    status: int
    body: str
    final_url: str
    redirects: int


_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "proxy-connection",
        "referer",
    }
)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose socket can only use pre-validated addresses."""

    def __init__(self, host: str, addresses: tuple[str, ...], **kwargs):
        self._pinned_addresses = addresses
        self._pinned_timeout: float | None = kwargs.get("timeout")
        self._pinned_source_address: tuple[str, int] | None = kwargs.get("source_address")
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = _connect_pinned(
            self._pinned_addresses,
            self.port,
            self._pinned_timeout,
            self._pinned_source_address,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Pinned socket with normal PKIX verification and hostname-bound SNI."""

    def __init__(self, host: str, addresses: tuple[str, ...], **kwargs):
        self._pinned_addresses = addresses
        self._pinned_timeout: float | None = kwargs.get("timeout")
        self._pinned_source_address: tuple[str, int] | None = kwargs.get("source_address")
        self._pinned_context: ssl.SSLContext = kwargs.get("context") or ssl.create_default_context()
        kwargs["context"] = self._pinned_context
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        raw_socket = _connect_pinned(
            self._pinned_addresses,
            self.port,
            self._pinned_timeout,
            self._pinned_source_address,
        )
        try:
            # ``self.host`` is the original URL hostname, never the pinned IP.
            # HTTPSConnection creates a default verifying SSLContext for us.
            self.sock = self._pinned_context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def _connect_pinned(
    addresses: tuple[str, ...],
    port: int,
    timeout: float | None,
    source_address: tuple[str, int] | None,
) -> socket.socket:
    """Connect to one of the exact addresses that passed SSRF validation."""
    last_error: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection(
                (address, port), timeout=timeout, source_address=source_address
            )
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError("no validated address available")


def _resolve(hostname: str) -> list[str]:
    """Resolve a hostname to all of its addresses. Seam for tests."""
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def _open_request(request: urllib.request.Request, timeout: float):
    """Perform a proxy-free request over the request's validated IP set.

    ``safe_fetch`` annotates the Request only after resolving and validating
    every address.  Keeping this as a two-argument seam preserves simple unit
    tests while production connections cannot perform a second DNS lookup.
    """
    parsed = urllib.parse.urlsplit(request.full_url)
    hostname = parsed.hostname
    addresses = getattr(request, "_nothx_validated_addresses", None)
    if not hostname or not isinstance(addresses, tuple) or not addresses:
        raise SSRFBlockedError("request has no validated destination")

    try:
        port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    except ValueError as exc:
        raise SSRFBlockedError("URL has an invalid port") from exc

    connection_type = (
        _PinnedHTTPSConnection if parsed.scheme.casefold() == "https" else _PinnedHTTPConnection
    )
    connection = connection_type(hostname, addresses, port=port, timeout=timeout)
    request_headers = {
        key: value
        for key, value in request.header_items()
        if key.casefold() not in _SENSITIVE_HEADERS
    }
    request_headers["Connection"] = "close"
    selector = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    try:
        connection.request(
            request.get_method(),
            selector,
            body=request.data,
            headers=request_headers,
        )
        response = connection.getresponse()
    except Exception:
        connection.close()
        raise

    if response.status >= 300:
        raise urllib.error.HTTPError(
            request.full_url,
            response.status,
            response.reason,
            response.headers,
            response,
        )
    return response


def _forbidden_ip(address: str) -> bool:
    """True if the address points at a network location we must not touch."""
    try:
        ip = ipaddress.ip_address(address.split("%")[0])  # strip zone id
    except ValueError:
        return True  # unparseable = do not connect
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 must be judged as 127.0.0.1
    # `not is_global` is the primary gate: it rejects any address that isn't
    # globally routable, including carrier-grade NAT / shared space
    # (100.64.0.0/10) which is neither is_private nor is_reserved. The explicit
    # flags remain as defense in depth / documentation of intent.
    return (
        not ip.is_global
        or ip.is_loopback
        or ip.is_private
        or ip.is_link_local  # includes 169.254.169.254 metadata endpoints
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _validate_url(url: str, allow_http: bool) -> urllib.parse.SplitResult:
    """Validate scheme and structure; return the parsed URL."""
    parsed = urllib.parse.urlsplit(url)
    allowed = ("https", "http") if allow_http else ("https",)
    if parsed.scheme.lower() not in allowed:
        raise SSRFBlockedError(f"Scheme not allowed: {parsed.scheme or '(none)'}")
    if not parsed.hostname:
        raise SSRFBlockedError("URL has no host")
    if parsed.username is not None or parsed.password is not None:
        raise SSRFBlockedError("URLs with embedded credentials are not allowed")
    return parsed


def _validate_host(hostname: str) -> tuple[str, ...]:
    """Reject unsafe resolutions and return the exact public addresses."""
    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            addresses = _resolve(hostname)
        except OSError as e:
            raise ResolutionError("DNS resolution failed") from e
        if not addresses:
            raise ResolutionError("DNS resolution returned no addresses") from None
    for address in addresses:
        if _forbidden_ip(address):
            raise SSRFBlockedError(f"Host {hostname} resolves to forbidden address {address}")
    # De-duplicate without changing resolver preference order.
    return tuple(dict.fromkeys(addresses))


def redacted_host(hostname: str) -> str:
    """Return a stable opaque host label without leaking subdomain tokens."""
    candidate = hostname.strip().casefold().rstrip(".")
    if not candidate:
        raise ValueError("empty hostname")
    try:
        normalized = ipaddress.ip_address(candidate.split("%", 1)[0]).compressed
    except ValueError:
        normalized = candidate.encode("idna").decode("ascii").casefold()
    digest = hashlib.sha256(normalized.encode("ascii")).hexdigest()[:12]
    return f"host-{digest}.redacted"


def redacted_url(url: str, *, include_scheme: bool = True) -> str:
    """Render a stable destination without host, path, query, or fragment tokens."""
    try:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.casefold()
        if scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("unsupported URL")
        host = redacted_host(parsed.hostname)
    except (UnicodeError, ValueError):
        return "[invalid URL]"
    prefix = f"{scheme}://" if include_scheme else ""
    # Parentheses render literally in Rich terminals; square brackets would
    # be consumed as an unknown markup tag by CLI callers.
    return f"{prefix}{host}/(redacted)"


def _redacted_url(url: str) -> str:
    """Backward-compatible internal wrapper used by redirect logging."""
    return redacted_url(url, include_scheme=False)


def safe_fetch(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_body: int = DEFAULT_MAX_BODY,
    allow_http: bool = False,
    follow_redirects: bool = True,
) -> FetchResponse:
    """Fetch a URL with SSRF protection, re-validating every redirect hop.

    Raises:
        SSRFBlockedError: If any hop fails safety validation.
        ResolutionError: If DNS resolution fails transiently.
        urllib.error.HTTPError: For non-redirect HTTP error statuses.
        urllib.error.URLError / OSError: For network failures.
    """
    current_url = url
    current_method = method
    current_data = data
    redirects = 0

    while True:
        parsed = _validate_url(current_url, allow_http)
        addresses = _validate_host(parsed.hostname)  # type: ignore[arg-type]

        request = urllib.request.Request(
            current_url,
            data=current_data,
            headers=dict(headers or {}),
            method=current_method,
        )
        # urllib Request deliberately has no public extension metadata slot;
        # this private marker is local to this module and never serialized.
        request._nothx_validated_addresses = addresses  # type: ignore[attr-defined]
        try:
            with _open_request(request, timeout) as response:
                body = response.read(max_body).decode("utf-8", errors="replace")
                return FetchResponse(
                    status=response.getcode(),
                    body=body,
                    final_url=current_url,
                    redirects=redirects,
                )
        except urllib.error.HTTPError as e:
            if e.code not in (301, 302, 303, 307, 308):
                raise
            if not follow_redirects:
                raise SSRFBlockedError(
                    f"Redirect (HTTP {e.code}) not allowed for this request"
                ) from e
            if redirects >= max_redirects:
                raise SSRFBlockedError(f"Too many redirects (>{max_redirects})") from e
            location = e.headers.get("Location")
            if not location:
                raise SSRFBlockedError("Redirect without Location header") from e
            current_url = urllib.parse.urljoin(current_url, location)
            if e.code == 303 or (e.code in (301, 302) and current_method == "POST"):
                current_method = "GET"
                current_data = None
            redirects += 1
            logger.debug("Following redirect %d to %s", redirects, _redacted_url(current_url))
