"""Hardened HTTP fetching for attacker-controlled URLs.

Unsubscribe URLs come from email headers, i.e. from the sender. This module
guards every request against SSRF: scheme allowlisting, private/loopback/
link-local address blocking (for every resolved address), no environment
proxies, no cookies, no auth, and full re-validation on every redirect hop.

Known residual risk: the hostname is resolved once for validation and again
by urllib for the connection, so a DNS-rebinding attacker with a sub-second
TTL could pass validation and connect elsewhere. True IP pinning requires a
custom HTTPSConnection; out of proportion to the threat model here.
"""

import ipaddress
import logging
import socket
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


@dataclass
class FetchResponse:
    """Result of a safe_fetch call."""

    status: int
    body: str
    final_url: str
    redirects: int


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface every 3xx as an HTTPError so redirects are handled manually."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# No proxies from the environment (an SSRF vector of its own), no cookie
# processor (RFC 8058: the request must not carry cookies or auth context).
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _resolve(hostname: str) -> list[str]:
    """Resolve a hostname to all of its addresses. Seam for tests."""
    infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def _open_request(request: urllib.request.Request, timeout: float):
    """Perform the actual network call. Seam for tests."""
    return _opener.open(request, timeout=timeout)


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


def _validate_host(hostname: str) -> None:
    """Reject hostnames that are, or resolve to, forbidden addresses."""
    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            addresses = _resolve(hostname)
        except OSError as e:
            raise SSRFBlockedError(f"Cannot resolve host {hostname}: {e}") from e
        if not addresses:
            raise SSRFBlockedError(f"Host {hostname} resolved to no addresses") from None
    for address in addresses:
        if _forbidden_ip(address):
            raise SSRFBlockedError(f"Host {hostname} resolves to forbidden address {address}")


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
        urllib.error.HTTPError: For non-redirect HTTP error statuses.
        urllib.error.URLError / OSError: For network failures.
    """
    current_url = url
    current_method = method
    current_data = data
    redirects = 0

    while True:
        parsed = _validate_url(current_url, allow_http)
        _validate_host(parsed.hostname)  # type: ignore[arg-type]

        request = urllib.request.Request(
            current_url,
            data=current_data,
            headers=dict(headers or {}),
            method=current_method,
        )
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
            logger.debug("Following redirect %d to %s", redirects, current_url)
