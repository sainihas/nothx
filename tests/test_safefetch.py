"""Tests for the SSRF-hardened HTTP helper."""

import io
import urllib.error

import pytest

from nothx import safefetch
from nothx.safefetch import (
    ResolutionError,
    SSRFBlockedError,
    _forbidden_ip,
    _validate_url,
    safe_fetch,
)


class TestForbiddenIp:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",
            "127.8.9.10",
            "10.0.0.5",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",  # cloud metadata
            "169.254.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",  # unique local
            "fe80::1",  # link local
            "::ffff:127.0.0.1",  # v4-mapped loopback
            "::ffff:10.0.0.1",  # v4-mapped private
            "224.0.0.1",  # multicast
            "100.64.0.1",  # carrier-grade NAT (100.64.0.0/10)
            "100.127.255.254",  # CGNAT upper edge
            "192.0.0.1",  # IETF protocol assignments (non-global)
            "not-an-ip",
        ],
    )
    def test_forbidden(self, address):
        assert _forbidden_ip(address) is True

    @pytest.mark.parametrize("address", ["93.184.216.34", "8.8.8.8", "2606:2800:220:1::1"])
    def test_allowed(self, address):
        assert _forbidden_ip(address) is False


class TestValidateUrl:
    def test_https_ok(self):
        parsed = _validate_url("https://example.com/unsub", allow_http=False)
        assert parsed.hostname == "example.com"

    def test_http_blocked_by_default(self):
        with pytest.raises(SSRFBlockedError, match="Scheme"):
            _validate_url("http://example.com/unsub", allow_http=False)

    def test_http_allowed_when_opted_in(self):
        parsed = _validate_url("http://example.com/unsub", allow_http=True)
        assert parsed.hostname == "example.com"

    @pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "gopher://x/"])
    def test_dangerous_schemes_blocked(self, url):
        with pytest.raises(SSRFBlockedError):
            _validate_url(url, allow_http=True)

    def test_embedded_credentials_blocked(self):
        with pytest.raises(SSRFBlockedError, match="credentials"):
            _validate_url("https://user:pass@example.com/", allow_http=False)

    def test_missing_host_blocked(self):
        with pytest.raises(SSRFBlockedError, match="no host"):
            _validate_url("https:///path-only", allow_http=False)


class _FakeResponse:
    def __init__(self, status: int = 200, body: bytes = b"ok"):
        self._status = status
        self.status = status
        self.reason = "test response"
        self.headers = {}
        self._body = io.BytesIO(body)

    def getcode(self) -> int:
        return self._status

    def read(self, n: int = -1) -> bytes:
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _redirect(code: int, location: str) -> urllib.error.HTTPError:
    import email.message

    headers = email.message.Message()
    headers["Location"] = location
    return urllib.error.HTTPError("https://x", code, "redirect", headers, io.BytesIO(b""))


class TestSafeFetch:
    def test_connect_uses_validated_ip_and_strips_sensitive_context(self, monkeypatch):
        """Production transport must not resolve the hostname a second time."""
        captured = {}

        class FakePinnedConnection:
            def __init__(self, host, addresses, **kwargs):
                captured.update(host=host, addresses=addresses, options=kwargs)

            def request(self, method, selector, body=None, headers=None):
                captured.update(method=method, selector=selector, headers=headers or {})

            def getresponse(self):
                return _FakeResponse(200, b"pinned")

            def close(self):
                pass

        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34"])
        monkeypatch.setattr(safefetch, "_PinnedHTTPSConnection", FakePinnedConnection)

        response = safe_fetch(
            "https://example.com/unsub?token=secret",
            headers={
                "Authorization": "Bearer secret",
                "Cookie": "session=secret",
                "Referer": "https://private.example/",
                "X-Safe": "yes",
            },
        )

        assert response.body == "pinned"
        assert captured["host"] == "example.com"
        assert captured["addresses"] == ("93.184.216.34",)
        assert captured["selector"] == "/unsub?token=secret"
        assert captured["headers"]["X-safe"] == "yes"
        assert not {"authorization", "cookie", "referer"} & {
            key.casefold() for key in captured["headers"]
        }

    def test_simple_fetch(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34"])
        monkeypatch.setattr(
            safefetch, "_open_request", lambda req, timeout: _FakeResponse(200, b"done")
        )
        response = safe_fetch("https://example.com/unsub")
        assert response.status == 200
        assert response.body == "done"
        assert response.redirects == 0

    def test_blocks_url_resolving_to_private_ip(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["192.168.1.10"])
        with pytest.raises(SSRFBlockedError, match="forbidden address"):
            safe_fetch("https://internal.example.com/")

    def test_blocks_any_private_address_in_resolution(self, monkeypatch):
        """One good address does not excuse a bad one."""
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34", "10.0.0.1"])
        with pytest.raises(SSRFBlockedError):
            safe_fetch("https://example.com/")

    def test_blocks_ip_literal_url(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_open_request", lambda req, timeout: _FakeResponse())
        with pytest.raises(SSRFBlockedError):
            safe_fetch("https://127.0.0.1:8080/admin")
        with pytest.raises(SSRFBlockedError):
            safe_fetch("https://[::1]/admin")

    def test_follows_redirect_with_revalidation(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34"])
        calls = []

        def fake_open(req, timeout):
            calls.append(req.full_url)
            if len(calls) == 1:
                raise _redirect(302, "https://other.example.com/final")
            return _FakeResponse(200, b"landed")

        monkeypatch.setattr(safefetch, "_open_request", fake_open)
        response = safe_fetch("https://example.com/start")
        assert response.status == 200
        assert response.final_url == "https://other.example.com/final"
        assert response.redirects == 1

    def test_redirect_to_private_ip_blocked(self, monkeypatch):
        """The rebinding case: hop 1 public, hop 2 private."""
        resolutions = {"good.example.com": ["93.184.216.34"], "evil.example.com": ["127.0.0.1"]}
        monkeypatch.setattr(safefetch, "_resolve", lambda host: resolutions[host])

        def fake_open(req, timeout):
            raise _redirect(302, "https://evil.example.com/internal")

        monkeypatch.setattr(safefetch, "_open_request", fake_open)
        with pytest.raises(SSRFBlockedError):
            safe_fetch("https://good.example.com/start")

    def test_redirect_cap(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34"])
        monkeypatch.setattr(
            safefetch,
            "_open_request",
            lambda req, timeout: (_ for _ in ()).throw(_redirect(302, "https://example.com/loop")),
        )
        with pytest.raises(SSRFBlockedError, match="Too many redirects"):
            safe_fetch("https://example.com/start", max_redirects=3)

    def test_redirects_refused_when_disabled(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34"])

        def fake_open(req, timeout):
            raise _redirect(302, "https://example.com/elsewhere")

        monkeypatch.setattr(safefetch, "_open_request", fake_open)
        with pytest.raises(SSRFBlockedError, match="Redirect"):
            safe_fetch("https://example.com/oneclick", follow_redirects=False)

    def test_post_downgraded_to_get_on_303(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34"])
        methods = []

        def fake_open(req, timeout):
            methods.append(req.get_method())
            if len(methods) == 1:
                raise _redirect(303, "https://example.com/result")
            return _FakeResponse(200, b"ok")

        monkeypatch.setattr(safefetch, "_open_request", fake_open)
        safe_fetch("https://example.com/form", method="POST", data=b"x=1")
        assert methods == ["POST", "GET"]

    def test_http_error_propagates(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34"])

        def fake_open(req, timeout):
            raise urllib.error.HTTPError("https://x", 404, "not found", {}, io.BytesIO(b""))

        monkeypatch.setattr(safefetch, "_open_request", fake_open)
        with pytest.raises(urllib.error.HTTPError):
            safe_fetch("https://example.com/gone")

    def test_body_capped(self, monkeypatch):
        monkeypatch.setattr(safefetch, "_resolve", lambda host: ["93.184.216.34"])
        monkeypatch.setattr(
            safefetch, "_open_request", lambda req, timeout: _FakeResponse(200, b"x" * 10000)
        )
        response = safe_fetch("https://example.com/", max_body=100)
        assert len(response.body) == 100


class TestPinnedTransport:
    def test_connect_pinned_tries_only_supplied_addresses(self, monkeypatch):
        calls = []
        sentinel = object()

        def connect(address, **kwargs):
            calls.append((address, kwargs))
            if address[0] == "93.184.216.1":
                raise OSError("first unavailable")
            return sentinel

        monkeypatch.setattr(safefetch.socket, "create_connection", connect)

        result = safefetch._connect_pinned(("93.184.216.1", "93.184.216.2"), 443, 4.0, None)

        assert result is sentinel
        assert [item[0][0] for item in calls] == ["93.184.216.1", "93.184.216.2"]

    def test_connect_pinned_empty_and_all_failed(self, monkeypatch):
        with pytest.raises(OSError, match="no validated"):
            safefetch._connect_pinned((), 443, 1.0, None)

        monkeypatch.setattr(
            safefetch.socket,
            "create_connection",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("unreachable")),
        )
        with pytest.raises(OSError, match="unreachable"):
            safefetch._connect_pinned(("93.184.216.1",), 443, 1.0, None)

    def test_http_connection_uses_pinned_socket(self, monkeypatch):
        raw_socket = object()
        captured = {}

        def connect(addresses, port, timeout, source):
            captured.update(addresses=addresses, port=port, timeout=timeout, source=source)
            return raw_socket

        monkeypatch.setattr(safefetch, "_connect_pinned", connect)
        connection = safefetch._PinnedHTTPConnection(
            "example.com", ("93.184.216.34",), port=8080, timeout=2.5
        )
        connection.connect()

        assert connection.sock is raw_socket
        assert captured == {
            "addresses": ("93.184.216.34",),
            "port": 8080,
            "timeout": 2.5,
            "source": None,
        }

    def test_https_preserves_original_hostname_for_tls(self, monkeypatch):
        class RawSocket:
            closed = False

            def close(self):
                self.closed = True

        raw = RawSocket()
        context = safefetch.ssl.create_default_context()
        captured = {}

        def wrap_socket(raw_socket, *, server_hostname):
            captured["server_hostname"] = server_hostname
            return ("tls", raw_socket)

        monkeypatch.setattr(context, "wrap_socket", wrap_socket)
        monkeypatch.setattr(safefetch, "_connect_pinned", lambda *args: raw)
        connection = safefetch._PinnedHTTPSConnection(
            "mail.example.com",
            ("93.184.216.34",),
            port=443,
            timeout=3.0,
            context=context,
        )
        connection.connect()

        assert captured["server_hostname"] == "mail.example.com"
        assert connection.sock == ("tls", raw)
        assert raw.closed is False

    def test_https_closes_raw_socket_when_tls_fails(self, monkeypatch):
        class RawSocket:
            closed = False

            def close(self):
                self.closed = True

        raw = RawSocket()
        context = safefetch.ssl.create_default_context()

        def fail_wrap(raw_socket, *, server_hostname):
            raise OSError("bad certificate")

        monkeypatch.setattr(context, "wrap_socket", fail_wrap)
        monkeypatch.setattr(safefetch, "_connect_pinned", lambda *args: raw)
        connection = safefetch._PinnedHTTPSConnection(
            "mail.example.com",
            ("93.184.216.34",),
            timeout=1.0,
            context=context,
        )

        with pytest.raises(OSError, match="certificate"):
            connection.connect()
        assert raw.closed is True

    def test_open_request_requires_validated_metadata(self):
        request = safefetch.urllib.request.Request("https://example.com/")
        with pytest.raises(SSRFBlockedError, match="validated destination"):
            safefetch._open_request(request, 1.0)

    def test_validate_host_resolution_errors_and_deduplication(self, monkeypatch):
        monkeypatch.setattr(
            safefetch,
            "_resolve",
            lambda host: ["93.184.216.34", "93.184.216.34"],
        )
        assert safefetch._validate_host("example.com") == ("93.184.216.34",)

        monkeypatch.setattr(safefetch, "_resolve", lambda host: [])
        with pytest.raises(ResolutionError, match="no addresses"):
            safefetch._validate_host("empty.example")

        def resolution_failure(host):
            raise OSError("resolver unavailable")

        monkeypatch.setattr(safefetch, "_resolve", resolution_failure)
        with pytest.raises(ResolutionError, match="DNS resolution failed"):
            safefetch._validate_host("broken.example")

    def test_redacted_log_destination_never_contains_path_or_query(self):
        redacted = safefetch._redacted_url(
            "https://example.com/unsubscribe/opaque-token?recipient=secret"
        )
        assert redacted.endswith(".redacted/(redacted)")
        assert "example.com" not in redacted
        assert "secret" not in redacted
        assert "opaque" not in redacted
        assert safefetch._redacted_url("https://[") == "[invalid URL]"

    def test_redaction_hides_token_bearing_subdomains_but_is_stable(self):
        first = safefetch.redacted_url("https://recipient-secret.mailer.example/u")
        repeat = safefetch.redacted_url("https://recipient-secret.mailer.example/other")
        other = safefetch.redacted_url("https://different-secret.mailer.example/u")

        assert first == repeat
        assert first != other
        assert "recipient-secret" not in first
        assert "mailer.example" not in first
