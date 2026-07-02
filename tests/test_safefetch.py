"""Tests for the SSRF-hardened HTTP helper."""

import io
import urllib.error

import pytest

from nothx import safefetch
from nothx.safefetch import (
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
