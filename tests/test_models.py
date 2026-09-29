"""Tests for data models, especially header parsing edge cases."""

from datetime import datetime

from nothx.models import EmailHeader


def make_header(sender: str = "user@example.com", list_unsubscribe: str | None = None):
    return EmailHeader(
        sender=sender,
        subject="Test",
        date=datetime(2026, 1, 1),
        message_id="<id@example.com>",
        list_unsubscribe=list_unsubscribe,
    )


class TestSenderAddress:
    def test_bare_address(self):
        assert make_header("user@example.com").sender_address == "user@example.com"

    def test_display_name(self):
        header = make_header('"Acme Store" <deals@acme.com>')
        assert header.sender_address == "deals@acme.com"
        assert header.domain == "acme.com"

    def test_uppercase_normalized(self):
        assert make_header("User@Example.COM").sender_address == "user@example.com"

    def test_malformed_trailing_text(self):
        """parseaddr handles '<bank@example.com> extra' correctly."""
        header = make_header("<bank@example.com> extra")
        assert header.domain == "example.com"

    def test_no_at_sign(self):
        assert make_header("not-an-email").sender_address == ""
        assert make_header("not-an-email").domain == "unknown"

    def test_empty_domain(self):
        assert make_header("user@").domain == "unknown"

    def test_dot_only_domain(self):
        """user@.com must not yield '.com'."""
        assert make_header("user@.com").domain == "unknown"

    def test_trailing_dot_domain(self):
        assert make_header("user@example.").domain == "unknown"

    def test_domain_without_dot(self):
        assert make_header("user@localhost").domain == "unknown"

    def test_empty_sender(self):
        assert make_header("").sender_address == ""
        assert make_header("").domain == "unknown"


class TestListUnsubscribeParsing:
    def test_single_https_url(self):
        header = make_header(list_unsubscribe="<https://example.com/unsub?id=123>")
        assert header.list_unsubscribe_targets == ["https://example.com/unsub?id=123"]
        assert header.list_unsubscribe_url == "https://example.com/unsub?id=123"
        assert header.list_unsubscribe_mailto is None

    def test_url_and_mailto(self):
        header = make_header(
            list_unsubscribe="<https://example.com/unsub>, <mailto:unsub@example.com>"
        )
        assert header.list_unsubscribe_url == "https://example.com/unsub"
        assert header.list_unsubscribe_mailto == "mailto:unsub@example.com"

    def test_preference_order_preserved(self):
        header = make_header(
            list_unsubscribe="<mailto:unsub@example.com>, <https://example.com/unsub>"
        )
        assert header.list_unsubscribe_targets == [
            "mailto:unsub@example.com",
            "https://example.com/unsub",
        ]

    def test_url_containing_comma(self):
        """Commas inside a bracketed URL must not split the URL."""
        url = "https://example.com/unsub?id=1,2,3&tok=a,b"
        header = make_header(list_unsubscribe=f"<{url}>")
        assert header.list_unsubscribe_targets == [url]

    def test_rfc5322_comment_after_bracket(self):
        header = make_header(list_unsubscribe="<https://example.com/unsub> (click to unsubscribe)")
        assert header.list_unsubscribe_targets == ["https://example.com/unsub"]

    def test_folded_header_whitespace_inside_url(self):
        """Header folding can leave CRLF+WSP inside the bracketed URL."""
        header = make_header(list_unsubscribe="<https://example.com/unsub?token=abc\r\n def>")
        assert header.list_unsubscribe_targets == ["https://example.com/unsub?token=abcdef"]

    def test_bare_url_without_brackets(self):
        """Non-compliant senders omit angle brackets entirely."""
        header = make_header(list_unsubscribe="https://example.com/unsub")
        assert header.list_unsubscribe_url == "https://example.com/unsub"

    def test_dangerous_scheme_ignored(self):
        header = make_header(list_unsubscribe="<file:///etc/passwd>")
        assert header.list_unsubscribe_targets == []
        assert header.list_unsubscribe_url is None

    def test_multiple_http_urls(self):
        header = make_header(list_unsubscribe="<https://a.com/u>, <https://b.com/u>")
        assert header.list_unsubscribe_targets == ["https://a.com/u", "https://b.com/u"]
        assert header.list_unsubscribe_url == "https://a.com/u"

    def test_no_header(self):
        header = make_header()
        assert header.list_unsubscribe_targets == []
        assert header.list_unsubscribe_url is None
        assert header.list_unsubscribe_mailto is None

    def test_empty_brackets(self):
        header = make_header(list_unsubscribe="<>")
        assert header.list_unsubscribe_targets == []
