"""Tests for Authentication-Results parsing (RFC 8601)."""

from nothx.authres import parse_authentication_results


class TestGmail:
    def test_all_pass(self):
        header = "mx.google.com; spf=pass smtp.mailfrom=x.com; dkim=pass header.d=x.com; dmarc=pass"
        v = parse_authentication_results([header], "gmail")
        assert v.spf is True and v.dkim is True and v.dmarc is True

    def test_dkim_fail(self):
        header = "mx.google.com; dkim=fail; spf=pass; dmarc=fail"
        v = parse_authentication_results([header], "gmail")
        assert v.dkim is False
        assert v.dmarc is False
        assert v.spf is True

    def test_none_is_unknown(self):
        header = "mx.google.com; spf=none; dkim=none; dmarc=none"
        v = parse_authentication_results([header], "gmail")
        assert v.spf is None and v.dkim is None and v.dmarc is None

    def test_softfail_is_unknown(self):
        v = parse_authentication_results(["mx.google.com; spf=softfail"], "gmail")
        assert v.spf is None

    def test_comments_stripped(self):
        header = "mx.google.com; dkim=pass (good signature) header.d=x.com; spf=pass"
        v = parse_authentication_results([header], "gmail")
        assert v.dkim is True and v.spf is True

    def test_folded_header(self):
        header = "mx.google.com;\r\n  dkim=pass;\r\n  spf=pass"
        v = parse_authentication_results([header], "gmail")
        assert v.dkim is True and v.spf is True


class TestUntrustedInstances:
    def test_forged_instance_ignored(self):
        """Only the instance matching the provider's authserv-id is trusted."""
        trusted = "mx.google.com; dkim=fail; dmarc=fail"
        forged = "evil-relay.attacker.com; dkim=pass; dmarc=pass"
        v = parse_authentication_results([trusted, forged], "gmail")
        assert v.dkim is False
        assert v.dmarc is False

    def test_no_matching_instance(self):
        v = parse_authentication_results(["some-other-mta.example.com; dkim=pass"], "gmail")
        assert v.dkim is None


class TestMicrosoftFormat:
    def test_no_authserv_id(self):
        """Microsoft omits the authserv-id: 'spf=pass; dkim=pass'."""
        header = "spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=x.com; dkim=pass; dmarc=pass action=none"
        v = parse_authentication_results([header], "outlook")
        assert v.spf is True and v.dkim is True and v.dmarc is True

    def test_gmail_does_not_trust_missing_authserv(self):
        header = "spf=pass; dkim=pass; dmarc=pass"
        v = parse_authentication_results([header], "gmail")
        assert v.dkim is None  # gmail requires mx.google.com


class TestUnknownProvider:
    def test_custom_provider_trusts_nothing(self):
        v = parse_authentication_results(["mail.custom.example; dkim=pass"], "fastmail")
        assert v.dkim is None and v.spf is None and v.dmarc is None

    def test_empty_headers(self):
        v = parse_authentication_results([], "gmail")
        assert v == parse_authentication_results([None], "gmail")
