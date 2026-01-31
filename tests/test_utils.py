"""Tests for pattern matching utilities."""

import pytest
from nothx.classifier.utils import matches_pattern


class TestMatchesPattern:
    """Tests for the matches_pattern utility function."""

    def test_exact_match(self):
        """Test exact domain matching."""
        assert matches_pattern("example.com", "example.com") is True
        assert matches_pattern("example.com", "other.com") is False

    def test_exact_match_case_insensitive(self):
        """Test that matching is case-insensitive."""
        assert matches_pattern("Example.COM", "example.com") is True
        assert matches_pattern("example.com", "EXAMPLE.COM") is True

    def test_suffix_pattern(self):
        """Test *.domain.com suffix patterns."""
        # Should match subdomains
        assert matches_pattern("mail.example.com", "*.example.com") is True
        assert matches_pattern("sub.mail.example.com", "*.example.com") is True

        # Should match the base domain itself
        assert matches_pattern("example.com", "*.example.com") is True

        # Should not match unrelated domains
        assert matches_pattern("example.org", "*.example.com") is False
        assert matches_pattern("notexample.com", "*.example.com") is False

    def test_suffix_pattern_gov(self):
        """Test .gov suffix matching."""
        assert matches_pattern("irs.gov", "*.gov") is True
        assert matches_pattern("state.ca.gov", "*.gov") is True
        assert matches_pattern("gov", "*.gov") is True
        assert matches_pattern("notgov.com", "*.gov") is False

    def test_prefix_pattern(self):
        """Test marketing.* prefix patterns."""
        # Should match subdomains starting with prefix
        assert matches_pattern("marketing.company.com", "marketing.*") is True
        assert matches_pattern("marketing.store.io", "marketing.*") is True

        # Should not match if prefix is not followed by a dot
        assert matches_pattern("marketingteam.com", "marketing.*") is False
        assert matches_pattern("company.marketing.com", "marketing.*") is False

    def test_contains_pattern(self):
        """Test *keyword* contains patterns."""
        assert matches_pattern("bankofamerica.com", "*bank*") is True
        assert matches_pattern("mybank.org", "*bank*") is True
        assert matches_pattern("banking.co", "*bank*") is True
        assert matches_pattern("example.com", "*bank*") is False

    def test_complex_patterns(self):
        """Test more complex wildcard patterns."""
        # Pattern with multiple wildcards
        assert matches_pattern("mail.sendgrid.net", "*.sendgrid.net") is True
        assert matches_pattern("sendgrid.net", "*.sendgrid.net") is True

        # Pattern matching health-related domains
        assert matches_pattern("myhealth.hospital.org", "*health*") is True
        assert matches_pattern("healthcare.com", "*health*") is True

    def test_empty_and_edge_cases(self):
        """Test edge cases."""
        # Empty strings
        assert matches_pattern("", "*.com") is False
        assert matches_pattern("example.com", "") is False

        # Pattern is just a wildcard
        assert matches_pattern("anything.com", "*") is True


class TestPatternMatchingIntegration:
    """Integration tests for pattern matching in real scenarios."""

    def test_marketing_service_domains(self):
        """Test matching common email marketing service domains."""
        marketing_domains = [
            "mail.mailchimp.com",
            "bounce.sendgrid.net",
            "email.klaviyo.com",
        ]
        patterns = [
            "*.mailchimp.com",
            "*.sendgrid.net",
            "*.klaviyo.com",
        ]

        for domain in marketing_domains:
            matched = any(matches_pattern(domain, p) for p in patterns)
            assert matched, f"{domain} should match a marketing pattern"

    def test_financial_domains_kept(self):
        """Test that financial domains match keep patterns."""
        financial_domains = [
            "alerts.chase.com",
            "notifications.bankofamerica.com",
            "secure.paypal.com",
        ]

        # These should match *bank* or *.paypal.com patterns
        assert matches_pattern("notifications.bankofamerica.com", "*bank*") is True
        assert matches_pattern("secure.paypal.com", "*.paypal.com") is True

    def test_government_domains_kept(self):
        """Test government domain matching."""
        gov_domains = [
            "irs.gov",
            "cdc.gov",
            "state.ca.gov",
            "hmrc.gov.uk",
        ]

        assert matches_pattern("irs.gov", "*.gov") is True
        assert matches_pattern("hmrc.gov.uk", "*.gov.uk") is True
