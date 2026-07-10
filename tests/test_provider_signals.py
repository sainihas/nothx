"""Trusted provider verdict adapter coverage."""

import email

import pytest

from nothx.provider_signals import ProviderSignals, parse_provider_signals


def _message(*headers: str):
    return email.message_from_string("\n".join(headers) + "\n\n")


def test_non_outlook_accounts_ignore_microsoft_headers():
    message = _message("X-Forefront-Antispam-Report: CAT:PHSH;SCL:9;")
    assert parse_provider_signals(message, "gmail") == ProviderSignals()


@pytest.mark.parametrize("category", ["SPM", "HSPM", "PHSH", "HPHSH", "MALW", "SPOOF"])
def test_microsoft_threat_categories(category):
    message = _message(f"X-Forefront-Antispam-Report: CAT:{category};")
    assert parse_provider_signals(message, "outlook").threat == category


def test_sfv_and_embedded_scl_are_strong_spam_verdicts():
    sfv = _message("X-Microsoft-Antispam: SFV:SPM;")
    scl = _message("X-Forefront-Antispam-Report: CAT:NONE;SCL:6;")

    assert parse_provider_signals(sfv, "outlook").threat == "SPM"
    assert parse_provider_signals(scl, "outlook").threat == "SCL:6"


def test_bulk_category_and_bcl_are_non_threat_bulk_evidence():
    category = _message("X-Forefront-Antispam-Report: CAT:BULK;SCL:1;")
    bcl = _message("X-Microsoft-Antispam: CAT:NONE;BCL:7;")

    assert parse_provider_signals(category, "outlook") == ProviderSignals(bulk=True)
    assert parse_provider_signals(bcl, "outlook") == ProviderSignals(bulk=True)


def test_invalid_numeric_values_fail_closed_without_crashing():
    message = _message(
        "X-MS-Exchange-Organization-SCL: invalid",
        "X-Forefront-Antispam-Report: SCL:invalid;BCL:invalid;CAT:NONE;",
    )

    assert parse_provider_signals(message, "outlook") == ProviderSignals()


def test_only_first_instance_of_each_trusted_header_is_used():
    message = _message(
        "X-Forefront-Antispam-Report: CAT:NONE;SCL:1;",
        "X-Forefront-Antispam-Report: CAT:PHSH;SCL:9;",
    )

    assert parse_provider_signals(message, "outlook") == ProviderSignals()
