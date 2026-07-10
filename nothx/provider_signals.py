"""Provider-added spam/bulk signals consumed only inside a trusted mailbox."""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.message import Message

_MS_TOKEN_RE = re.compile(r"(?:^|;)\s*([A-Z][A-Z0-9-]*)\s*:\s*([^;]+)", re.IGNORECASE)
_MS_THREAT_CATEGORIES = {"SPM", "HSPM", "PHSH", "HPHSH", "MALW", "SPOOF"}


@dataclass(frozen=True)
class ProviderSignals:
    """Threat and bulk conclusions from the receiving provider."""

    threat: str | None = None
    bulk: bool = False


def parse_provider_signals(msg: Message, provider: str) -> ProviderSignals:
    """Parse only headers that the configured receiving provider can vouch for.

    Authentication-Results remains the primary trust-boundary control. These
    provider-specific headers are ignored for other account providers so a
    sender cannot gain policy influence merely by adding a familiar header.
    """
    if provider.casefold() != "outlook":
        return ProviderSignals()

    scl_values = msg.get_all("X-MS-Exchange-Organization-SCL", [])
    if scl_values:
        try:
            scl = int(scl_values[0].strip())
            if scl >= 5:
                return ProviderSignals(threat=f"SCL:{scl}")
        except ValueError:
            pass

    # Microsoft prepends its verdict headers. Use only the first instance of
    # each supported header, rather than combining attacker-supplied copies.
    raw_values = []
    for name in ("X-Forefront-Antispam-Report", "X-Microsoft-Antispam"):
        values = msg.get_all(name, [])
        if values:
            raw_values.append(values[0])

    bulk = False
    for raw in raw_values:
        tokens = {key.upper(): value.strip().upper() for key, value in _MS_TOKEN_RE.findall(raw)}
        category = tokens.get("CAT")
        sfv = tokens.get("SFV")
        if category in _MS_THREAT_CATEGORIES:
            return ProviderSignals(threat=category, bulk=bulk)
        if sfv == "SPM":
            return ProviderSignals(threat="SPM", bulk=bulk)
        try:
            # SCL 5/6 is spam and 9 is high-confidence spam/phishing.
            scl = int(tokens.get("SCL", "0"))
            if scl >= 5:
                return ProviderSignals(threat=f"SCL:{scl}", bulk=bulk)
        except ValueError:
            pass
        if category == "BULK":
            bulk = True
        try:
            bulk = bulk or int(tokens.get("BCL", "0")) >= 5
        except ValueError:
            pass
    return ProviderSignals(bulk=bulk)
