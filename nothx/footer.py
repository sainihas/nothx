"""Bounded, local-only discovery of unsubscribe links in message footers.

This module deliberately does not fetch messages or execute candidates.  It
selects a very small set of safe inline text MIME sections from a supplied
BODYSTRUCTURE and inspects supplied partial/decoded text.  Every returned URI
is marked as a footer source and therefore must never be used as RFC 8058
one-click POST material.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import quopri
import re
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any

from .models import FooterUnsubscribeCandidate

MAX_MIME_NODES = 50
MAX_INLINE_PARTS = 2
MAX_PART_BYTES = 64 * 1024
MAX_TOTAL_BYTES = 128 * 1024
MAX_CANDIDATES = 5
MAX_MESSAGES_PER_ACCOUNT = 100
MAX_TARGET_LENGTH = 4096
MAX_BODYSTRUCTURE_BYTES = 256 * 1024
MAX_BODYSTRUCTURE_TOKENS = 4096
MAX_BODYSTRUCTURE_DEPTH = 64

_SUPPORTED_TEXT_TYPES = frozenset({"text/plain", "text/html"})
_SUPPORTED_ENCODINGS = frozenset({"7bit", "8bit", "binary", "base64", "quoted-printable"})
_TARGET_RE = re.compile(r"(?i)(?:https://|mailto:)[^\s<>\"']+")
_EVIDENCE_RE = re.compile(
    r"(?i)\b("
    r"unsubscribe|un-subscribe|"
    r"opt(?:\s|-)?out|"
    r"(?:manage\s+)?(?:email\s+|subscription\s+|notification\s+)?preferences?"
    r")\b"
)
_ADDR_RE = re.compile(
    r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


@dataclass(frozen=True)
class FooterLimits:
    """Resource limits applied before any untrusted footer is parsed."""

    max_mime_nodes: int = MAX_MIME_NODES
    max_parts: int = MAX_INLINE_PARTS
    max_part_bytes: int = MAX_PART_BYTES
    max_total_bytes: int = MAX_TOTAL_BYTES
    max_candidates: int = MAX_CANDIDATES
    max_structure_bytes: int = MAX_BODYSTRUCTURE_BYTES
    max_structure_tokens: int = MAX_BODYSTRUCTURE_TOKENS
    max_structure_depth: int = MAX_BODYSTRUCTURE_DEPTH

    def __post_init__(self) -> None:
        for value in (
            self.max_mime_nodes,
            self.max_parts,
            self.max_part_bytes,
            self.max_total_bytes,
            self.max_candidates,
            self.max_structure_bytes,
            self.max_structure_tokens,
            self.max_structure_depth,
        ):
            if value <= 0:
                raise ValueError("footer limits must be positive")


@dataclass(frozen=True)
class FooterPartSpec:
    """An inline MIME leaf and the bounded tail range the caller may fetch."""

    section: str
    content_type: str
    charset: str
    transfer_encoding: str
    octets: int
    fetch_start: int
    fetch_count: int

    @property
    def imap_partial(self) -> str:
        """BODY.PEEK section fragment suitable for an IMAP FETCH item."""
        return f"BODY.PEEK[{self.section}]<{self.fetch_start}.{self.fetch_count}>"


@dataclass(frozen=True)
class BodyStructureSelection:
    """Result of walking an untrusted BODYSTRUCTURE under hard limits."""

    parts: tuple[FooterPartSpec, ...]
    nodes_seen: int
    truncated: bool = False
    parse_error: str | None = None


@dataclass(frozen=True)
class InlineTextPart:
    """One supplied inline part, either decoded text or transfer-encoded bytes."""

    section: str
    content_type: str
    content: str | bytes
    charset: str = "utf-8"
    transfer_encoding: str = "decoded"
    disposition: str | None = None
    filename: str | None = None
    partial: bool = True


@dataclass(frozen=True)
class FooterExtraction:
    """Bounded candidates plus diagnostic counters (never message content)."""

    candidates: tuple[FooterUnsubscribeCandidate, ...]
    parts_examined: int
    bytes_examined: int
    rejected_targets: int = 0
    forms_seen: bool = False
    truncated: bool = False


class BodyStructureError(ValueError):
    """Raised when an IMAP BODYSTRUCTURE value cannot be parsed safely."""


class _BodyTokenizer:
    def __init__(self, value: str | bytes, limits: FooterLimits):
        if isinstance(value, str):
            # Check characters before encoding so a huge string cannot cause a
            # second unbounded allocation merely to discover it is too large.
            if len(value) > limits.max_structure_bytes:
                raise BodyStructureError("BODYSTRUCTURE exceeds the byte limit")
            data = value.encode("utf-8")
        else:
            data = value
        if len(data) > limits.max_structure_bytes:
            raise BodyStructureError("BODYSTRUCTURE exceeds the byte limit")
        self.data = data
        self.offset = 0
        self.limits = limits
        self.tokens_seen = 0

    def _skip_space(self) -> None:
        while self.offset < len(self.data) and self.data[self.offset] in b" \t\r\n":
            self.offset += 1

    def parse(self) -> Any:
        self._skip_space()
        value = self._value(0)
        self._skip_space()
        if self.offset != len(self.data):
            raise BodyStructureError("unexpected data after BODYSTRUCTURE")
        return value

    def _value(self, depth: int) -> Any:
        if depth > self.limits.max_structure_depth:
            raise BodyStructureError("BODYSTRUCTURE exceeds the nesting limit")
        self.tokens_seen += 1
        if self.tokens_seen > self.limits.max_structure_tokens:
            raise BodyStructureError("BODYSTRUCTURE exceeds the token limit")
        self._skip_space()
        if self.offset >= len(self.data):
            raise BodyStructureError("unexpected end of BODYSTRUCTURE")
        current = self.data[self.offset]
        if current == ord("("):
            return self._list(depth)
        if current == ord('"'):
            return self._quoted()
        if current == ord("{"):
            return self._literal()
        return self._atom()

    def _list(self, depth: int) -> list[Any]:
        self.offset += 1
        result: list[Any] = []
        while True:
            self._skip_space()
            if self.offset >= len(self.data):
                raise BodyStructureError("unterminated BODYSTRUCTURE list")
            if self.data[self.offset] == ord(")"):
                self.offset += 1
                return result
            result.append(self._value(depth + 1))

    def _quoted(self) -> str:
        self.offset += 1
        result = bytearray()
        while self.offset < len(self.data):
            current = self.data[self.offset]
            self.offset += 1
            if current == ord('"'):
                return result.decode("utf-8", errors="replace")
            if current == ord("\\"):
                if self.offset >= len(self.data):
                    raise BodyStructureError("unterminated quoted escape")
                current = self.data[self.offset]
                self.offset += 1
            result.append(current)
        raise BodyStructureError("unterminated quoted string")

    def _literal(self) -> str:
        close = self.data.find(b"}", self.offset)
        if close < 0:
            raise BodyStructureError("unterminated literal length")
        length_raw = self.data[self.offset + 1 : close].rstrip(b"+")
        if not length_raw.isdigit():
            raise BodyStructureError("invalid literal length")
        self.offset = close + 1
        if self.data[self.offset : self.offset + 2] == b"\r\n":
            self.offset += 2
        elif self.data[self.offset : self.offset + 1] == b"\n":
            self.offset += 1
        else:
            raise BodyStructureError("literal is missing line ending")
        length = int(length_raw)
        end = self.offset + length
        if end > len(self.data):
            raise BodyStructureError("truncated literal")
        value = self.data[self.offset : end]
        self.offset = end
        return value.decode("utf-8", errors="replace")

    def _atom(self) -> Any:
        start = self.offset
        while self.offset < len(self.data) and self.data[self.offset] not in b"() \t\r\n":
            self.offset += 1
        raw = self.data[start : self.offset]
        if not raw:
            raise BodyStructureError("empty BODYSTRUCTURE atom")
        if raw.upper() == b"NIL":
            return None
        if raw.isdigit():
            return int(raw)
        return raw.decode("utf-8", errors="replace")


def _string(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _parameters(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        return {}
    result: dict[str, str] = {}
    for index in range(0, len(value) - 1, 2):
        key, item = value[index : index + 2]
        if isinstance(key, str) and isinstance(item, str):
            result[key.casefold()] = item
    return result


def _disposition(value: Any) -> tuple[str | None, dict[str, str]]:
    if not isinstance(value, list) or not value:
        return None, {}
    kind = value[0].casefold() if isinstance(value[0], str) else None
    params = _parameters(value[1]) if len(value) > 1 else {}
    return kind, params


class _BodySelector:
    def __init__(self, limits: FooterLimits):
        self.limits = limits
        self.parts: list[FooterPartSpec] = []
        self.nodes_seen = 0
        self.bytes_planned = 0
        self.truncated = False

    def visit(self, node: Any, path: tuple[int, ...] = ()) -> None:
        if len(self.parts) >= self.limits.max_parts:
            self.truncated = True
            return
        if self.nodes_seen >= self.limits.max_mime_nodes:
            self.truncated = True
            return
        if not isinstance(node, list) or not node:
            return
        self.nodes_seen += 1

        if isinstance(node[0], list):
            child_count = 0
            while child_count < len(node) and isinstance(node[child_count], list):
                child_count += 1
            # Multipart extension fields: subtype, parameters, disposition.
            parent_disposition, _ = _disposition(
                node[child_count + 2] if len(node) > child_count + 2 else None
            )
            if parent_disposition == "attachment":
                return
            for index, child in enumerate(node[:child_count], start=1):
                self.visit(child, (*path, index))
                if len(self.parts) >= self.limits.max_parts:
                    if index < child_count:
                        self.truncated = True
                    return
            return

        major = _string(node[0]).casefold()
        subtype = _string(node[1] if len(node) > 1 else None).casefold()
        content_type = f"{major}/{subtype}"
        # Never descend into encapsulated messages.
        if content_type == "message/rfc822" or content_type not in _SUPPORTED_TEXT_TYPES:
            return

        params = _parameters(node[2] if len(node) > 2 else None)
        encoding = _string(node[5] if len(node) > 5 else None, "7bit").casefold()
        octets = node[6] if len(node) > 6 and isinstance(node[6], int) else 0
        # Text body extension fields follow the mandatory line count at index 7.
        disposition, disposition_params = _disposition(node[9] if len(node) > 9 else None)
        filename = disposition_params.get("filename") or params.get("name")
        if (
            disposition not in (None, "inline")
            or filename
            or encoding not in _SUPPORTED_ENCODINGS
            or octets <= 0
        ):
            return

        remaining = self.limits.max_total_bytes - self.bytes_planned
        if remaining <= 0:
            self.truncated = True
            return
        count = min(octets, self.limits.max_part_bytes, remaining)
        start = max(0, octets - count)
        if encoding == "base64" and start:
            # Starting on a base64 quantum lets a partial tail decode locally.
            aligned_start = start + (-start % 4)
            count = octets - aligned_start
            start = aligned_start
        section = ".".join(str(value) for value in path) if path else "1"
        self.parts.append(
            FooterPartSpec(
                section=section,
                content_type=content_type,
                charset=params.get("charset", "utf-8"),
                transfer_encoding=encoding,
                octets=octets,
                fetch_start=start,
                fetch_count=count,
            )
        )
        self.bytes_planned += count


def select_footer_parts(
    bodystructure: str | bytes, *, limits: FooterLimits | None = None
) -> BodyStructureSelection:
    """Select at most two safe inline text leaves from a BODYSTRUCTURE value."""
    active_limits = limits or FooterLimits()
    try:
        root = _BodyTokenizer(bodystructure, active_limits).parse()
    except (BodyStructureError, RecursionError, UnicodeError, ValueError) as exc:
        return BodyStructureSelection((), 0, parse_error=str(exc))
    selector = _BodySelector(active_limits)
    selector.visit(root)
    return BodyStructureSelection(
        tuple(selector.parts), selector.nodes_seen, truncated=selector.truncated
    )


@dataclass
class _Anchor:
    href: str
    start: int
    end: int = 0


class _FooterHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text = ""
        self.anchors: list[_Anchor] = []
        self._active_anchor: _Anchor | None = None
        self._suppressed_depth = 0
        self._form_depth = 0
        self.forms_seen = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        if lowered in ("script", "style"):
            self._suppressed_depth += 1
            return
        if lowered == "form":
            self.forms_seen = True
            self._form_depth += 1
            return
        if lowered != "a" or self._suppressed_depth or self._form_depth:
            return
        values = {key.casefold(): value for key, value in attrs}
        href = values.get("href")
        if href:
            self._active_anchor = _Anchor(href, len(self.text))

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.casefold()
        if lowered in ("script", "style") and self._suppressed_depth:
            self._suppressed_depth -= 1
            return
        if lowered == "form" and self._form_depth:
            self._form_depth -= 1
            return
        if lowered == "a" and self._active_anchor is not None:
            self._active_anchor.end = len(self.text)
            self.anchors.append(self._active_anchor)
            self._active_anchor = None

    def handle_data(self, data: str) -> None:
        if not self._suppressed_depth:
            self.text += data

    def close(self) -> None:
        super().close()
        if self._active_anchor is not None:
            self._active_anchor.end = len(self.text)
            self.anchors.append(self._active_anchor)
            self._active_anchor = None


def _decode_text(value: bytes, charset: str) -> str:
    try:
        return value.decode(charset or "utf-8", errors="replace")
    except LookupError:
        return value.decode("utf-8", errors="replace")


def _bounded_decode(part: InlineTextPart, limit: int) -> tuple[str, int, bool]:
    if isinstance(part.content, str):
        # At most ``limit`` trailing characters are encoded; UTF-8 expansion is
        # then capped by bytes.  This avoids allocating from an unbounded input.
        raw = part.content[-limit:].encode("utf-8", errors="replace")
        truncated = len(part.content) > limit or len(raw) > limit
        tail = raw[-limit:]
        return _decode_text(tail, "utf-8"), len(tail), truncated

    raw = part.content
    truncated = len(raw) > limit
    encoding = part.transfer_encoding.casefold()
    if encoding == "base64":
        # Only process the bounded tail.  With a complete base64 value, the
        # amount removed below aligns the retained suffix to a new quantum.
        clean = b"".join(raw[-limit:].split())
        if offset := len(clean) % 4:
            clean = clean[offset:]
        tail = clean
        try:
            decoded = base64.b64decode(tail + b"=" * (-len(tail) % 4), validate=False)
        except (binascii.Error, ValueError):
            return "", len(tail), truncated
        decoded = decoded[-limit:]
        return _decode_text(decoded, part.charset), len(tail), truncated
    if encoding == "quoted-printable":
        tail = raw[-limit:]
        if (part.partial or truncated) and b"\n" in tail:
            tail = tail.split(b"\n", 1)[1]
        decoded = quopri.decodestring(tail)[-limit:]
        return _decode_text(decoded, part.charset), len(tail), truncated
    tail = raw[-limit:]
    return _decode_text(tail, part.charset), len(tail), truncated


def _mailto_is_safe(uri: str) -> bool:
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme.casefold() != "mailto" or parsed.netloc or parsed.fragment:
        return False
    try:
        recipient = urllib.parse.unquote(parsed.path, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return False
    if not _ADDR_RE.fullmatch(recipient) or any(ord(char) > 127 for char in recipient):
        return False
    try:
        fields = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=2,
            encoding="utf-8",
            errors="strict",
        )
    except (UnicodeDecodeError, ValueError):
        return False
    keys = [key.casefold() for key, _ in fields]
    if len(keys) != len(set(keys)) or any(key not in ("subject", "body") for key in keys):
        return False
    for key, value in fields:
        if key.casefold() == "subject" and any(character in value for character in "\r\n\0"):
            return False
        if key.casefold() == "body" and len(value.encode("utf-8")) > 2048:
            return False
    return True


def _https_is_safe(uri: str) -> bool:
    if any(ord(character) < 32 or ord(character) == 127 for character in uri):
        return False
    try:
        parsed = urllib.parse.urlsplit(uri)
        # Accessing port validates malformed/out-of-range values.
        _ = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.casefold() == "https"
        and bool(parsed.hostname)
        and parsed.username is None
        and parsed.password is None
    )


def _strip_plain_punctuation(uri: str) -> str:
    uri = uri.rstrip(".,;:!?")
    for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
        while uri.endswith(closing) and uri.count(closing) > uri.count(opening):
            uri = uri[:-1]
    return uri


def _candidate(uri: str, context: str, source: str) -> FooterUnsubscribeCandidate | None:
    uri = _strip_plain_punctuation(uri.strip())
    if not uri or len(uri) > MAX_TARGET_LENGTH:
        return None
    evidence = _EVIDENCE_RE.search(f"{context} {urllib.parse.unquote(uri)}")
    if not evidence:
        return None
    scheme = urllib.parse.urlsplit(uri).scheme.casefold()
    if scheme == "https" and _https_is_safe(uri):
        pass
    elif scheme == "mailto" and _mailto_is_safe(uri):
        pass
    else:
        return None
    return FooterUnsubscribeCandidate(
        uri=uri,
        source=source,
        # Persistable evidence is only the matched generic phrase, never body text.
        evidence=evidence.group(0).casefold(),
    )


def _plain_targets(text: str) -> Iterable[tuple[str, str]]:
    for match in _TARGET_RE.finditer(text):
        context = text[max(0, match.start() - 160) : min(len(text), match.end() + 160)]
        yield match.group(0), context


def _html_targets(text: str) -> tuple[list[tuple[str, str]], bool]:
    parser = _FooterHTMLParser()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError):
        return [], parser.forms_seen
    targets = []
    for anchor in parser.anchors:
        context = parser.text[max(0, anchor.start - 160) : min(len(parser.text), anchor.end + 160)]
        targets.append((anchor.href, context))
    return targets, parser.forms_seen


def extract_footer_candidates(
    parts: Iterable[InlineTextPart], *, limits: FooterLimits | None = None
) -> FooterExtraction:
    """Inspect bounded inline text tails and return safe footer candidates.

    Attachments, nested messages, forms, resources, relative links, HTTP links,
    and mailto targets with multiple recipients or non-body headers are never
    returned.  Candidate bodies are not retained in the result.
    """
    active_limits = limits or FooterLimits()
    candidates: list[FooterUnsubscribeCandidate] = []
    seen: set[str] = set()
    bytes_examined = 0
    parts_examined = 0
    rejected = 0
    forms_seen = False
    truncated = False

    for node_index, part in enumerate(parts, start=1):
        if node_index > active_limits.max_mime_nodes:
            truncated = True
            break
        content_type = part.content_type.split(";", 1)[0].strip().casefold()
        disposition = (part.disposition or "inline").casefold()
        if content_type not in _SUPPORTED_TEXT_TYPES or disposition != "inline" or part.filename:
            continue
        if parts_examined >= active_limits.max_parts:
            truncated = True
            break
        remaining = active_limits.max_total_bytes - bytes_examined
        if remaining <= 0:
            truncated = True
            break
        per_part_limit = min(active_limits.max_part_bytes, remaining)
        text, consumed, part_truncated = _bounded_decode(part, per_part_limit)
        bytes_examined += consumed
        parts_examined += 1
        truncated = truncated or part_truncated

        if content_type == "text/html":
            targets, found_form = _html_targets(text)
            forms_seen = forms_seen or found_form
            source = "footer_html"
        else:
            targets = list(_plain_targets(text))
            source = "footer_plain"

        for uri, context in targets:
            item = _candidate(uri, context, source)
            if item is None:
                rejected += 1
                continue
            fingerprint = candidate_fingerprint(item.uri)
            if fingerprint in seen:
                continue
            if len(candidates) >= active_limits.max_candidates:
                truncated = True
                break
            seen.add(fingerprint)
            candidates.append(item)
        if len(candidates) >= active_limits.max_candidates:
            # The exact cap is safe; report truncation only if later content is skipped.
            continue

    return FooterExtraction(
        candidates=tuple(candidates),
        parts_examined=parts_examined,
        bytes_examined=bytes_examined,
        rejected_targets=rejected,
        forms_seen=forms_seen,
        truncated=truncated,
    )


def candidate_fingerprint(uri: str) -> str:
    """Return a stable identifier so raw tokens need not be stored."""
    return hashlib.sha256(uri.encode("utf-8", errors="surrogatepass")).hexdigest()


def redact_footer_uri(uri: str) -> str:
    """Remove opaque query/fragment/user information for logs and exports."""
    try:
        parsed = urllib.parse.urlsplit(uri)
    except ValueError:
        return "<invalid-footer-target>"
    if parsed.scheme.casefold() == "mailto":
        recipient = urllib.parse.unquote(parsed.path)
        domain = recipient.rsplit("@", 1)[-1] if "@" in recipient else "invalid"
        return f"mailto:<redacted>@{domain.casefold()}"
    if parsed.scheme.casefold() == "https" and parsed.hostname:
        host = parsed.hostname.casefold()
        try:
            port = parsed.port
        except ValueError:
            return "<invalid-footer-target>"
        if port and port != 443:
            host = f"{host}:{port}"
        segments = []
        for segment in (parsed.path or "/").split("/"):
            unquoted = urllib.parse.unquote(segment)
            looks_opaque = len(unquoted) > 32 or bool(
                re.search(r"(?i)(?:[a-f0-9]{24,}|[a-z0-9_-]{32,})", unquoted)
            )
            segments.append("[redacted]" if looks_opaque else segment)
        return urllib.parse.urlunsplit(("https", host, "/".join(segments), "", ""))
    return "<invalid-footer-target>"
