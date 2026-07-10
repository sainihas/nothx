"""Portable, fail-closed IMAP mailbox discovery and Junk movement.

The scanner owns policy decisions; this module owns the protocol details that
make a mailbox mutation safe.  In particular, a message is always re-located
by ``(mailbox, UIDVALIDITY, UID)`` immediately before a write, and COPY
fallbacks never use the mailbox-wide EXPUNGE command.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .models import MailboxActionOutcome, MailboxInfo, MessageRef

_LITERAL_RE = re.compile(rb"\{(\d+)\+?\}\s*$")
_POSITIVE_INT_RE = re.compile(rb"^[1-9][0-9]*$")


class IMAPMailboxClient(Protocol):
    """The subset of :mod:`imaplib` used by these helpers."""

    capabilities: Sequence[str | bytes]

    def list(self, directory: str = '""', pattern: str = "*") -> tuple[Any, Any]: ...

    def select(self, mailbox: str = "INBOX", readonly: bool = False) -> tuple[Any, Any]: ...

    def response(self, code: str) -> tuple[Any, Any] | None: ...

    def uid(self, command: str, *args: Any) -> tuple[Any, Any]: ...

    def capability(self) -> tuple[Any, Any]: ...


@dataclass(frozen=True)
class ParsedFlags:
    """Case-normalized system flags and keywords from an IMAP response."""

    system: frozenset[str] = frozenset()
    keywords: frozenset[str] = frozenset()

    @property
    def all(self) -> frozenset[str]:
        return self.system | self.keywords

    def has(self, flag: str) -> bool:
        return flag.casefold() in self.all

    @property
    def is_junk(self) -> bool:
        return self.has("$junk") or self.has(r"\junk")

    @property
    def is_not_junk(self) -> bool:
        return self.has("$notjunk")

    @property
    def is_phishing(self) -> bool:
        return self.has("$phishing")

    @property
    def can_unsubscribe(self) -> bool:
        return self.has("$canunsubscribe")


@dataclass(frozen=True)
class MailboxDiscovery:
    """Mailbox inventory plus an unambiguous Junk selection, if available."""

    mailboxes: tuple[MailboxInfo, ...]
    inbox: MailboxInfo | None
    junk: MailboxInfo | None
    junk_candidates: tuple[MailboxInfo, ...]
    override_used: bool = False
    errors: tuple[str, ...] = ()

    @property
    def junk_is_ambiguous(self) -> bool:
        return self.junk is None and len(self.junk_candidates) > 1


@dataclass(frozen=True)
class UIDValidation:
    """Result of reselecting and checking a stable UID locator."""

    valid: bool
    selected_uidvalidity: int | None
    uid_exists: bool
    permanent_flags: ParsedFlags = ParsedFlags()
    error: str | None = None
    exact_search_completed: bool = False


@dataclass(frozen=True)
class MailboxActionResult:
    """Detailed result of moving exactly one UID to Junk."""

    outcome: MailboxActionOutcome
    message_ref: MessageRef
    destination: str
    method: str | None = None
    destination_created: bool = False
    source_marked_deleted: bool = False
    source_removed: bool = False
    junk_keyword_set: bool = False
    not_junk_keyword_removed: bool = False
    error: str | None = None


class MailboxParseError(ValueError):
    """Raised for an invalid or unsupported LIST response."""


def _as_bytes(value: str | bytes) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")


def _decode_wire(value: bytes) -> str:
    """Decode ASCII/UTF-8 mailbox wire text without losing undecodable bytes."""
    return value.decode("utf-8", errors="surrogateescape")


def _read_quoted(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != ord('"'):
        raise MailboxParseError("expected quoted string")
    result = bytearray()
    index = offset + 1
    while index < len(data):
        current = data[index]
        if current == ord('"'):
            return bytes(result), index + 1
        if current == ord("\\"):
            index += 1
            if index >= len(data):
                raise MailboxParseError("unterminated quoted escape")
            current = data[index]
        result.append(current)
        index += 1
    raise MailboxParseError("unterminated quoted string")


def _skip_space(data: bytes, offset: int) -> int:
    while offset < len(data) and data[offset] in b" \t\r\n":
        offset += 1
    return offset


def _read_nstring(data: bytes, offset: int) -> tuple[bytes | None, int]:
    offset = _skip_space(data, offset)
    if data[offset : offset + 3].upper() == b"NIL" and (
        offset + 3 == len(data) or data[offset + 3] in b" \t\r\n"
    ):
        return None, offset + 3
    if offset < len(data) and data[offset] == ord('"'):
        return _read_quoted(data, offset)
    end = offset
    while end < len(data) and data[end] not in b" \t\r\n":
        end += 1
    if end == offset:
        raise MailboxParseError("missing LIST field")
    return data[offset:end], end


def _coalesce_list_response(response: str | bytes | tuple[Any, ...]) -> bytes:
    """Join the prefix and literal returned by imaplib for a literal mailbox."""
    if not isinstance(response, tuple):
        return _as_bytes(response)
    if not response:
        raise MailboxParseError("empty LIST response tuple")
    prefix = _as_bytes(response[0])
    match = _LITERAL_RE.search(prefix)
    if not match or len(response) < 2 or not isinstance(response[1], (str, bytes)):
        raise MailboxParseError("unsupported LIST response tuple")
    literal = _as_bytes(response[1])
    if len(literal) != int(match.group(1)):
        raise MailboxParseError("LIST literal length mismatch")
    return prefix[: match.start()] + literal


def parse_list_response(response: str | bytes | tuple[Any, ...]) -> MailboxInfo:
    """Parse one RFC 3501/9051 LIST response returned by :mod:`imaplib`.

    Attribute spelling is normalized for comparisons.  The unquoted mailbox
    name remains in wire form so callers can safely pass it back to IMAP.
    """
    data = _coalesce_list_response(response).strip()
    if not data.startswith(b"("):
        raise MailboxParseError("LIST response has no attribute list")
    close = data.find(b")")
    if close < 0:
        raise MailboxParseError("unterminated LIST attribute list")

    raw_attributes = data[1:close].split()
    attributes = tuple(_decode_wire(value).casefold() for value in raw_attributes)
    delimiter_raw, offset = _read_nstring(data, close + 1)
    offset = _skip_space(data, offset)
    if offset >= len(data):
        raise MailboxParseError("LIST response has no mailbox name")
    if data[offset] == ord('"'):
        name_raw, offset = _read_quoted(data, offset)
        if data[offset:].strip():
            raise MailboxParseError("unexpected data after mailbox name")
    else:
        name_raw = data[offset:].strip()
    if not name_raw:
        raise MailboxParseError("LIST response has an empty mailbox name")

    wire_name = _decode_wire(name_raw)
    delimiter = _decode_wire(delimiter_raw) if delimiter_raw is not None else None
    return MailboxInfo(
        name=wire_name,
        wire_name=wire_name,
        delimiter=delimiter,
        attributes=attributes,
        selectable=r"\noselect" not in attributes,
    )


def discover_from_list(
    responses: Iterable[str | bytes | tuple[Any, ...] | None],
    *,
    junk_override: str | None = None,
) -> MailboxDiscovery:
    """Discover Inbox and Junk without guessing localized mailbox names."""
    mailboxes: list[MailboxInfo] = []
    errors: list[str] = []
    for index, response in enumerate(responses):
        if response is None:
            continue
        try:
            mailboxes.append(parse_list_response(response))
        except (MailboxParseError, UnicodeError) as exc:
            errors.append(f"LIST item {index}: {exc}")

    inbox = next(
        (item for item in mailboxes if item.selectable and item.name.casefold() == "inbox"),
        None,
    )
    candidates = tuple(item for item in mailboxes if item.selectable and item.is_junk)
    junk: MailboxInfo | None = None
    override_used = False

    if junk_override is not None:
        exact = [item for item in mailboxes if item.selectable and item.name == junk_override]
        if not exact:
            folded = [
                item
                for item in mailboxes
                if item.selectable and item.name.casefold() == junk_override.casefold()
            ]
            exact = folded if len(folded) == 1 else []
        if len(exact) == 1:
            junk = exact[0]
            override_used = True
        else:
            errors.append("configured Junk mailbox was not found unambiguously")
    elif len(candidates) == 1:
        junk = candidates[0]

    return MailboxDiscovery(
        mailboxes=tuple(mailboxes),
        inbox=inbox,
        junk=junk,
        junk_candidates=candidates,
        override_used=override_used,
        errors=tuple(errors),
    )


def discover_mailboxes(
    client: IMAPMailboxClient, *, junk_override: str | None = None
) -> MailboxDiscovery:
    """Issue a portable LIST and return SPECIAL-USE discovery metadata."""
    if "SPECIAL-USE" in _capabilities(client):
        # imaplib's LIST wrapper accepts the constant extended syntax as its
        # pattern argument and emits: LIST "" * RETURN (SPECIAL-USE). RFC 6154
        # permits servers to omit special-use attributes from a basic LIST,
        # so request them explicitly whenever the capability is advertised.
        status, data = client.list('""', "* RETURN (SPECIAL-USE)")
        if (
            _is_ok(status)
            and isinstance(data, (list, tuple))
            and any(item is not None for item in data)
        ):
            extended = discover_from_list(data, junk_override=junk_override)
            if extended.mailboxes:
                return extended

        # A broken/older implementation can advertise SPECIAL-USE but reject
        # the RETURN option. Fall back to basic LIST and remain fail-closed if
        # it does not expose an unambiguous role.
    status, data = client.list('""', "*")
    if not _is_ok(status):
        return MailboxDiscovery((), None, None, (), errors=("IMAP LIST failed",))
    if not isinstance(data, (list, tuple)):
        return MailboxDiscovery((), None, None, (), errors=("IMAP LIST returned invalid data",))
    return discover_from_list(data, junk_override=junk_override)


def parse_flags(value: str | bytes | Iterable[str | bytes] | None) -> ParsedFlags:
    """Parse FLAGS/PERMANENTFLAGS data and split system flags from keywords."""
    if value is None:
        return ParsedFlags()
    if isinstance(value, (str, bytes)):
        chunks = [_as_bytes(value)]
    else:
        chunks = [_as_bytes(item) for item in value]
    data = b" ".join(chunks)
    match = re.search(rb"\b(?:PERMANENTFLAGS|FLAGS)\s*\(([^)]*)\)", data, re.IGNORECASE)
    if not match:
        # ``IMAP4.response('PERMANENTFLAGS')`` returns only the parenthesized
        # value, while FETCH responses include the explicit FLAGS label.
        match = re.fullmatch(rb"\s*\(([^)]*)\)\s*", data)
    if not match:
        return ParsedFlags()
    tokens = {_decode_wire(token).casefold() for token in match.group(1).split() if token}
    return ParsedFlags(
        system=frozenset(token for token in tokens if token.startswith("\\")),
        keywords=frozenset(token for token in tokens if not token.startswith("\\")),
    )


def _response_data(client: IMAPMailboxClient, code: str) -> list[bytes]:
    response = client.response(code)
    if not response or len(response) < 2:
        return []
    data = response[1]
    if isinstance(data, (str, bytes)):
        return [_as_bytes(data)]
    if not isinstance(data, (list, tuple)):
        return []
    return [_as_bytes(item) for item in data if isinstance(item, (str, bytes))]


def _parse_positive_response_number(values: Iterable[bytes]) -> int | None:
    for raw in values:
        value = raw.strip()
        if _POSITIVE_INT_RE.fullmatch(value):
            return int(value)
        match = re.search(rb"\b([1-9][0-9]*)\b", value)
        if match:
            return int(match.group(1))
    return None


def _quote_mailbox(name: str) -> str:
    if not name or any(character in name for character in ("\r", "\n", "\0")):
        raise ValueError("invalid mailbox name")
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _is_ok(status: Any) -> bool:
    if isinstance(status, bytes):
        return status.upper() == b"OK"
    return isinstance(status, str) and status.upper() == "OK"


def _capabilities(client: IMAPMailboxClient) -> frozenset[str]:
    raw = getattr(client, "capabilities", ()) or ()
    chunks: list[bytes] = []
    if isinstance(raw, (str, bytes)):
        chunks.append(_as_bytes(raw))
    else:
        chunks.extend(_as_bytes(item) for item in raw if isinstance(item, (str, bytes)))
    if not chunks:
        status, data = client.capability()
        if _is_ok(status):
            if isinstance(data, (str, bytes)):
                chunks.append(_as_bytes(data))
            elif isinstance(data, (list, tuple)):
                chunks.extend(_as_bytes(item) for item in data if isinstance(item, (str, bytes)))
    return frozenset(
        _decode_wire(token).upper() for chunk in chunks for token in chunk.split() if token
    )


def validate_uid_locator(client: IMAPMailboxClient, locator: MessageRef) -> UIDValidation:
    """Reselect read-write and prove that a UID still belongs to this mailbox."""
    if locator.uid <= 0 or locator.uidvalidity <= 0:
        return UIDValidation(False, None, False, error="UID and UIDVALIDITY must be positive")
    try:
        source = _quote_mailbox(locator.mailbox)
    except ValueError as exc:
        return UIDValidation(False, None, False, error=str(exc))

    status, _ = client.select(source, readonly=False)
    if not _is_ok(status):
        return UIDValidation(False, None, False, error="source mailbox is not writable")

    selected_uidvalidity = _parse_positive_response_number(_response_data(client, "UIDVALIDITY"))
    permanent_flags = parse_flags(_response_data(client, "PERMANENTFLAGS"))
    if selected_uidvalidity is None:
        return UIDValidation(
            False,
            None,
            False,
            permanent_flags,
            "server did not provide UIDVALIDITY",
        )
    if selected_uidvalidity != locator.uidvalidity:
        return UIDValidation(
            False,
            selected_uidvalidity,
            False,
            permanent_flags,
            "UIDVALIDITY changed; refusing stale locator",
        )

    status, data = client.uid("SEARCH", None, "UID", str(locator.uid))
    if not _is_ok(status):
        return UIDValidation(
            False,
            selected_uidvalidity,
            False,
            permanent_flags,
            "UID search failed",
        )
    values: list[bytes] = []
    if isinstance(data, (str, bytes)):
        values.append(_as_bytes(data))
    elif isinstance(data, (list, tuple)):
        if any(not isinstance(item, (str, bytes)) for item in data):
            return UIDValidation(
                False,
                selected_uidvalidity,
                False,
                permanent_flags,
                "UID search returned malformed data",
            )
        values.extend(_as_bytes(item) for item in data)
    else:
        return UIDValidation(
            False,
            selected_uidvalidity,
            False,
            permanent_flags,
            "UID search returned malformed data",
        )
    if not values:
        return UIDValidation(
            False,
            selected_uidvalidity,
            False,
            permanent_flags,
            "UID search returned malformed data",
        )
    tokens = [token for value in values for token in value.split()]
    if any(_POSITIVE_INT_RE.fullmatch(token) is None for token in tokens):
        return UIDValidation(
            False,
            selected_uidvalidity,
            False,
            permanent_flags,
            "UID search returned malformed data",
        )
    found = {int(token) for token in tokens}
    if locator.uid not in found:
        return UIDValidation(
            False,
            selected_uidvalidity,
            False,
            permanent_flags,
            "UID no longer exists in source mailbox",
            exact_search_completed=True,
        )
    return UIDValidation(
        True,
        selected_uidvalidity,
        True,
        permanent_flags,
        exact_search_completed=True,
    )


def _keyword_is_permanent(flags: ParsedFlags, keyword: str) -> bool:
    return flags.has(keyword) or flags.has(r"\*")


def _store_flag(client: IMAPMailboxClient, uid: int, operation: str, flag: str) -> bool:
    status, _ = client.uid("STORE", str(uid), operation, f"({flag})")
    return _is_ok(status)


def move_uid_to_junk(
    client: IMAPMailboxClient,
    locator: MessageRef,
    junk: MailboxInfo | str,
) -> MailboxActionResult:
    """Move one validated UID to Junk without ever issuing broad EXPUNGE.

    MOVE is preferred when advertised.  Otherwise the safe fallback is UID
    COPY, UID STORE ``\\Deleted`` on exactly this UID, and UID EXPUNGE only
    when UIDPLUS is available.  Without UIDPLUS the successful copy is
    reported as partial so callers do not mistake it for source removal.
    """
    destination = junk.wire_name if isinstance(junk, MailboxInfo) else junk
    same_mailbox = locator.mailbox == destination or (
        locator.mailbox.casefold() == "inbox" and destination.casefold() == "inbox"
    )
    if same_mailbox:
        return MailboxActionResult(
            MailboxActionOutcome.ALREADY_JUNK,
            locator,
            destination,
            source_removed=True,
        )
    try:
        quoted_destination = _quote_mailbox(destination)
    except ValueError as exc:
        return MailboxActionResult(
            MailboxActionOutcome.FAILED, locator, destination, error=str(exc)
        )

    validation = validate_uid_locator(client, locator)
    if not validation.valid:
        if (
            validation.exact_search_completed
            and validation.selected_uidvalidity == locator.uidvalidity
            and not validation.uid_exists
        ):
            return MailboxActionResult(
                MailboxActionOutcome.NOT_FOUND,
                locator,
                destination,
                method="uid-search",
                source_removed=True,
            )
        return MailboxActionResult(
            MailboxActionOutcome.FAILED,
            locator,
            destination,
            error=validation.error,
        )

    removed_not_junk = False
    set_junk = False
    if _keyword_is_permanent(validation.permanent_flags, "$NotJunk"):
        removed_not_junk = _store_flag(client, locator.uid, "-FLAGS.SILENT", "$NotJunk")
    if _keyword_is_permanent(validation.permanent_flags, "$Junk"):
        set_junk = _store_flag(client, locator.uid, "+FLAGS.SILENT", "$Junk")

    capabilities = _capabilities(client)
    if "MOVE" in capabilities:
        status, _ = client.uid("MOVE", str(locator.uid), quoted_destination)
        if _is_ok(status):
            return MailboxActionResult(
                MailboxActionOutcome.MOVED,
                locator,
                destination,
                method="uid-move",
                destination_created=True,
                source_removed=True,
                junk_keyword_set=set_junk,
                not_junk_keyword_removed=removed_not_junk,
            )
        # A failed MOVE can be ambiguous after a connection abort.  Do not
        # issue COPY and risk duplicating a message whose MOVE actually ran.
        return MailboxActionResult(
            MailboxActionOutcome.FAILED,
            locator,
            destination,
            method="uid-move",
            junk_keyword_set=set_junk,
            not_junk_keyword_removed=removed_not_junk,
            error="UID MOVE failed; COPY fallback suppressed because completion is ambiguous",
        )

    status, _ = client.uid("COPY", str(locator.uid), quoted_destination)
    if not _is_ok(status):
        return MailboxActionResult(
            MailboxActionOutcome.FAILED,
            locator,
            destination,
            method="uid-copy",
            junk_keyword_set=set_junk,
            not_junk_keyword_removed=removed_not_junk,
            error="UID COPY failed",
        )

    deleted = _store_flag(client, locator.uid, "+FLAGS.SILENT", r"\Deleted")
    if not deleted:
        return MailboxActionResult(
            MailboxActionOutcome.PARTIAL,
            locator,
            destination,
            method="uid-copy",
            destination_created=True,
            junk_keyword_set=set_junk,
            not_junk_keyword_removed=removed_not_junk,
            error="copied to Junk but could not mark the source UID deleted",
        )

    if "UIDPLUS" not in capabilities:
        return MailboxActionResult(
            MailboxActionOutcome.PARTIAL,
            locator,
            destination,
            method="uid-copy-delete",
            destination_created=True,
            source_marked_deleted=True,
            junk_keyword_set=set_junk,
            not_junk_keyword_removed=removed_not_junk,
            error="copied and marked deleted; UIDPLUS unavailable, so source was not expunged",
        )

    status, _ = client.uid("EXPUNGE", str(locator.uid))
    if not _is_ok(status):
        return MailboxActionResult(
            MailboxActionOutcome.PARTIAL,
            locator,
            destination,
            method="uid-copy-delete",
            destination_created=True,
            source_marked_deleted=True,
            junk_keyword_set=set_junk,
            not_junk_keyword_removed=removed_not_junk,
            error="copied and marked deleted, but UID EXPUNGE failed",
        )
    return MailboxActionResult(
        MailboxActionOutcome.MOVED,
        locator,
        destination,
        method="uid-copy-delete-expunge",
        destination_created=True,
        source_marked_deleted=True,
        source_removed=True,
        junk_keyword_set=set_junk,
        not_junk_keyword_removed=removed_not_junk,
    )
