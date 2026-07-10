"""IMAP connection and email fetching for nothx."""

import email
import email.utils
import imaplib
import logging
import re
import shlex
import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from email.header import decode_header
from email.message import Message
from typing import Any, cast

from . import msauth
from .authres import dkim_covers_unsubscribe, parse_authentication_results
from .config import AccountConfig
from .errors import (
    ErrorCode,
    IMAPError,
    OAuthError,
    RetryConfig,
    retry_with_backoff,
)
from .footer import (
    MAX_BODYSTRUCTURE_BYTES,
    InlineTextPart,
    extract_footer_candidates,
    select_footer_parts,
)
from .mailbox import (
    MailboxActionResult,
    MailboxDiscovery,
    move_uid_to_junk,
)
from .mailbox import (
    discover_mailboxes as discover_imap_mailboxes,
)
from .models import (
    EmailHeader,
    FooterUnsubscribeCandidate,
    MailboxActionOutcome,
    MailboxInfo,
    MessageRef,
)
from .provider_signals import parse_provider_signals

# Exact ESP fingerprint headers -> ESP name. IMAP HEADER.FIELDS takes exact
# names only (no wildcards), so each vendor header is enumerated.
ESP_HEADER_MAP = {
    "X-SG-EID": "sendgrid",
    "X-Mailgun-Sid": "mailgun",
    "X-SES-Outgoing": "amazon-ses",
    "X-MC-User": "mandrill",
    "X-PM-Message-Id": "postmark",
    "X-Campaign": "campaign",
    "X-HS-Cid": "hubspot",
}

# Header fields fetched from each message (headers only — never bodies).
_FETCH_HEADER_FIELDS = [
    "FROM",
    "SUBJECT",
    "DATE",
    "MESSAGE-ID",
    "LIST-UNSUBSCRIBE",
    "LIST-UNSUBSCRIBE-POST",
    "X-MAILER",
    "LIST-ID",
    "PRECEDENCE",
    "AUTO-SUBMITTED",
    "FEEDBACK-ID",
    "AUTHENTICATION-RESULTS",
    "DKIM-SIGNATURE",
    "RETURN-PATH",
    "X-FOREFRONT-ANTISPAM-REPORT",
    "X-MICROSOFT-ANTISPAM",
    "X-MS-EXCHANGE-ORGANIZATION-SCL",
    *ESP_HEADER_MAP.keys(),
]

# IMAP date-searches require English month abbreviations (RFC 3501);
# strftime("%b") is locale-dependent and breaks on non-English locales.
_IMAP_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_UID_RE = re.compile(r"\bUID\s+(\d+)\b", re.IGNORECASE)
_INTERNALDATE_RE = re.compile(rb'\bINTERNALDATE\s+"([^"\r\n]{1,64})"', re.IGNORECASE)
_LABELS_RE = re.compile(r"\bX-GM-LABELS\s+\((.*?)\)", re.IGNORECASE | re.DOTALL)
_FETCH_BATCH_SIZE = 100
_BODYSTRUCTURE_TOKEN = re.compile(rb"\bBODYSTRUCTURE\s+", re.IGNORECASE)


def _imap_date(dt: datetime) -> str:
    """Format a datetime as an IMAP search date (DD-Mon-YYYY), locale-independent."""
    return f"{dt.day:02d}-{_IMAP_MONTHS[dt.month - 1]}-{dt.year}"


def _imap_mailbox_arg(name: str) -> str:
    """Quote a configured/discovered mailbox for an IMAP command."""
    if not name or any(character in name for character in ("\r", "\n", "\0")):
        raise ValueError("invalid mailbox name")
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


logger = logging.getLogger("nothx.imap")

# Retry configuration for IMAP operations
IMAP_RETRY_CONFIG = RetryConfig(
    max_attempts=3,
    base_delay=2.0,
    max_delay=30.0,
    exponential_base=2.0,
    retryable_exceptions=(
        socket.timeout,
        socket.error,
        ConnectionError,
        TimeoutError,
        OSError,
        imaplib.IMAP4.abort,
    ),
)

# IMAP server settings
IMAP_SERVERS = {
    "gmail": "imap.gmail.com",
    "outlook": "imap-mail.outlook.com",
    "yahoo": "imap.mail.yahoo.com",
    "icloud": "imap.mail.me.com",
}
OUTLOOK_OAUTH_IMAP_SERVER = "outlook.office365.com"


class IMAPConnection:
    """Manages IMAP connection to email provider."""

    def __init__(self, account: AccountConfig):
        self.account = account
        self.server = (
            OUTLOOK_OAUTH_IMAP_SERVER
            if account.provider == "outlook" and account.uses_oauth
            else IMAP_SERVERS.get(account.provider, account.provider)
        )
        self.conn: imaplib.IMAP4_SSL | None = None
        # Metadata for the most recently exhausted header iterator.  The
        # scanner uses it to advance durable cursors only after every FETCH
        # batch completed.  It is deliberately reset at the start of a fetch.
        self.last_fetch_uidvalidity: int | None = None
        self.last_fetch_highest_uid = 0
        self.last_fetch_complete = False

    def connect(self) -> bool:
        """Connect to the IMAP server with retry logic."""

        @retry_with_backoff(
            config=IMAP_RETRY_CONFIG,
            on_retry=lambda e, attempt, delay: logger.warning(
                "IMAP connection attempt %d failed, retrying in %.1fs: %s",
                attempt,
                delay,
                e,
            ),
        )
        def _connect():
            self.conn = imaplib.IMAP4_SSL(self.server)
            if self.account.uses_oauth:
                if self.account.provider != "outlook" or not self.account.client_id:
                    raise OAuthError(
                        code=ErrorCode.OAUTH_TOKEN_MISSING,
                        message="OAuth account is missing a Microsoft client ID",
                    )
                token = msauth.get_access_token(self.account.email, self.account.client_id)
                try:
                    self.conn.authenticate(
                        "XOAUTH2",
                        lambda _challenge: msauth.build_xoauth2_bytes(self.account.email, token),
                    )
                except imaplib.IMAP4.error:
                    # A stale/revoked access token gets one forced refresh on a
                    # new TLS connection. Never reuse the failed socket.
                    try:
                        self.conn.logout()
                    except Exception:
                        pass
                    token = msauth.get_access_token(
                        self.account.email, self.account.client_id, force_refresh=True
                    )
                    self.conn = imaplib.IMAP4_SSL(self.server)
                    self.conn.authenticate(
                        "XOAUTH2",
                        lambda _challenge: msauth.build_xoauth2_bytes(self.account.email, token),
                    )
            else:
                self.conn.login(self.account.email, self.account.password)

        try:
            _connect()
            logger.debug(
                "Connected to IMAP server %s",
                self.server,
                extra={"server": self.server, "email": self.account.email},
            )
            return True
        except OAuthError as e:
            raise IMAPError(
                code=ErrorCode.IMAP_AUTH_FAILED,
                message=f"OAuth authentication failed for {self.account.email}: {e.message}",
                details={"server": self.server, "email": self.account.email},
                cause=e,
            ) from e
        except imaplib.IMAP4.error as e:
            error_str = str(e).lower()
            if "authentication" in error_str or "login" in error_str:
                raise IMAPError(
                    code=ErrorCode.IMAP_AUTH_FAILED,
                    message=f"Authentication failed for {self.account.email}",
                    details={"server": self.server, "email": self.account.email},
                    cause=e,
                ) from e
            raise IMAPError(
                code=ErrorCode.IMAP_CONNECTION_FAILED,
                message=f"Failed to connect to {self.server}",
                details={"server": self.server},
                cause=e,
            ) from e
        except TimeoutError as e:
            raise IMAPError(
                code=ErrorCode.IMAP_TIMEOUT,
                message=f"Connection timed out to {self.server}",
                details={"server": self.server},
                cause=e,
            ) from e
        except OSError as e:
            raise IMAPError(
                code=ErrorCode.IMAP_CONNECTION_FAILED,
                message=f"Network error connecting to {self.server}: {e}",
                details={"server": self.server, "error_type": type(e).__name__},
                cause=e,
            ) from e

    def disconnect(self) -> None:
        """Disconnect from the IMAP server."""
        if self.conn:
            try:
                self.conn.logout()
            except Exception:
                pass
            self.conn = None

    def __enter__(self) -> "IMAPConnection":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()

    def test_connection(self) -> bool:
        """Test if the connection works."""
        try:
            self.connect()
            if self.conn is None:
                return False
            self.conn.select("INBOX", readonly=True)
            self.disconnect()
            return True
        except IMAPError:
            raise
        except (imaplib.IMAP4.error, OSError) as e:
            logger.info(
                "Connection test failed with error: %s",
                e,
                extra={"server": self.server, "error_type": type(e).__name__},
            )
            return False

    def discover_mailboxes(self, *, junk_override: str | None = None) -> MailboxDiscovery:
        """Return SPECIAL-USE mailbox discovery without guessing folder names."""
        if not self.conn:
            raise RuntimeError("Not connected")
        try:
            return discover_imap_mailboxes(cast(Any, self.conn), junk_override=junk_override)
        except imaplib.IMAP4.error as error:
            raise IMAPError(
                code=ErrorCode.IMAP_FETCH_ERROR,
                message="IMAP mailbox discovery failed",
                details={"account": self.account.email},
                cause=error,
            ) from error

    def move_message_to_junk(
        self,
        locator: MessageRef,
        junk: MailboxInfo | str,
    ) -> MailboxActionResult:
        """Safely move one UID-stable message locator to a discovered Junk mailbox."""
        if not self.conn:
            raise RuntimeError("Not connected")
        try:
            return move_uid_to_junk(cast(Any, self.conn), locator, junk)
        except (imaplib.IMAP4.error, OSError) as error:
            destination = junk.wire_name if isinstance(junk, MailboxInfo) else junk
            return MailboxActionResult(
                MailboxActionOutcome.FAILED,
                locator,
                destination,
                error=f"IMAP mailbox action failed ({type(error).__name__})",
            )

    def fetch_marketing_emails(
        self,
        days: int = 30,
        folder: str = "INBOX",
        include_bulk: bool = False,
        *,
        mailbox_role: str = "inbox",
        since_uid: int | None = None,
        expected_uidvalidity: int | None = None,
        full_history: bool = False,
    ) -> Iterator[EmailHeader]:
        """
        Fetch every message header needed by local spam/subscription policy.

        ``include_bulk`` is retained for API compatibility but no longer gates
        admission: filtering before rules/authentication was the main source of
        false negatives. Bodies are never fetched here.
        """
        del include_bulk
        if not self.conn:
            raise RuntimeError("Not connected")

        self.last_fetch_uidvalidity = None
        self.last_fetch_highest_uid = 0
        self.last_fetch_complete = False

        try:
            select_status, _ = self.conn.select(_imap_mailbox_arg(folder), readonly=True)
            if select_status not in ("OK", b"OK"):
                raise imaplib.IMAP4.error(f"SELECT returned {select_status!r}")
        except (imaplib.IMAP4.error, ValueError) as e:
            logger.error(
                "Failed to select folder %s: %s",
                folder,
                e,
                extra={"folder": folder, "error": str(e)},
            )
            raise IMAPError(
                code=ErrorCode.IMAP_FETCH_ERROR,
                message=f"Failed to select folder {folder}",
                details={"folder": folder},
                cause=e,
            ) from e

        uidvalidity = self._selected_uidvalidity(folder)
        if uidvalidity is None:
            raise IMAPError(
                code=ErrorCode.IMAP_FETCH_ERROR,
                message=f"Mailbox {folder} did not provide UIDVALIDITY",
                details={"folder": folder},
            )
        self.last_fetch_uidvalidity = uidvalidity
        selected_high_water = self._selected_uidnext(folder)
        if selected_high_water is not None:
            selected_high_water = max(0, selected_high_water - 1)

        # A changed UIDVALIDITY starts a new UID namespace.  Continuing from
        # the old cursor could skip new low-numbered UIDs, so safely fall back
        # to the configured initial lookback (or ALL for an explicit history
        # scan).
        if expected_uidvalidity is not None and expected_uidvalidity != uidvalidity:
            logger.info(
                "UIDVALIDITY changed for %s; resetting incremental cursor",
                folder,
                extra={
                    "folder": folder,
                    "expected_uidvalidity": expected_uidvalidity,
                    "uidvalidity": uidvalidity,
                },
            )
            since_uid = None

        since_date = _imap_date(datetime.now() - timedelta(days=days))
        uid_command = cast(Any, self.conn).uid
        try:
            if since_uid is not None:
                # IMAP sequence-set ranges can be interpreted in reverse when
                # their first endpoint exceeds '*'.  Filter the server result
                # below as well, making this cursor strictly exclusive.
                status, data = uid_command("SEARCH", None, "UID", f"{since_uid + 1}:*")
            elif full_history:
                status, data = uid_command("SEARCH", None, "ALL")
            else:
                status, data = uid_command("SEARCH", None, "SINCE", since_date)
        except imaplib.IMAP4.error as e:
            logger.error(
                "IMAP search failed: %s",
                e,
                extra={"since_date": since_date, "error": str(e)},
            )
            raise IMAPError(
                code=ErrorCode.IMAP_FETCH_ERROR,
                message=f"IMAP search failed: {e}",
                details={"since_date": since_date},
                cause=e,
            ) from e

        if status not in ("OK", b"OK"):
            logger.warning(
                "IMAP search returned non-OK status: %s",
                status,
                extra={"status": status},
            )
            raise IMAPError(
                code=ErrorCode.IMAP_FETCH_ERROR,
                message=f"IMAP search returned non-OK status: {status}",
                details={"status": status},
            )

        message_ids = data[0].split() if data and data[0] else []
        if any(not value.isdigit() for value in message_ids):
            raise IMAPError(
                code=ErrorCode.IMAP_FETCH_ERROR,
                message=f"IMAP search returned malformed UIDs for {folder}",
                details={"folder": folder},
            )
        if since_uid is not None:
            message_ids = [value for value in message_ids if int(value) > since_uid]
        searched_high_water = max((int(value) for value in message_ids), default=0)
        self.last_fetch_highest_uid = max(selected_high_water or 0, searched_high_water)
        logger.debug(
            "Found %d messages since %s",
            len(message_ids),
            since_date,
            extra={"message_count": len(message_ids), "since_date": since_date},
        )

        fetch_errors = 0
        parse_errors = 0
        yielded_count = 0
        all_requested_uids_parsed = True

        gmail_ext = self._has_capability("X-GM-EXT-1")
        fetch_items = [
            "UID",
            "INTERNALDATE",
            "FLAGS",
            f"BODY.PEEK[HEADER.FIELDS ({' '.join(_FETCH_HEADER_FIELDS)})]",
        ]
        if gmail_ext:
            fetch_items.insert(2, "X-GM-LABELS")

        for offset in range(0, len(message_ids), _FETCH_BATCH_SIZE):
            batch = message_ids[offset : offset + _FETCH_BATCH_SIZE]
            uid_set = b",".join(batch).decode("ascii")
            try:
                status, msg_data = self.conn.uid("FETCH", uid_set, f"({' '.join(fetch_items)})")
                if status not in ("OK", b"OK"):
                    fetch_errors += len(batch)
                    all_requested_uids_parsed = False
                    continue
                if not isinstance(msg_data, (list, tuple)):
                    fetch_errors += len(batch)
                    all_requested_uids_parsed = False
                    continue

                returned_uids: set[int] = set()
                parsed_uids: set[int] = set()
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        if (
                            len(response_part) < 2
                            or not isinstance(response_part[0], (bytes, str))
                            or not isinstance(response_part[1], bytes)
                        ):
                            parse_errors += 1
                            continue
                        metadata_raw = response_part[0]
                        metadata_bytes = (
                            metadata_raw.encode("utf-8", errors="replace")
                            if isinstance(metadata_raw, str)
                            else metadata_raw
                        )
                        metadata = metadata_bytes.decode("utf-8", errors="replace")
                        uid_match = _UID_RE.search(metadata)
                        if not uid_match:
                            parse_errors += 1
                            continue
                        uid = int(uid_match.group(1))
                        returned_uids.add(uid)
                        received_at = self._parse_internaldate(metadata_bytes)
                        if received_at is None:
                            parse_errors += 1
                            continue

                        decoded_flags = tuple(
                            flag.decode("utf-8", errors="replace")
                            for flag in imaplib.ParseFlags(metadata_bytes)
                        )
                        system_flags = tuple(
                            flag for flag in decoded_flags if flag.startswith("\\")
                        )
                        keywords = tuple(
                            flag for flag in decoded_flags if not flag.startswith("\\")
                        )
                        is_seen = any(flag.casefold() == "\\seen" for flag in system_flags)
                        labels = self._parse_gmail_labels(metadata)

                        msg = email.message_from_bytes(response_part[1])

                        header = self._parse_header(msg, is_seen)
                        if not header:
                            continue

                        header.mailbox_name = folder
                        header.mailbox_role = mailbox_role
                        header.uid = uid
                        header.uidvalidity = uidvalidity
                        header.system_flags = system_flags
                        header.keywords = keywords
                        header.gmail_labels = labels
                        header.received_at = received_at

                        parsed_uids.add(uid)
                        yielded_count += 1
                        yield header

                expected_uids = {int(value) for value in batch}
                missing_uids = expected_uids - returned_uids
                if missing_uids:
                    fetch_errors += len(missing_uids)
                    logger.debug(
                        "IMAP FETCH omitted %d requested UIDs from %s",
                        len(missing_uids),
                        uid_set,
                    )
                unparsed_uids = expected_uids - parsed_uids
                if unparsed_uids:
                    all_requested_uids_parsed = False
                    logger.debug(
                        "IMAP FETCH did not yield valid headers for %d requested UIDs from %s",
                        len(unparsed_uids),
                        uid_set,
                    )

            except imaplib.IMAP4.error as e:
                fetch_errors += 1
                all_requested_uids_parsed = False
                logger.debug(
                    "IMAP fetch error for message %s: %s",
                    uid_set,
                    e,
                    extra={"uid_set": uid_set, "error_type": "imap_error"},
                )
            except email.errors.MessageError as e:
                parse_errors += 1
                all_requested_uids_parsed = False
                logger.debug(
                    "Email parse error for message %s: %s",
                    uid_set,
                    e,
                    extra={"uid_set": uid_set, "error_type": "parse_error"},
                )
            except (UnicodeDecodeError, ValueError) as e:
                parse_errors += 1
                all_requested_uids_parsed = False
                logger.debug(
                    "Encoding error for message %s: %s",
                    uid_set,
                    e,
                    extra={"uid_set": uid_set, "error_type": type(e).__name__},
                )

        # Log summary if there were errors
        if fetch_errors or parse_errors:
            logger.info(
                "Email fetch complete: %d yielded, %d fetch errors, %d parse errors",
                yielded_count,
                fetch_errors,
                parse_errors,
                extra={
                    "yielded": yielded_count,
                    "fetch_errors": fetch_errors,
                    "parse_errors": parse_errors,
                    "total_messages": len(message_ids),
                },
            )
        # A checkpoint is safe only when every requested UID produced a valid
        # header. Otherwise advancing past a malformed/omitted response would
        # permanently skip that message.
        self.last_fetch_complete = fetch_errors == 0 and all_requested_uids_parsed

    def _has_capability(self, capability: str) -> bool:
        if not self.conn:
            return False
        values = getattr(self.conn, "capabilities", ()) or ()
        wanted = capability.casefold()
        return any(
            (
                value.decode("ascii", errors="ignore") if isinstance(value, bytes) else str(value)
            ).casefold()
            == wanted
            for value in values
        )

    def _selected_uidvalidity(self, folder: str) -> int | None:
        """Read UIDVALIDITY for the currently selected mailbox."""
        assert self.conn is not None
        try:
            _status, values = self.conn.response("UIDVALIDITY")
        except (imaplib.IMAP4.error, AttributeError):
            values = None
        if values:
            raw = values[-1]
            if isinstance(raw, bytes):
                raw = raw.decode("ascii", errors="ignore")
            match = re.search(r"\d+", str(raw))
            if match:
                return int(match.group(0))
        logger.warning("UIDVALIDITY missing for mailbox %s", folder)
        return None

    def _selected_uidnext(self, folder: str) -> int | None:
        """Read the selection-time UIDNEXT high-water marker, when supplied."""
        assert self.conn is not None
        try:
            _status, values = self.conn.response("UIDNEXT")
        except (imaplib.IMAP4.error, AttributeError):
            values = None
        if values:
            raw = values[-1]
            if isinstance(raw, bytes):
                raw = raw.decode("ascii", errors="ignore")
            match = re.search(r"\d+", str(raw))
            if match:
                return int(match.group(0))
        logger.debug("UIDNEXT missing for mailbox %s", folder)
        return None

    @staticmethod
    def _bodystructure_from_fetch(data: object) -> bytes | None:
        """Extract the balanced BODYSTRUCTURE expression from FETCH metadata."""
        if not isinstance(data, (list, tuple)):
            return None
        for response in data:
            metadata = response[0] if isinstance(response, tuple) and response else response
            if not isinstance(metadata, (bytes, str)):
                continue
            raw = (
                metadata.encode("utf-8", errors="replace")
                if isinstance(metadata, str)
                else metadata
            )
            if len(raw) > MAX_BODYSTRUCTURE_BYTES:
                return None
            match = _BODYSTRUCTURE_TOKEN.search(raw)
            if not match:
                continue
            start = raw.find(b"(", match.end())
            if start < 0:
                continue
            depth = 0
            quoted = False
            escaped = False
            for index in range(start, len(raw)):
                value = raw[index]
                if quoted:
                    if escaped:
                        escaped = False
                    elif value == ord("\\"):
                        escaped = True
                    elif value == ord('"'):
                        quoted = False
                    continue
                if value == ord('"'):
                    quoted = True
                elif value == ord("("):
                    depth += 1
                elif value == ord(")"):
                    depth -= 1
                    if depth == 0:
                        return raw[start : index + 1]
        return None

    def fetch_footer_candidates(
        self, header: EmailHeader
    ) -> tuple[FooterUnsubscribeCandidate, ...]:
        """Return bounded footer candidates, isolating per-message IMAP errors."""
        try:
            return self._fetch_footer_candidates(header)
        except (imaplib.IMAP4.error, OSError, ValueError) as error:
            logger.info(
                "Footer fetch failed for %s/%s (%s)",
                header.mailbox_name,
                header.uid,
                type(error).__name__,
            )
            return ()

    def _fetch_footer_candidates(
        self, header: EmailHeader
    ) -> tuple[FooterUnsubscribeCandidate, ...]:
        """Locally inspect bounded inline footer tails for one stable message.

        This method is intentionally separate from header scanning so the
        default path performs zero body fetches.  It revalidates the mailbox's
        UIDVALIDITY and exact UID before requesting BODYSTRUCTURE or partial
        inline text leaves.
        """
        if not self.conn:
            raise RuntimeError("Not connected")
        locator = header.message_ref
        if locator is None:
            return ()
        status, _ = self.conn.select(_imap_mailbox_arg(locator.mailbox), readonly=True)
        if status != "OK" and status != b"OK":
            return ()
        if self._selected_uidvalidity(locator.mailbox) != locator.uidvalidity:
            return ()

        uid_command = cast(Any, self.conn).uid
        status, found = uid_command("SEARCH", None, "UID", str(locator.uid))
        if status not in ("OK", b"OK"):
            return ()
        found_values = found if isinstance(found, (list, tuple)) else (found,)
        found_uids = {
            int(value)
            for group in found_values
            if isinstance(group, (bytes, str))
            for value in (group.split() if isinstance(group, bytes) else group.encode().split())
            if value.isdigit()
        }
        if locator.uid not in found_uids:
            return ()

        status, structure_data = uid_command("FETCH", str(locator.uid), "(UID BODYSTRUCTURE)")
        if status not in ("OK", b"OK"):
            return ()
        structure = self._bodystructure_from_fetch(structure_data)
        if structure is None:
            return ()
        selection = select_footer_parts(structure)
        if selection.parse_error or not selection.parts:
            return ()

        parts: list[InlineTextPart] = []
        for spec in selection.parts:
            status, part_data = uid_command("FETCH", str(locator.uid), f"(UID {spec.imap_partial})")
            if status not in ("OK", b"OK") or not isinstance(part_data, (list, tuple)):
                continue
            content: bytes | None = None
            for response in part_data:
                if (
                    isinstance(response, tuple)
                    and len(response) > 1
                    and isinstance(response[1], bytes)
                ):
                    content = response[1]
                    break
            if content is None or len(content) > spec.fetch_count:
                # Fail closed if a server ignores the requested partial range.
                continue
            parts.append(
                InlineTextPart(
                    section=spec.section,
                    content_type=spec.content_type,
                    content=content,
                    charset=spec.charset,
                    transfer_encoding=spec.transfer_encoding,
                    partial=True,
                )
            )
        if not parts:
            return ()
        extraction = extract_footer_candidates(parts)
        # Persist only the boolean manual-action signal on the in-memory
        # header. Footer content itself is never retained or written to state.
        header.footer_requires_user = extraction.forms_seen
        return extraction.candidates

    def _parse_gmail_labels(self, metadata: str) -> tuple[str, ...]:
        match = _LABELS_RE.search(metadata)
        if not match:
            return ()
        try:
            return tuple(shlex.split(match.group(1)))
        except ValueError:
            return ()

    @staticmethod
    def _parse_internaldate(metadata: bytes) -> datetime | None:
        """Parse immutable IMAP INTERNALDATE metadata as aware UTC."""
        match = _INTERNALDATE_RE.search(metadata)
        if match is None:
            return None
        try:
            parsed = email.utils.parsedate_to_datetime(match.group(1).decode("ascii"))
        except (UnicodeDecodeError, TypeError, ValueError):
            return None
        if parsed is None or parsed.tzinfo is None:
            return None
        return parsed.astimezone(UTC)

    def _parse_header(self, msg: Message, is_seen: bool) -> EmailHeader | None:
        """Parse an email message into an EmailHeader."""
        try:
            # Decode sender
            sender_raw = msg.get("From", "")
            sender = self._decode_header_value(sender_raw)

            # Decode subject
            subject_raw = msg.get("Subject", "")
            subject = self._decode_header_value(subject_raw)

            # Parse date with fallback. Normalize everything to aware UTC:
            # mixing naive and aware datetimes makes min()/sorted() raise TypeError.
            date_str = msg.get("Date", "")
            try:
                date = email.utils.parsedate_to_datetime(date_str)
            except (TypeError, ValueError) as e:
                logger.debug(
                    "Failed to parse date '%s': %s, using current time",
                    date_str[:50],
                    e,
                )
                date = datetime.now(UTC)
            if date.tzinfo is None:
                date = date.replace(tzinfo=UTC)
            else:
                date = date.astimezone(UTC)

            # Detect ESP by the first fingerprint header present
            esp = next(
                (name for field, name in ESP_HEADER_MAP.items() if msg.get(field)),
                None,
            )

            verdicts = parse_authentication_results(
                msg.get_all("Authentication-Results", []), self.account.provider
            )
            _display_name, from_address = email.utils.parseaddr(sender)
            from_domain = from_address.rsplit("@", 1)[1] if from_address.count("@") == 1 else None
            provider_signals = parse_provider_signals(msg, self.account.provider)
            unsubscribe_values = msg.get_all("List-Unsubscribe", [])
            unsubscribe_post_values = msg.get_all("List-Unsubscribe-Post", [])

            def _lower(name: str) -> str | None:
                value = msg.get(name)
                return value.strip().lower() if value else None

            return EmailHeader(
                sender=sender,
                subject=subject,
                date=date,
                message_id=msg.get("Message-ID", ""),
                list_unsubscribe=unsubscribe_values[0] if unsubscribe_values else None,
                list_unsubscribe_post=(
                    unsubscribe_post_values[0] if unsubscribe_post_values else None
                ),
                x_mailer=msg.get("X-Mailer"),
                is_seen=is_seen,
                list_id=msg.get("List-Id"),
                precedence=_lower("Precedence"),
                auto_submitted=_lower("Auto-Submitted"),
                feedback_id=msg.get("Feedback-ID"),
                return_path=msg.get("Return-Path"),
                esp=esp,
                dkim_pass=verdicts.dkim,
                spf_pass=verdicts.spf,
                dmarc_pass=verdicts.dmarc,
                authentication=verdicts.evidence,
                dkim_covers_unsubscribe=dkim_covers_unsubscribe(
                    msg.get_all("DKIM-Signature", []),
                    verdicts,
                    from_domain=from_domain,
                ),
                list_unsubscribe_count=len(unsubscribe_values),
                list_unsubscribe_post_count=len(unsubscribe_post_values),
                provider_threat=provider_signals.threat,
                provider_bulk=provider_signals.bulk,
            )
        except (TypeError, ValueError, AttributeError) as e:
            logger.debug(
                "Failed to parse email header: %s",
                e,
                extra={"error_type": type(e).__name__},
            )
            return None

    def _decode_header_value(self, value: str) -> str:
        """Decode a potentially encoded header value."""
        if not value:
            return ""
        try:
            decoded_parts = decode_header(value)
            result = []
            for part, charset in decoded_parts:
                if isinstance(part, bytes):
                    result.append(part.decode(charset or "utf-8", errors="replace"))
                else:
                    result.append(part)
            return "".join(result)
        except Exception:
            return value


def test_account(account: AccountConfig) -> tuple[bool, str]:
    """Test an account configuration."""
    try:
        conn = IMAPConnection(account)
        if conn.test_connection():
            return True, "Connection successful"
        return False, "Connection failed"
    except IMAPError as e:
        return False, str(e)
    except imaplib.IMAP4.error as e:
        error_str = str(e).lower()
        if "authentication" in error_str or "login" in error_str:
            return False, f"Authentication failed: {e}"
        return False, f"IMAP error: {e}"
    except TimeoutError:
        return False, "Connection timed out"
    except OSError as e:
        return False, f"Connection error: {e}"
