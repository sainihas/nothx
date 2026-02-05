"""IMAP connection and email fetching for nothx."""

import email
import email.utils
import imaplib
import logging
import socket
from collections.abc import Iterator
from datetime import datetime, timedelta
from email.header import decode_header
from email.message import Message

from .config import AccountConfig
from .errors import (
    ErrorCode,
    IMAPError,
    RetryConfig,
    retry_with_backoff,
)
from .models import EmailHeader

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


class IMAPConnection:
    """Manages IMAP connection to email provider."""

    def __init__(self, account: AccountConfig):
        self.account = account
        self.server = IMAP_SERVERS.get(account.provider, account.provider)
        self.conn: imaplib.IMAP4_SSL | None = None

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
            self.conn.login(self.account.email, self.account.password)

        try:
            _connect()
            logger.debug(
                "Connected to IMAP server %s",
                self.server,
                extra={"server": self.server, "email": self.account.email},
            )
            return True
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

    def fetch_marketing_emails(
        self, days: int = 30, folder: str = "INBOX"
    ) -> Iterator[EmailHeader]:
        """
        Fetch emails with List-Unsubscribe header from the last N days.
        Only fetches headers, never email bodies.
        """
        if not self.conn:
            raise RuntimeError("Not connected")

        try:
            self.conn.select(folder, readonly=True)
        except imaplib.IMAP4.error as e:
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

        # Search for emails from the last N days with List-Unsubscribe header
        since_date = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")

        # First, get all emails from the date range
        try:
            status, data = self.conn.search(None, f'(SINCE "{since_date}")')
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

        if status != "OK":
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

        message_ids = data[0].split()
        logger.debug(
            "Found %d messages since %s",
            len(message_ids),
            since_date,
            extra={"message_count": len(message_ids), "since_date": since_date},
        )

        fetch_errors = 0
        parse_errors = 0
        yielded_count = 0

        for msg_id in message_ids:
            try:
                # Fetch only headers
                status, msg_data = self.conn.fetch(
                    msg_id,
                    "(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST X-MAILER)])",
                )
                if status != "OK":
                    fetch_errors += 1
                    continue

                # Parse the response
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        flags_part = (
                            response_part[0].decode()
                            if isinstance(response_part[0], bytes)
                            else response_part[0]
                        )
                        is_seen = "\\Seen" in flags_part

                        msg = email.message_from_bytes(response_part[1])

                        # Only yield emails with List-Unsubscribe header
                        list_unsub = msg.get("List-Unsubscribe")
                        if not list_unsub:
                            continue

                        header = self._parse_header(msg, is_seen)
                        if header:
                            yielded_count += 1
                            yield header

            except imaplib.IMAP4.error as e:
                fetch_errors += 1
                logger.debug(
                    "IMAP fetch error for message %s: %s",
                    msg_id,
                    e,
                    extra={"msg_id": msg_id, "error_type": "imap_error"},
                )
            except email.errors.MessageError as e:
                parse_errors += 1
                logger.debug(
                    "Email parse error for message %s: %s",
                    msg_id,
                    e,
                    extra={"msg_id": msg_id, "error_type": "parse_error"},
                )
            except (UnicodeDecodeError, ValueError) as e:
                parse_errors += 1
                logger.debug(
                    "Encoding error for message %s: %s",
                    msg_id,
                    e,
                    extra={"msg_id": msg_id, "error_type": type(e).__name__},
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

    def _parse_header(self, msg: Message, is_seen: bool) -> EmailHeader | None:
        """Parse an email message into an EmailHeader."""
        try:
            # Decode sender
            sender_raw = msg.get("From", "")
            sender = self._decode_header_value(sender_raw)

            # Decode subject
            subject_raw = msg.get("Subject", "")
            subject = self._decode_header_value(subject_raw)

            # Parse date with fallback
            date_str = msg.get("Date", "")
            try:
                date = email.utils.parsedate_to_datetime(date_str)
            except (TypeError, ValueError) as e:
                logger.debug(
                    "Failed to parse date '%s': %s, using current time",
                    date_str[:50],
                    e,
                )
                date = datetime.now()

            return EmailHeader(
                sender=sender,
                subject=subject,
                date=date,
                message_id=msg.get("Message-ID", ""),
                list_unsubscribe=msg.get("List-Unsubscribe"),
                list_unsubscribe_post=msg.get("List-Unsubscribe-Post"),
                x_mailer=msg.get("X-Mailer"),
                is_seen=is_seen,
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
