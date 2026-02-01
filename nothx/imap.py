"""IMAP connection and email fetching for nothx."""

import email
import email.utils
import imaplib
from collections.abc import Iterator
from datetime import datetime, timedelta
from email.header import decode_header
from email.message import Message

from .config import AccountConfig
from .models import EmailHeader

# IMAP server settings
IMAP_SERVERS = {
    "gmail": "imap.gmail.com",
    "outlook": "imap-mail.outlook.com",
}


class IMAPConnection:
    """Manages IMAP connection to email provider."""

    def __init__(self, account: AccountConfig):
        self.account = account
        self.server = IMAP_SERVERS.get(account.provider, account.provider)
        self.conn: imaplib.IMAP4_SSL | None = None

    def connect(self) -> bool:
        """Connect to the IMAP server."""
        try:
            self.conn = imaplib.IMAP4_SSL(self.server)
            self.conn.login(self.account.email, self.account.password)
            return True
        except imaplib.IMAP4.error as e:
            raise ConnectionError(f"Failed to connect: {e}") from e

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
        except Exception:
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

        self.conn.select(folder, readonly=True)

        # Search for emails from the last N days with List-Unsubscribe header
        since_date = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")

        # First, get all emails from the date range
        status, data = self.conn.search(None, f'(SINCE "{since_date}")')
        if status != "OK":
            return

        message_ids = data[0].split()

        for msg_id in message_ids:
            try:
                # Fetch only headers
                status, msg_data = self.conn.fetch(
                    msg_id,
                    "(FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID LIST-UNSUBSCRIBE LIST-UNSUBSCRIBE-POST X-MAILER)])",
                )
                if status != "OK":
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
                            yield header

            except Exception:
                # Skip problematic emails
                continue

    def _parse_header(self, msg: Message, is_seen: bool) -> EmailHeader | None:
        """Parse an email message into an EmailHeader."""
        try:
            # Decode sender
            sender_raw = msg.get("From", "")
            sender = self._decode_header_value(sender_raw)

            # Decode subject
            subject_raw = msg.get("Subject", "")
            subject = self._decode_header_value(subject_raw)

            # Parse date
            date_str = msg.get("Date", "")
            try:
                date = email.utils.parsedate_to_datetime(date_str)
            except Exception:
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
        except Exception:
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
    except ConnectionError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Error: {e}"
