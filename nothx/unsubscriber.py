"""Unsubscribe execution for nothx."""

import smtplib
import urllib.parse
import urllib.request
from email.mime.text import MIMEText

from . import db
from .config import AccountConfig, Config
from .models import EmailHeader, SenderStatus, UnsubMethod, UnsubResult

# User agent for HTTP requests - identifies as nothx email automation tool
USER_AGENT = "nothx/0.1.0 (Email Unsubscribe Automation; +https://github.com/nothx/nothx)"

# Timeout for HTTP requests
REQUEST_TIMEOUT = 30


def unsubscribe(
    email_header: EmailHeader, config: Config, account: AccountConfig | None = None
) -> UnsubResult:
    """
    Attempt to unsubscribe from a sender.
    Tries methods in order: one-click POST > GET > mailto.
    """
    # Method 1: RFC 8058 One-Click POST (best method)
    if email_header.list_unsubscribe_post and email_header.list_unsubscribe_url:
        result = _execute_one_click(email_header.list_unsubscribe_url)
        if result.success:
            _log_result(email_header.domain, result)
            return result

    # Method 2: HTTPS GET request
    if email_header.list_unsubscribe_url:
        result = _execute_get(email_header.list_unsubscribe_url)
        if result.success:
            _log_result(email_header.domain, result)
            return result

    # Method 3: Mailto (requires SMTP)
    if email_header.list_unsubscribe_mailto and account:
        result = _execute_mailto(email_header.list_unsubscribe_mailto, account, config)
        _log_result(email_header.domain, result)
        return result

    # No method available
    result = UnsubResult(success=False, method=None, error="No unsubscribe method available")
    _log_result(email_header.domain, result)
    return result


def _execute_one_click(url: str) -> UnsubResult:
    """Execute RFC 8058 one-click unsubscribe (POST request)."""
    try:
        data = urllib.parse.urlencode({"List-Unsubscribe": "One-Click"}).encode()
        request = urllib.request.Request(
            url,
            data=data,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            status = response.getcode()
            body = response.read(1000).decode("utf-8", errors="replace")

            # Check for success indicators
            success = status in (200, 201, 202, 204) or _check_success_indicators(body)

            return UnsubResult(
                success=success,
                method=UnsubMethod.ONE_CLICK,
                http_status=status,
                response_snippet=body[:200] if body else None,
            )

    except urllib.error.HTTPError as e:
        return UnsubResult(
            success=False,
            method=UnsubMethod.ONE_CLICK,
            http_status=e.code,
            error=str(e),
        )
    except Exception as e:
        return UnsubResult(
            success=False,
            method=UnsubMethod.ONE_CLICK,
            error=str(e),
        )


def _execute_get(url: str) -> UnsubResult:
    """Execute GET request to unsubscribe URL."""
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")

        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            status = response.getcode()
            body = response.read(1000).decode("utf-8", errors="replace")

            # Check for success indicators
            success = status in (200, 201, 202, 204) or _check_success_indicators(body)

            return UnsubResult(
                success=success,
                method=UnsubMethod.GET,
                http_status=status,
                response_snippet=body[:200] if body else None,
            )

    except urllib.error.HTTPError as e:
        return UnsubResult(
            success=False,
            method=UnsubMethod.GET,
            http_status=e.code,
            error=str(e),
        )
    except Exception as e:
        return UnsubResult(
            success=False,
            method=UnsubMethod.GET,
            error=str(e),
        )


def _execute_mailto(mailto: str, account: AccountConfig, config: Config) -> UnsubResult:
    """Execute mailto unsubscribe by sending an email."""
    try:
        # Parse mailto URL
        mailto = mailto.replace("mailto:", "")
        parts = mailto.split("?")
        to_address = parts[0]

        subject = "unsubscribe"
        body = "Please unsubscribe me from this mailing list."

        # Parse query parameters
        if len(parts) > 1:
            params = urllib.parse.parse_qs(parts[1])
            subject = params.get("subject", [subject])[0]
            body = params.get("body", [body])[0]

        # Create email
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = account.email
        msg["To"] = to_address

        # Send via SMTP
        server, port, use_starttls = _get_smtp_config(account.provider)
        smtp_class = smtplib.SMTP if use_starttls else smtplib.SMTP_SSL
        with smtp_class(server, port) as smtp:
            if use_starttls:
                smtp.starttls()
                smtp.ehlo()  # Required after STARTTLS
            smtp.login(account.email, account.password)
            smtp.send_message(msg)

        return UnsubResult(
            success=True,
            method=UnsubMethod.MAILTO,
            response_snippet=f"Sent unsubscribe email to {to_address}",
        )

    except Exception as e:
        return UnsubResult(
            success=False,
            method=UnsubMethod.MAILTO,
            error=str(e),
        )


def _get_smtp_config(provider: str) -> tuple[str, int, bool]:
    """Get SMTP config for email provider. Returns (server, port, use_starttls)."""
    configs = {
        "gmail": ("smtp.gmail.com", 465, False),
        "outlook": ("smtp-mail.outlook.com", 465, False),
        "yahoo": ("smtp.mail.yahoo.com", 465, False),
        "icloud": ("smtp.mail.me.com", 587, True),  # STARTTLS
    }
    return configs.get(provider, (provider, 465, False))


def _check_success_indicators(body: str) -> bool:
    """Check if response body indicates successful unsubscribe."""
    body_lower = body.lower()
    success_phrases = [
        "successfully unsubscribed",
        "you have been unsubscribed",
        "unsubscribe successful",
        "removed from",
        "no longer receive",
        "subscription cancelled",
        "subscription canceled",
        "thank you for unsubscribing",
    ]
    return any(phrase in body_lower for phrase in success_phrases)


def _log_result(domain: str, result: UnsubResult) -> None:
    """Log unsubscribe result to database."""
    db.log_unsub_attempt(
        domain=domain,
        success=result.success,
        method=result.method,
        http_status=result.http_status,
        error=result.error,
        response_snippet=result.response_snippet,
    )

    # Update sender status
    if result.success:
        db.update_sender_status(domain, SenderStatus.UNSUBSCRIBED)
    elif result.error:
        db.update_sender_status(domain, SenderStatus.FAILED)
