"""Optional isolated browser completion for JavaScript unsubscribe pages."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from importlib import import_module
from typing import Any
from urllib.parse import urljoin, urlsplit

from .safefetch import safe_fetch


@dataclass(frozen=True)
class BrowserOutcome:
    success: bool
    error_code: str | None = None
    ambiguous_send: bool = False


BUTTON_NAME = re.compile(r"^(?:unsubscribe|confirm unsubscribe|yes,? unsubscribe)$", re.I)
CONFIRMED = re.compile(
    r"\b(?:you (?:have been|are now|are) unsubscribed|you['’]ve been unsubscribed"
    r"|you['’]re (?:now )?unsubscribed|successfully unsubscribed|unsubscribe (?:successful|complete|confirmed)"
    r"|unsubscribed successfully)\b",
    re.I,
)


def _origin(url: str) -> tuple[str, str | None, int]:
    parsed = urlsplit(url)
    return parsed.scheme.casefold(), parsed.hostname, parsed.port or 443


def _confirmed(text: str) -> bool:
    for line in text.splitlines():
        if "?" in line or re.search(r"\b(?:if|when|once|after|before|until)\b", line, re.I):
            continue
        if CONFIRMED.search(line) or re.fullmatch(r"\s*already unsubscribed[.!]?\s*", line, re.I):
            return True
    return False


def _unsubscribe_target(url: str) -> bool:
    path = urlsplit(url).path.casefold()
    return not re.search(r"/(?:analytics|events|telemetry)/", path) and bool(
        re.search(r"(?:^|/)(?:[^/]*unsubscri[^/]*|opt[-_]?out)(?:/|$)", path)
    )


def complete_unsubscribe(url: str) -> BrowserOutcome:
    try:
        sync_api = import_module("playwright.sync_api")
    except ImportError:
        return BrowserOutcome(False, "browser_not_installed")
    try:
        origin = _origin(url)
        if origin[0] != "https" or not origin[1]:
            return BrowserOutcome(False, "browser_unsafe_destination")
    except ValueError:
        return BrowserOutcome(False, "browser_unsafe_destination")

    deadline = time.monotonic() + 45
    requests = 0
    total_bytes = 0
    submitted = False
    visited = False
    blocked = False
    blocked_action = False
    accepted_submit = False
    clicked = False
    approved_targets: set[str] = set()
    navigation: str | None = None

    def route_request(route: Any) -> None:
        nonlocal requests, total_bytes, submitted, blocked, blocked_action, accepted_submit
        nonlocal navigation
        request = route.request
        candidate = request.url in approved_targets or (
            _unsubscribe_target(request.url)
            and (request.method == "POST" or request.resource_type in {"xhr", "fetch"})
        )
        try:
            if request.resource_type not in {"document", "script", "stylesheet", "xhr", "fetch"}:
                route.abort()
                return
            requests += 1
            if requests > 80 or time.monotonic() >= deadline or total_bytes > 16 * 1024 * 1024:
                raise ValueError("Browser request budget exhausted")
            target_origin = _origin(request.url)
            if target_origin[0] != "https":
                raise ValueError("HTTPS required")
            if request.method not in {"GET", "HEAD", "POST"}:
                raise ValueError("Unsupported method")
            if (
                request.method == "POST" or request.resource_type == "document"
            ) and target_origin != origin:
                raise ValueError("Cross-origin action")
            if (
                candidate
                or request.method == "POST"
                or (clicked and request.resource_type in {"xhr", "fetch"})
            ):
                submitted = True
            request_headers = request.all_headers()
            headers = {
                key: value
                for key, value in request_headers.items()
                if key.casefold()
                not in {
                    "cookie",
                    "authorization",
                    "proxy-authorization",
                    "referer",
                    "accept-encoding",
                    "host",
                    "connection",
                    "content-length",
                }
            }
            if target_origin == origin and "cookie" in request_headers:
                headers["cookie"] = request_headers["cookie"]
            target, method, data = request.url, request.method, request.post_data_buffer
            for hop in range(6):
                if hop:
                    requests += 1
                if requests > 80 or total_bytes > 16 * 1024 * 1024 or time.monotonic() >= deadline:
                    raise ValueError("Browser request budget exhausted")
                response = safe_fetch(
                    target,
                    method=method,
                    data=data,
                    headers=headers,
                    timeout=max(0.1, min(10, deadline - time.monotonic())),
                    max_body=2 * 1024 * 1024,
                    allow_http=False,
                    follow_redirects=False,
                    return_redirects=True,
                    allow_cookies=target_origin == origin,
                )
                total_bytes += len(response.body.encode())
                if not 300 <= response.status < 400:
                    break
                destination = urljoin(target, response.headers.get("location", "")).split("#", 1)[0]
                if (
                    not response.headers.get("location")
                    or _origin(destination) != origin
                    or hop == 5
                    or time.monotonic() >= deadline
                ):
                    raise ValueError("Unsafe or exhausted redirect")
                if candidate:
                    approved_targets.add(destination)
                if response.status == 303 or (response.status in {301, 302} and method == "POST"):
                    method, data = "GET", None
                if request.resource_type == "document":
                    if method != "GET":
                        raise ValueError("Document redirect requires resubmission")
                    navigation = destination
                    route.fulfill(status=200, body="", headers=response.headers)
                    return
                if request.resource_type not in {"xhr", "fetch"}:
                    raise ValueError("Unsupported resource redirect")
                # Chromium does not route redirect hops after route.fulfill().
                # Follow API redirects here, validating every destination first.
                if target_origin == origin:
                    for line in response.headers.get("set-cookie", "").splitlines():
                        cookies = SimpleCookie()
                        cookies.load(line)
                        for cookie in cookies.values():
                            context.add_cookies(
                                [{"name": cookie.key, "value": cookie.value, "url": target}]
                            )
                    headers["cookie"] = "; ".join(
                        f"{cookie['name']}={cookie['value']}"
                        for cookie in context.cookies(destination)
                    )
                target = destination
            if request.resource_type == "document" and _origin(response.final_url) != origin:
                raise ValueError("Cross-origin navigation")
            if candidate:
                if 200 <= response.status < 300:
                    accepted_submit = True
                else:
                    raise ValueError("Unsubscribe response was not accepted")
            content_type = response.content_type.split(";", 1)[0] + "; charset=utf-8"
            route.fulfill(
                status=response.status,
                body=response.body,
                content_type=content_type,
                headers=response.headers,
            )
        except Exception:
            blocked = True
            blocked_action |= candidate
            try:
                route.abort()
            except Exception:
                pass

    try:
        with sync_api.sync_playwright() as playwright:
            # All page traffic is fulfilled through the pinned-IP safe fetcher.
            # The dead proxy also denies browser traffic that bypasses routing.
            browser = playwright.chromium.launch(
                headless=True,
                timeout=max(1, (deadline - time.monotonic()) * 1000),
                chromium_sandbox=True,
                proxy={"server": "http://127.0.0.1:9"},
                args=[
                    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    "--proxy-bypass-list=<-loopback>",
                ],
            )
            context = browser.new_context(accept_downloads=False, service_workers="block")
            try:
                context.route("**/*", route_request)
                context.route_web_socket("**/*", lambda socket: socket.close())
                page = context.new_page()
                context.on("page", lambda other: other.close() if other != page else None)
                page.set_default_timeout(2000)
                page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=max(1, (deadline - time.monotonic()) * 1000),
                )
                visited = True
                while time.monotonic() < deadline:
                    if navigation:
                        target, navigation = navigation, None
                        page.goto(
                            target,
                            wait_until="domcontentloaded",
                            timeout=max(1, (deadline - time.monotonic()) * 1000),
                        )
                        continue
                    text = page.locator("body").inner_text(timeout=2000)
                    gates = page.locator(
                        'input[type="password"]:visible, iframe[src*="captcha"]:visible, [data-sitekey]:visible'
                    )
                    if gates.count() or (
                        not clicked
                        and not accepted_submit
                        and re.search(
                            r"complete (?:the|a) captcha|verify (?:that )?you are human|sign in to|log in to|login required",
                            text,
                            re.I,
                        )
                    ):
                        return BrowserOutcome(False, "browser_user_interaction", submitted)
                    buttons = page.get_by_role("button", name=BUTTON_NAME).filter(visible=True)
                    if (
                        accepted_submit
                        and not blocked_action
                        and _confirmed(text)
                        and (
                            buttons.count() == 0
                            or (buttons.count() == 1 and not buttons.first.is_enabled())
                        )
                    ):
                        return BrowserOutcome(True)
                    if not clicked and buttons.count() == 1:
                        button = buttons.first
                        form = button.locator("xpath=ancestor::form[1]")
                        if (
                            form.count()
                            and form.locator(
                                'input:visible:not([type="submit"]):not([type="button"]):not([readonly]):not([disabled]), select:visible, textarea:visible'
                            ).count()
                        ):
                            return BrowserOutcome(False, "browser_preference_choice", submitted)
                        if re.search(
                            r"delete (?:your )?account|close (?:your )?account|all (?:emails|communications|messages)",
                            text,
                            re.I,
                        ):
                            return BrowserOutcome(False, "browser_scope_choice", submitted)
                        if form.count():
                            target = urljoin(page.url, form.get_attribute("action") or page.url)
                            if _origin(target) != origin:
                                return BrowserOutcome(False, "browser_scope_choice", submitted)
                            approved_targets.add(target.split("#", 1)[0])
                        clicked = True
                        button.click(timeout=2000)
                    page.wait_for_timeout(250)
                return BrowserOutcome(
                    False, "browser_blocked" if blocked else "browser_unconfirmed", submitted
                )
            finally:
                context.close()
                browser.close()
    except Exception:
        return BrowserOutcome(
            False,
            "browser_unconfirmed" if visited or submitted else "browser_unavailable",
            submitted,
        )
