from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from nothx.browser import BrowserOutcome, _confirmed, complete_unsubscribe
from nothx.models import UnsubMethod
from nothx.safefetch import FetchResponse
from nothx.unsubscriber import _execute_get


@pytest.mark.parametrize(
    "text", ["You have been unsubscribed", "You've been unsubscribed", "Already unsubscribed"]
)
def test_browser_confirmation_assertions(text):
    assert _confirmed(text)


@pytest.mark.parametrize(
    "text",
    [
        "If you have been unsubscribed, click here.",
        "Unsubscribe",
        "Loading...",
        "Newsletter signup successful",
        "Have you already unsubscribed?",
        "When you are unsubscribed, these emails stop.",
    ],
)
def test_browser_does_not_invent_confirmation(text):
    assert not _confirmed(text)


def fake_browser(text="You have been unsubscribed"):
    page = MagicMock()
    page.wait_for_timeout.side_effect = TimeoutError("test deadline")
    page.get_by_role.return_value.filter.return_value.count.return_value = 0
    body = MagicMock()
    body.inner_text.return_value = text
    gates = MagicMock()
    gates.count.return_value = 0
    page.locator.side_effect = lambda selector: body if selector == "body" else gates
    context = MagicMock()
    context.new_page.return_value = page
    browser = MagicMock()
    browser.new_context.return_value = context
    driver = MagicMock()
    driver.chromium.launch.return_value = browser
    manager = MagicMock()
    manager.__enter__.return_value = driver
    api = SimpleNamespace(sync_playwright=lambda: manager)
    return api, driver, browser, context, page


def test_browser_isolated_and_all_requests_use_safe_transport():
    api, driver, browser, context, page = fake_browser()
    route = MagicMock()
    route.request = SimpleNamespace(
        url="https://news.example/api/unsubscribe",
        method="POST",
        resource_type="fetch",
        headers={
            "cookie": "private",
            "authorization": "private",
            "content-type": "application/json",
        },
        post_data_buffer=b'{"unsubscribe":true}',
    )
    route.request.all_headers = lambda: route.request.headers
    page.goto.side_effect = lambda *args, **kwargs: context.route.call_args.args[1](route)
    with (
        patch("nothx.browser.import_module", return_value=api),
        patch(
            "nothx.browser.safe_fetch",
            return_value=FetchResponse(200, "{}", route.request.url, 0, "application/json"),
        ) as fetch,
    ):
        assert complete_unsubscribe("https://news.example/unsubscribe") == BrowserOutcome(True)
    assert fetch.call_args.kwargs["headers"] == {
        "content-type": "application/json",
        "cookie": "private",
    }
    assert fetch.call_args.kwargs["allow_cookies"] is True
    assert fetch.call_args.kwargs["follow_redirects"] is False
    route.continue_.assert_not_called()
    route.fulfill.assert_called_once()
    assert driver.chromium.launch.call_args.kwargs["chromium_sandbox"]
    assert driver.chromium.launch.call_args.kwargs["proxy"] == {"server": "http://127.0.0.1:9"}
    assert browser.new_context.call_args.kwargs == {
        "accept_downloads": False,
        "service_workers": "block",
    }
    context.close.assert_called_once()
    browser.close.assert_called_once()


@pytest.mark.parametrize(
    ("url", "method"),
    [
        ("https://other.example/api/unsubscribe", "POST"),
        ("http://news.example/api/unsubscribe", "POST"),
        ("https://news.example/api/delete", "DELETE"),
    ],
)
def test_browser_denies_cross_origin_and_unsupported_requests(url, method):
    api, _, _, context, page = fake_browser()
    route = MagicMock()
    route.request = SimpleNamespace(
        url=url, method=method, resource_type="fetch", headers={}, post_data_buffer=b""
    )
    route.request.all_headers = lambda: route.request.headers
    page.goto.side_effect = lambda *args, **kwargs: context.route.call_args.args[1](route)
    with (
        patch("nothx.browser.import_module", return_value=api),
        patch("nothx.browser.safe_fetch") as fetch,
    ):
        result = complete_unsubscribe("https://news.example/unsubscribe")
    assert not result.success
    assert not result.ambiguous_send
    route.abort.assert_called_once()
    fetch.assert_not_called()


def test_browser_transport_failure_after_submission_is_not_retryable():
    api, _, _, context, page = fake_browser()
    route = MagicMock()
    route.request = SimpleNamespace(
        url="https://news.example/api/unsubscribe",
        method="POST",
        resource_type="fetch",
        headers={},
        post_data_buffer=b"",
    )

    route.request.all_headers = lambda: route.request.headers

    def navigate(*args, **kwargs):
        context.route.call_args.args[1](route)
        raise OSError("transport failed")

    page.goto.side_effect = navigate
    with (
        patch("nothx.browser.import_module", return_value=api),
        patch("nothx.browser.safe_fetch", side_effect=OSError("no response")),
    ):
        result = complete_unsubscribe("https://news.example/unsubscribe")
    assert not result.success and result.ambiguous_send


def test_get_browser_fallback_is_explicit_and_preserves_ambiguity():
    response = FetchResponse(
        200, "<script></script><p>Loading...</p>", "https://news.example/unsubscribe", 0
    )
    with (
        patch("nothx.unsubscriber._rate_limited", return_value=None),
        patch("nothx.unsubscriber._fetch_with_retry", return_value=response),
        patch(
            "nothx.browser.complete_unsubscribe",
            return_value=BrowserOutcome(False, "browser_unconfirmed", True),
        ) as browser,
    ):
        _execute_get(response.final_url)
        browser.assert_not_called()
        result = _execute_get(response.final_url, browser_fallback=True)
    assert result.method is UnsubMethod.BROWSER
    assert result._ambiguous_send is True
    assert result.needs_confirmation


def test_browser_follows_same_origin_confirmation_redirect():
    api, _, _, context, page = fake_browser()
    routes = []
    for path, method, resource in [
        ("/api/unsubscribe", "POST", "fetch"),
        ("/confirmation", "GET", "fetch"),
    ]:
        route = MagicMock()
        route.request = SimpleNamespace(
            url="https://news.example" + path,
            method=method,
            resource_type=resource,
            headers={"next-action": "synthetic-action"},
            post_data_buffer=None,
        )
        route.request.all_headers = lambda route=route: route.request.headers
        routes.append(route)

    def navigate(*args, **kwargs):
        context.route.call_args.args[1](routes[0])

    page.goto.side_effect = navigate
    with (
        patch("nothx.browser.import_module", return_value=api),
        patch(
            "nothx.browser.safe_fetch",
            side_effect=[
                FetchResponse(
                    303, "", routes[0].request.url, 0, headers={"location": "/confirmation"}
                ),
                FetchResponse(200, "{}", routes[1].request.url, 0),
            ],
        ) as fetch,
    ):
        assert complete_unsubscribe("https://news.example/unsubscribe").success
    assert fetch.call_args_list[0].kwargs["headers"]["next-action"] == "synthetic-action"
    assert routes[0].fulfill.call_args.kwargs["status"] == 200
    assert fetch.call_args_list[1].args[0] == "https://news.example/confirmation"


def test_browser_rejects_optimistic_text_when_unsubscribe_request_failed():
    api, _, _, context, page = fake_browser()
    route = MagicMock()
    route.request = SimpleNamespace(
        url="https://news.example/api/unsubscribe",
        method="POST",
        resource_type="fetch",
        headers={},
        post_data_buffer=b"",
    )
    route.request.all_headers = lambda: route.request.headers
    page.goto.side_effect = lambda *args, **kwargs: context.route.call_args.args[1](route)
    with (
        patch("nothx.browser.import_module", return_value=api),
        patch(
            "nothx.browser.safe_fetch", return_value=FetchResponse(403, "", route.request.url, 0)
        ),
    ):
        result = complete_unsubscribe("https://news.example/unsubscribe")
    assert not result.success
    assert result.ambiguous_send


@pytest.mark.parametrize("error", ["browser_not_installed", "browser_unavailable"])
def test_missing_browser_preserves_get_retry_semantics(error):
    response = FetchResponse(
        200, "<script></script><p>Loading...</p>", "https://news.example/unsubscribe", 0
    )
    with (
        patch("nothx.unsubscriber._rate_limited", return_value=None),
        patch("nothx.unsubscriber._fetch_with_retry", return_value=response),
        patch("nothx.browser.complete_unsubscribe", return_value=BrowserOutcome(False, error)),
    ):
        result = _execute_get(response.final_url, browser_fallback=True)
    assert result.method is UnsubMethod.GET
    assert result._error_code == "interactive_response"
    assert not result._ambiguous_send
