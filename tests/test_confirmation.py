"""Only unambiguous opt-out forms may be submitted without browser interaction."""

import pytest

from nothx import unsubscriber
from nothx.confirmation import confirmation_request
from nothx.safefetch import FetchResponse

URL = "https://mailer.example/unsubscribe/token"
FORM = '<form action="/unsubscribe" method="post"><input type="hidden" name="token" value="secret"><button name="decision" value="yes">Unsubscribe</button></form>'


def test_simple_form_encodes_hidden_token_and_clicked_button():
    assert confirmation_request(FORM, URL) == (
        "https://mailer.example/unsubscribe",
        "POST",
        b"token=secret&decision=yes",
    )


@pytest.mark.parametrize(
    "body",
    [
        FORM.replace('/unsubscribe"', 'https://other.example/unsubscribe"'),
        FORM.replace("<button", '<input type="password"><button'),
        FORM.replace("<button", '<input type="checkbox" name="news"><button'),
        FORM.replace("<button", '<select name="frequency"></select><button'),
        FORM.replace("<button", '<button onclick="submitOther()"'),
        FORM + FORM,
        "<p>Unsubscribe</p><form><button>Confirm</button></form>",
        "<script>unsubscribe</script><form><button>Confirm</button></form>",
        FORM + '<div class="g-recaptcha"></div>',
        FORM.replace("<button", "<p>Delete your account</p><button"),
    ],
)
def test_ambiguous_or_interactive_form_is_left_for_user(body):
    assert confirmation_request(body, URL) is None


def test_generic_confirmation_requires_local_unsubscribe_context():
    assert confirmation_request(
        "<form><p>Confirm your unsubscribe</p><button>Confirm</button></form>", URL
    )


def test_example_newsletter_confirm_scope():
    form = '<form method="post"><input type="hidden" name="target" value="newsletter"><button>Confirm</button></form>'
    assert confirmation_request(
        form,
        "https://mailer-q7m4.example/account/change_setting.rvt?target=newsletter;action=never",
    )
    assert (
        confirmation_request(
            form,
            "https://mailer-q7m4.example/account/change_setting.rvt?target=account;action=delete",
        )
        is None
    )


def test_executor_finishes_form_and_navigation_login_does_not_override_success(monkeypatch):
    monkeypatch.setattr(unsubscriber._http_rate_limiter, "acquire", lambda timeout=None: True)
    calls = []

    def fetch(url, **kwargs):
        calls.append((url, kwargs))
        return FetchResponse(
            200,
            FORM if len(calls) == 1 else "<nav>Log In</nav><h1>Unsubscribe successful</h1>",
            url,
            (),
        )

    monkeypatch.setattr(unsubscriber, "safe_fetch", fetch)
    result = unsubscriber._execute_get(URL)
    assert result.success
    assert len(calls) == 2
    assert calls[1][1]["method"] == "POST"
    assert calls[1][1]["data"] == b"token=secret&decision=yes"


@pytest.mark.parametrize("response", ["timeout", "<h1>Try again</h1>"])
def test_uncertain_submission_never_retries(monkeypatch, response):
    monkeypatch.setattr(unsubscriber._http_rate_limiter, "acquire", lambda timeout=None: True)
    calls = []

    def fetch(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return FetchResponse(200, FORM, url, ())
        if response == "timeout":
            raise TimeoutError()
        return FetchResponse(200, response, url, ())

    monkeypatch.setattr(unsubscriber, "safe_fetch", fetch)
    result = unsubscriber._execute_get(URL)
    assert not result.success
    assert result.needs_confirmation
    assert result._ambiguous_send
    assert len(calls) == 2


def test_script_success_is_not_confirmation_and_login_wall_still_blocks():
    assert not unsubscriber._check_success_indicators(
        '<script>"you have been unsubscribed"</script><div>Loading</div>'
    )
    assert unsubscriber._check_interaction_gate_indicators(
        "Sign in to continue. You have been unsubscribed"
    )
    assert unsubscriber._check_interaction_gate_indicators(
        '<input type="password">You have been unsubscribed'
    )


@pytest.mark.parametrize("attribute", ["hidden", 'aria-hidden="true"', 'style="display:none"'])
def test_hidden_success_placeholder_is_not_confirmation(attribute):
    assert not unsubscriber._check_success_indicators(
        f"<div {attribute}><b>You have been unsubscribed</b></div><p>Loading</p>"
    )


def test_success_page_does_not_submit_a_broader_followup(monkeypatch):
    monkeypatch.setattr(unsubscriber._http_rate_limiter, "acquire", lambda timeout=None: True)
    from unittest.mock import Mock

    fetch = Mock(
        return_value=FetchResponse(200, "<h1>You have been unsubscribed</h1>" + FORM, URL, 0)
    )
    monkeypatch.setattr(unsubscriber, "safe_fetch", fetch)
    result = unsubscriber._execute_get(URL)
    assert result.success
    assert not result._ambiguous_send
    fetch.assert_called_once()


@pytest.mark.parametrize(
    "body",
    [
        "<form><fieldset disabled><button>Unsubscribe</button></fieldset></form>",
        '<form><div hidden><input type="checkbox" name="all" checked></div><button>Unsubscribe</button></form>',
        '<form><div hidden><input type="hidden" name="token" value="test"></div><button>Unsubscribe</button></form>',
        "<form><p>Unsubscribe from all emails</p><button>Unsubscribe</button></form>",
        '<base href="https://other.example/">' + FORM,
    ],
)
def test_form_semantics_that_need_a_browser_are_not_submitted(body):
    assert confirmation_request(body, URL) is None


def test_unclosed_optional_tag_in_hidden_container_does_not_hide_success():
    assert unsubscriber._check_success_indicators(
        "<div hidden><p>placeholder</div><h1>You have been unsubscribed</h1>"
    )


def test_conditional_unsubscribe_text_is_not_confirmation():
    assert not unsubscriber._check_success_indicators("If you've already unsubscribed, ignore this")
    assert not unsubscriber._check_success_indicators(
        "If you are already unsubscribed, ignore this."
    )
    assert unsubscriber._check_success_indicators("You are already unsubscribed.")
    assert unsubscriber._check_success_indicators("Already unsubscribed")
    assert (
        confirmation_request(
            "<form>Unsubscribe from all marketing emails<button>Unsubscribe</button></form>", URL
        )
        is None
    )
