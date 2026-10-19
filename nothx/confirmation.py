"""Recognize narrowly scoped unsubscribe confirmation forms without executing JS."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


@dataclass
class _Form:
    action: str
    method: str
    fields: list[tuple[str, str]] = field(default_factory=list)
    buttons: list[tuple[str, str, str]] = field(default_factory=list)
    unsafe: bool = False
    text: list[str] = field(default_factory=list)


class ConfirmationPage(HTMLParser):
    """Visible text and simple forms only; never evaluate page instructions."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.forms: list[_Form] = []
        self.current: _Form | None = None
        self.button: tuple[str, str, list[str]] | None = None
        self.hidden = 0
        self.hidden_elements: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        invisible = (
            "hidden" in values
            or values.get("aria-hidden") == "true"
            or re.search(
                r"display\s*:\s*none|visibility\s*:\s*hidden", values.get("style") or "", re.I
            )
        )
        if self.hidden_elements or invisible:
            if tag not in {
                "input",
                "br",
                "hr",
                "img",
                "meta",
                "link",
                "area",
                "base",
                "embed",
                "source",
                "wbr",
            }:
                self.hidden_elements.append(tag)
            return
        if tag in {"script", "style", "template"}:
            self.hidden += 1
        if self.hidden:
            return
        if tag == "form":
            if self.current:
                self.current.unsafe = True
            self.current = _Form(
                values.get("action") or "", (values.get("method") or "get").lower()
            )
            self.current.unsafe = (
                "onsubmit" in values
                or (values.get("enctype") or "application/x-www-form-urlencoded").casefold()
                != "application/x-www-form-urlencoded"
            )
            self.forms.append(self.current)
        if self.current is None:
            return
        if tag in {"textarea", "select", "iframe"}:
            self.current.unsafe = True
        if tag in {"input", "button"}:
            kind = (values.get("type") or ("submit" if tag == "button" else "text")).lower()
            if any(
                k in values for k in ("formaction", "formmethod", "form", "onclick", "disabled")
            ):
                self.current.unsafe = True
            if kind == "hidden":
                if name := values.get("name"):
                    self.current.fields.append((name, values.get("value") or ""))
            elif kind == "submit":
                name, value = values.get("name") or "", values.get("value") or ""
                if tag == "button":
                    self.button = (name, value, [])
                else:
                    self.current.buttons.append((value, name, value))
            else:
                self.current.unsafe = True

    def handle_endtag(self, tag: str) -> None:
        if self.hidden_elements:
            if self.hidden_elements[-1] == tag:
                self.hidden_elements.pop()
            return
        if tag in {"script", "style", "template"} and self.hidden:
            self.hidden -= 1
        if tag == "button" and self.button and self.current:
            name, value, label = self.button
            self.current.buttons.append((" ".join(label), name, value))
            self.button = None
        if tag == "form":
            self.current = None

    def handle_data(self, data: str) -> None:
        if not self.hidden and not self.hidden_elements:
            self.text.append(data)
            if self.current:
                self.current.text.append(data)
            if self.button:
                self.button[2].append(data)


def confirmation_request(body: str, page_url: str) -> tuple[str, str, bytes | None] | None:
    """Return one same-origin opt-out request, or leave interactive pages alone."""
    page = ConfirmationPage()
    page.feed(body)
    visible = " ".join(page.text).casefold()
    if re.search(r"captcha|type\s*=\s*['\"]?password", body, re.I) or re.search(
        r"sign in to|log in to|login required|enable javascript", visible
    ):
        return None
    source = urlsplit(page_url)
    query = dict(parse_qsl(source.query.replace(";", "&")))
    example_newsletter = (
        source.hostname == "mailer-q7m4.example"
        and source.path == "/account/change_setting.rvt"
        and query.get("target") == "newsletter"
        and query.get("action") == "never"
    )
    if not example_newsletter and not re.search(r"unsubscribe|opt out of this email", visible):
        return None
    candidates: list[tuple[str, str, bytes | None]] = []
    for form in page.forms:
        if form.unsafe or form.method not in {"get", "post"} or len(form.fields) > 30:
            continue
        affirmative = [
            (name, value)
            for label, name, value in form.buttons
            if re.fullmatch(
                r"\s*(?:unsubscribe|confirm(?: unsubscribe)?|yes,? unsubscribe)\s*", label, re.I
            )
        ]
        if len(affirmative) != 1:
            continue
        # A generic Confirm elsewhere on the page is not an unsubscribe.
        labels = " ".join(label for label, _, _ in form.buttons).casefold()
        form_text = " ".join(form.text).casefold()
        if not example_newsletter and "unsubscribe" not in labels:
            if not re.search(r"confirm (?:your )?unsubscribe|unsubscribe from", form_text):
                continue
        if re.search(r"delete (?:your )?account|close (?:your )?account|resubscribe", form_text):
            continue
        target = urljoin(page_url, form.action)
        dest = urlsplit(target)
        try:
            same_origin = (dest.hostname, dest.port) == (source.hostname, source.port)
        except ValueError:
            continue
        if dest.scheme != "https" or not same_origin or dest.username or dest.password:
            continue
        fields = form.fields + ([affirmative[0]] if affirmative[0][0] else [])
        if form.method == "get":
            target = urlunsplit((dest.scheme, dest.netloc, dest.path, urlencode(fields), ""))
            candidates.append((target, "GET", None))
        else:
            candidates.append((target, "POST", urlencode(fields).encode()))
    return candidates[0] if len(candidates) == 1 else None


def visible_text(body: str) -> str:
    """Exclude script/template strings that may describe an unperformed action."""
    page = ConfirmationPage()
    page.feed(body)
    return " ".join(" ".join(page.text).split())
