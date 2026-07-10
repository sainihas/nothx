"""Tests for bounded, local-only MIME footer unsubscribe discovery."""

from __future__ import annotations

import base64

import pytest

from nothx.footer import (
    MAX_CANDIDATES,
    MAX_INLINE_PARTS,
    MAX_MIME_NODES,
    MAX_PART_BYTES,
    FooterLimits,
    InlineTextPart,
    candidate_fingerprint,
    extract_footer_candidates,
    redact_footer_uri,
    select_footer_parts,
)


def text_leaf(
    subtype: str,
    *,
    size: int = 1000,
    encoding: str = "7BIT",
    disposition: str = "INLINE",
    filename: str | None = None,
) -> str:
    disposition_params = f'("FILENAME" "{filename}")' if filename else "NIL"
    return (
        f'("TEXT" "{subtype}" ("CHARSET" "UTF-8") NIL NIL "{encoding}" '
        f'{size} 20 NIL ("{disposition}" {disposition_params}) NIL NIL)'
    )


class TestBodyStructureSelection:
    def test_selects_only_two_inline_plain_or_html_leaves(self) -> None:
        structure = (
            f"({text_leaf('PLAIN', size=100_000)}"
            f"{text_leaf('HTML', size=2_000, encoding='QUOTED-PRINTABLE')}"
            f"{text_leaf('PLAIN', disposition='ATTACHMENT', filename='message.txt')}"
            '"MIXED" ("BOUNDARY" "x") NIL NIL)'
        )
        result = select_footer_parts(structure)
        assert len(result.parts) == MAX_INLINE_PARTS
        assert result.parts[0].section == "1"
        assert result.parts[0].fetch_start == 100_000 - MAX_PART_BYTES
        assert result.parts[0].fetch_count == MAX_PART_BYTES
        assert result.parts[1].content_type == "text/html"
        assert result.truncated is True

    def test_attachment_text_and_non_text_resources_are_never_selected(self) -> None:
        attachment = text_leaf("PLAIN", disposition="ATTACHMENT", filename="data.txt")
        image = '("IMAGE" "PNG" NIL NIL NIL "BASE64" 1234 NIL NIL NIL NIL)'
        result = select_footer_parts(f'({attachment}{image}"MIXED" NIL NIL NIL)')
        assert result.parts == ()

    def test_message_rfc822_is_not_descended(self) -> None:
        nested = (
            '("MESSAGE" "RFC822" NIL NIL NIL "7BIT" 1000 NIL '
            f"{text_leaf('HTML')} 50 NIL NIL NIL NIL)"
        )
        result = select_footer_parts(nested)
        assert result.parts == ()
        assert result.nodes_seen == 1

    def test_nested_sections_are_numbered_for_imap_fetch(self) -> None:
        alternative = f'({text_leaf("PLAIN")}{text_leaf("HTML")}"ALTERNATIVE" NIL NIL NIL)'
        structure = f'({alternative}("IMAGE" "PNG" NIL NIL NIL "BASE64" 20 NIL NIL NIL NIL)'
        structure += '"MIXED" NIL NIL NIL)'
        result = select_footer_parts(structure)
        assert [part.section for part in result.parts] == ["1.1", "1.2"]
        assert result.parts[0].imap_partial == "BODY.PEEK[1.1]<0.1000>"

    def test_base64_tail_starts_on_quantum(self) -> None:
        result = select_footer_parts(text_leaf("PLAIN", size=100_003, encoding="BASE64"))
        part = result.parts[0]
        assert part.fetch_start % 4 == 0
        assert part.fetch_count <= MAX_PART_BYTES

    def test_fetch_specs_respect_total_byte_budget(self) -> None:
        limits = FooterLimits(max_part_bytes=100, max_total_bytes=120)
        structure = f"({text_leaf('PLAIN', size=200)}{text_leaf('HTML', size=200)}"
        structure += '"ALTERNATIVE" NIL NIL NIL)'
        result = select_footer_parts(structure, limits=limits)
        assert [part.fetch_count for part in result.parts] == [100, 20]
        assert sum(part.fetch_count for part in result.parts) == 120

    def test_zero_sized_part_is_not_selected(self) -> None:
        assert select_footer_parts(text_leaf("PLAIN", size=0)).parts == ()

    def test_mime_node_cap_is_fail_closed(self) -> None:
        structure = (
            "("
            + "".join(
                '("IMAGE" "PNG" NIL NIL NIL "BASE64" 10 NIL NIL NIL NIL)'
                for _ in range(MAX_MIME_NODES + 5)
            )
            + '"MIXED" NIL NIL NIL)'
        )
        result = select_footer_parts(structure)
        assert result.parts == ()
        assert result.nodes_seen == MAX_MIME_NODES
        assert result.truncated is True

    def test_bodystructure_byte_limit_is_enforced_before_parse(self) -> None:
        limits = FooterLimits(max_structure_bytes=16)
        result = select_footer_parts("(" + "NIL " * 10 + ")", limits=limits)
        assert result.parts == ()
        assert "byte limit" in (result.parse_error or "")

    def test_bodystructure_nesting_limit_fails_closed(self) -> None:
        limits = FooterLimits(max_structure_depth=4)
        structure = "(" * 8 + "NIL" + ")" * 8
        result = select_footer_parts(structure, limits=limits)
        assert result.parts == ()
        assert "nesting limit" in (result.parse_error or "")

    def test_bodystructure_token_limit_fails_closed(self) -> None:
        limits = FooterLimits(max_structure_tokens=8)
        result = select_footer_parts("(" + "NIL " * 12 + ")", limits=limits)
        assert result.parts == ()
        assert "token limit" in (result.parse_error or "")

    @pytest.mark.parametrize("value", ["", "(", '("TEXT"', "garbage trailing"])
    def test_malformed_structure_returns_error_without_raising(self, value: str) -> None:
        result = select_footer_parts(value)
        assert result.parts == ()
        assert result.parse_error


class TestCandidateExtraction:
    def test_plain_https_and_mailto_with_evidence_are_returned_in_order(self) -> None:
        text = (
            "To unsubscribe visit https://letters.example/unsub?opaque=secret. "
            "Or opt out by emailing mailto:leave@example.com?subject=unsubscribe"
        )
        result = extract_footer_candidates([InlineTextPart("1", "text/plain", text)])
        assert [item.uri for item in result.candidates] == [
            "https://letters.example/unsub?opaque=secret",
            "mailto:leave@example.com?subject=unsubscribe",
        ]
        assert {item.source for item in result.candidates} == {"footer_plain"}
        assert {item.evidence for item in result.candidates} <= {"unsubscribe", "opt out"}

    def test_html_uses_anchor_href_and_nearby_visible_evidence(self) -> None:
        html = (
            '<html><img src="https://tracking.example/unsubscribe.png">'
            '<p>To unsubscribe, <a href="https://letters.example/u?t=secret">click here</a>.</p>'
            "<script>https://evil.example/unsubscribe</script></html>"
        )
        result = extract_footer_candidates([InlineTextPart("2", "text/html", html)])
        assert [item.uri for item in result.candidates] == ["https://letters.example/u?t=secret"]
        assert result.candidates[0].source == "footer_html"

    def test_forms_and_links_inside_forms_are_never_candidates(self) -> None:
        html = (
            '<form action="https://example.com/unsubscribe">'
            '<a href="https://example.com/unsubscribe">Unsubscribe</a>'
            '<input name="email"></form>'
        )
        result = extract_footer_candidates([InlineTextPart("1", "text/html", html)])
        assert result.candidates == ()
        assert result.forms_seen is True

    @pytest.mark.parametrize(
        "target",
        [
            "http://example.com/unsubscribe",
            "/unsubscribe",
            "javascript:unsubscribe()",
            "https://user:password@example.com/unsubscribe",
            "https://example.com:99999/unsubscribe",
        ],
    )
    def test_non_https_or_structurally_unsafe_urls_are_rejected(self, target: str) -> None:
        html = f'<a href="{target}">Unsubscribe</a>'
        result = extract_footer_candidates([InlineTextPart("1", "text/html", html)])
        assert result.candidates == ()

    @pytest.mark.parametrize(
        "target",
        [
            "mailto:a@example.com,b@example.com?subject=unsubscribe",
            "mailto:a@example.com?cc=b@example.com&subject=unsubscribe",
            "mailto:a@example.com?subject=unsubscribe&subject=again",
            "mailto:Display%20Name%20%3Ca@example.com%3E?subject=unsubscribe",
            "mailto:a@localhost?subject=unsubscribe",
            "mailto:a@example.com?subject=unsubscribe%0ABcc%3Aevil%40example.com",
        ],
    )
    def test_mailto_requires_one_strict_recipient_and_safe_fields(self, target: str) -> None:
        result = extract_footer_candidates(
            [InlineTextPart("1", "text/html", f'<a href="{target}">Unsubscribe</a>')]
        )
        assert result.candidates == ()

    def test_link_without_unsubscribe_or_preferences_evidence_is_ignored(self) -> None:
        html = '<a href="https://example.com/view">View this email online</a>'
        result = extract_footer_candidates([InlineTextPart("1", "text/html", html)])
        assert result.candidates == ()

    def test_duplicate_plain_and_html_candidates_are_deduplicated(self) -> None:
        target = "https://example.com/unsubscribe?token=x"
        result = extract_footer_candidates(
            [
                InlineTextPart("1", "text/plain", f"Unsubscribe: {target}"),
                InlineTextPart("2", "text/html", f'<a href="{target}">Unsubscribe</a>'),
            ]
        )
        assert len(result.candidates) == 1

    def test_only_the_bounded_tail_is_examined(self) -> None:
        limits = FooterLimits(max_part_bytes=128, max_total_bytes=128)
        early = "Unsubscribe: https://early.example/unsubscribe "
        late = "Unsubscribe: https://late.example/unsubscribe"
        content = early + ("x" * 300) + late
        result = extract_footer_candidates(
            [InlineTextPart("1", "text/plain", content)], limits=limits
        )
        assert [item.uri for item in result.candidates] == ["https://late.example/unsubscribe"]
        assert result.bytes_examined == 128
        assert result.truncated is True

    def test_unknown_charset_falls_back_without_crashing(self) -> None:
        result = extract_footer_candidates(
            [
                InlineTextPart(
                    "1",
                    "text/plain",
                    b"Unsubscribe https://example.com/u",
                    charset="attacker-invented-charset",
                )
            ]
        )
        assert result.candidates[0].uri == "https://example.com/u"

    def test_plain_text_parentheses_are_not_part_of_target(self) -> None:
        result = extract_footer_candidates(
            [InlineTextPart("1", "text/plain", "Unsubscribe (https://example.com/unsubscribe).")]
        )
        assert result.candidates[0].uri == "https://example.com/unsubscribe"

    def test_attachments_and_third_inline_part_are_not_inspected(self) -> None:
        parts = [
            InlineTextPart(
                "1",
                "text/plain",
                "Unsubscribe https://attachment.example/unsubscribe",
                disposition="attachment",
                filename="note.txt",
            ),
            InlineTextPart("2", "text/plain", "Unsubscribe https://one.example/u"),
            InlineTextPart("3", "text/html", '<a href="https://two.example/u">Opt out</a>'),
            InlineTextPart("4", "text/plain", "Unsubscribe https://three.example/u"),
        ]
        result = extract_footer_candidates(parts)
        assert [item.uri for item in result.candidates] == [
            "https://one.example/u",
            "https://two.example/u",
        ]
        assert result.parts_examined == 2
        assert result.truncated is True

    def test_candidate_cap_is_enforced(self) -> None:
        links = " ".join(
            f"Unsubscribe https://list{index}.example/u" for index in range(MAX_CANDIDATES + 2)
        )
        result = extract_footer_candidates([InlineTextPart("1", "text/plain", links)])
        assert len(result.candidates) == MAX_CANDIDATES
        assert result.truncated is True

    def test_decodes_base64_and_quoted_printable_supplied_parts(self) -> None:
        plain = "Unsubscribe https://encoded.example/u"
        base64_result = extract_footer_candidates(
            [
                InlineTextPart(
                    "1",
                    "text/plain",
                    base64.b64encode(plain.encode()),
                    transfer_encoding="base64",
                    partial=False,
                )
            ]
        )
        quoted_result = extract_footer_candidates(
            [
                InlineTextPart(
                    "1",
                    "text/plain",
                    b"Unsubscribe https://quoted.example/u=3Ftoken=3Dx",
                    transfer_encoding="quoted-printable",
                    partial=False,
                )
            ]
        )
        assert base64_result.candidates[0].uri == "https://encoded.example/u"
        assert quoted_result.candidates[0].uri == "https://quoted.example/u?token=x"


class TestRedactionAndFingerprinting:
    def test_redaction_removes_tokens_and_mailto_local_part(self) -> None:
        assert (
            redact_footer_uri("https://Example.com/unsub/path?token=secret#fragment")
            == "https://example.com/unsub/path"
        )
        assert (
            redact_footer_uri("mailto:opaque-token@example.com?body=secret")
            == "mailto:<redacted>@example.com"
        )
        assert (
            redact_footer_uri("https://example.com/u/0123456789abcdef0123456789abcdef?token=secret")
            == "https://example.com/u/[redacted]"
        )

    def test_fingerprint_is_stable_without_exposing_target(self) -> None:
        uri = "https://example.com/u?secret=token"
        assert candidate_fingerprint(uri) == candidate_fingerprint(uri)
        assert uri not in candidate_fingerprint(uri)
