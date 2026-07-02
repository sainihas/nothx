"""Tests for AI response JSON extraction robustness."""

from nothx.classifier.ai import _extract_json_value


class TestExtractJsonValue:
    def test_plain_array(self):
        assert _extract_json_value('[{"a": 1}]', "[") == [{"a": 1}]

    def test_array_in_markdown_fence(self):
        text = 'Here you go:\n```json\n[{"domain": "x.com"}]\n```\nDone.'
        assert _extract_json_value(text, "[") == [{"domain": "x.com"}]

    def test_array_with_trailing_prose(self):
        text = '[{"domain": "x.com"}]\n\nLet me know if you need more.'
        assert _extract_json_value(text, "[") == [{"domain": "x.com"}]

    def test_first_of_multiple_arrays(self):
        """rfind-based slicing would merge two arrays into invalid JSON."""
        text = '[{"a": 1}]\nand also\n[{"b": 2}]'
        assert _extract_json_value(text, "[") == [{"a": 1}]

    def test_object_extraction(self):
        text = 'Result:\n```json\n{"insights": []}\n```'
        assert _extract_json_value(text, "{") == {"insights": []}

    def test_bracket_in_prose_before_json(self):
        """A stray '[' in prose must not derail extraction."""
        text = 'Consider [this] example: [{"domain": "x.com"}]'
        assert _extract_json_value(text, "[") == [{"domain": "x.com"}]

    def test_no_json_returns_none(self):
        assert _extract_json_value("no json here", "[") is None

    def test_truncated_json_returns_none(self):
        assert _extract_json_value('[{"domain": "x.com"', "[") is None
