"""Tests for confidence validation edge cases."""

import math

from nothx.errors import validate_confidence


class TestValidateConfidence:
    def test_in_range_unchanged(self):
        assert validate_confidence(0.5) == 0.5
        assert validate_confidence(0.0) == 0.0
        assert validate_confidence(1.0) == 1.0

    def test_clamps_out_of_range(self):
        assert validate_confidence(1.5) == 1.0
        assert validate_confidence(-0.3) == 0.0

    def test_nan_falls_back(self):
        """NaN passes every comparison, so it must be handled explicitly."""
        assert validate_confidence(float("nan")) == 0.5

    def test_inf_falls_back(self):
        assert validate_confidence(float("inf")) == 0.5
        assert validate_confidence(float("-inf")) == 0.5

    def test_nan_never_stored(self):
        result = validate_confidence(float("nan"))
        assert not math.isnan(result)
