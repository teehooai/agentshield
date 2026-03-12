"""Tests for the public scoring specification."""

import pytest

from spidershield.scoring_spec import (
    ARCHITECTURE_BONUS_MAX,
    DEFAULT_LAYER_WEIGHTS,
    DESC_WEIGHTS,
    GRADE_THRESHOLDS,
    META_WEIGHTS,
    SEVERITY_PENALTIES,
    SPEC_VERSION,
    spec_architecture_bonus,
    spec_description_composite,
    spec_grade,
    spec_metadata_composite,
    spec_overall,
    spec_security_score,
)


class TestSpecVersion:
    def test_version_format(self):
        parts = SPEC_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)


class TestWeights:
    def test_desc_weights_sum_to_1(self):
        assert abs(sum(DESC_WEIGHTS.values()) - 1.0) < 0.001

    def test_meta_weights_sum_to_1(self):
        assert abs(sum(META_WEIGHTS.values()) - 1.0) < 0.001

    def test_layer_weights_sum_to_1(self):
        assert abs(sum(DEFAULT_LAYER_WEIGHTS.values()) - 1.0) < 0.001

    def test_desc_has_5_dimensions(self):
        expected = {
            "intent_clarity", "permission_scope", "side_effects",
            "capability_disclosure", "operational_boundaries",
        }
        assert set(DESC_WEIGHTS.keys()) == expected

    def test_meta_has_3_dimensions(self):
        expected = {"provenance", "maintenance", "popularity"}
        assert set(META_WEIGHTS.keys()) == expected


class TestSpecGrade:
    @pytest.mark.parametrize("score,expected", [
        (10.0, "A"), (9.5, "A"), (9.0, "A"),
        (8.99, "B"), (8.0, "B"), (7.0, "B"),
        (6.99, "C"), (5.0, "C"),
        (4.99, "D"), (3.0, "D"),
        (2.99, "F"), (0.0, "F"),
    ])
    def test_grade_boundaries(self, score, expected):
        assert spec_grade(score) == expected

    def test_grade_thresholds_descending(self):
        thresholds = [t for t, _ in GRADE_THRESHOLDS]
        assert thresholds == sorted(thresholds, reverse=True)


class TestSpecSecurityScore:
    def test_perfect_score(self):
        assert spec_security_score(0, 0, 0, 0) == 10.0

    def test_one_critical(self):
        assert spec_security_score(1, 0, 0, 0) == 7.0

    def test_one_of_each(self):
        # 10 - (3 + 2 + 1 + 0.25) = 3.75
        assert spec_security_score(1, 1, 1, 1) == 3.75

    def test_floor_at_zero(self):
        assert spec_security_score(10, 10, 10, 10) == 0.0

    def test_architecture_bonus(self):
        assert spec_security_score(1, 0, 0, 0, 2.0) == 9.0

    def test_bonus_capped(self):
        # Even with huge bonus, max is 10
        assert spec_security_score(0, 0, 0, 0, 100.0) == 10.0

    def test_bonus_cap_value(self):
        assert ARCHITECTURE_BONUS_MAX == 2.0


class TestSpecDescriptionComposite:
    def test_all_tens(self):
        dims = {k: 10.0 for k in DESC_WEIGHTS}
        assert spec_description_composite(dims) == 10.0

    def test_all_zeros(self):
        dims = {k: 0.0 for k in DESC_WEIGHTS}
        assert spec_description_composite(dims) == 0.0

    def test_missing_dimensions_default_to_zero(self):
        assert spec_description_composite({}) == 0.0

    def test_partial_dimensions(self):
        # Only permission_scope at 10 → 10 * 0.25 = 2.5
        result = spec_description_composite({"permission_scope": 10.0})
        assert abs(result - 2.5) < 0.01


class TestSpecMetadataComposite:
    def test_all_tens(self):
        assert spec_metadata_composite(10.0, 10.0, 10.0) == 10.0

    def test_all_zeros(self):
        assert spec_metadata_composite(0.0, 0.0, 0.0) == 0.0

    def test_weighted_average(self):
        # 8*0.4 + 6*0.35 + 4*0.25 = 3.2 + 2.1 + 1.0 = 6.3
        result = spec_metadata_composite(8.0, 6.0, 4.0)
        assert abs(result - 6.3) < 0.01


class TestSpecOverall:
    def test_default_weights(self):
        # 8*0.35 + 6*0.35 + 4*0.30 = 2.8 + 2.1 + 1.2 = 6.1
        result = spec_overall(8.0, 6.0, 4.0)
        assert abs(result - 6.1) < 0.01

    def test_custom_weights(self):
        weights = {"description": 0.5, "security": 0.3, "metadata": 0.2}
        # 8*0.5 + 6*0.3 + 4*0.2 = 4.0 + 1.8 + 0.8 = 6.6
        result = spec_overall(8.0, 6.0, 4.0, weights=weights)
        assert abs(result - 6.6) < 0.01

    def test_clamped_to_10(self):
        assert spec_overall(10.0, 10.0, 10.0) == 10.0


class TestSpecArchitectureBonus:
    def test_zero(self):
        assert spec_architecture_bonus(0.0) == 0.0

    def test_max(self):
        assert spec_architecture_bonus(10.0) == 2.0

    def test_midpoint(self):
        assert spec_architecture_bonus(5.0) == 1.0

    def test_capped(self):
        assert spec_architecture_bonus(15.0) == 2.0

    def test_negative_clamped(self):
        assert spec_architecture_bonus(-5.0) == 0.0
