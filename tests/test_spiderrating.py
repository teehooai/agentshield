"""Tests for SpiderRating conversion module."""

from __future__ import annotations

from teeshield.spiderrating import (
    compute_grade,
    compute_metadata_score,
    convert,
    detect_hard_constraints,
    map_description_dimensions,
    map_security,
    parse_owner_repo,
)


class TestComputeGrade:
    def test_grade_a(self):
        assert compute_grade(9.0, None) == "A"

    def test_grade_b(self):
        assert compute_grade(7.5, None) == "B"

    def test_grade_c(self):
        assert compute_grade(5.5, None) == "C"

    def test_grade_d(self):
        assert compute_grade(3.5, None) == "D"

    def test_grade_f(self):
        assert compute_grade(2.0, None) == "F"

    def test_critical_forces_f(self):
        assert compute_grade(9.5, "critical_vulnerability") == "F"

    def test_no_tools_forces_f(self):
        assert compute_grade(8.0, "no_tools") == "F"

    def test_license_banned_caps_d(self):
        assert compute_grade(9.0, "license_banned") == "D"

    def test_license_banned_low_score_f(self):
        assert compute_grade(2.0, "license_banned") == "F"


class TestDetectHardConstraints:
    def test_no_constraints(self):
        assert detect_hard_constraints([], 5, "MIT") is None

    def test_critical_vulnerability(self):
        issues = [{"severity": "critical", "category": "rce"}]
        assert detect_hard_constraints(issues, 5, "MIT") == "critical_vulnerability"

    def test_no_tools(self):
        assert detect_hard_constraints([], 0, "MIT") == "no_tools"

    def test_banned_license(self):
        assert detect_hard_constraints([], 5, "AGPL-3.0") == "license_banned"

    def test_allowed_license(self):
        assert detect_hard_constraints([], 5, "Apache-2.0") is None


class TestComputeMetadataScore:
    def test_default_meta(self):
        meta = {"stars": 0, "forks": 0, "license": None, "description": ""}
        result = compute_metadata_score(meta)
        assert "provenance" in result
        assert "maintenance" in result
        assert "popularity" in result
        assert "composite" in result
        assert 0 <= result["composite"] <= 10

    def test_high_stars(self):
        meta = {
            "stars": 10000, "forks": 500,
            "license": "MIT",
            "description": "A great tool for developers",
        }
        result = compute_metadata_score(meta)
        assert result["popularity"] >= 9.0
        assert result["provenance"] >= 7.0

    def test_recent_commit(self):
        import datetime as dt
        meta = {
            "stars": 0, "forks": 0,
            "last_commit": dt.datetime.now(
                tz=dt.UTC
            ).isoformat(),
        }
        result = compute_metadata_score(meta)
        assert result["maintenance"] >= 8.0


class TestMapDescriptionDimensions:
    def test_empty_tools(self):
        result = map_description_dimensions([])
        assert result["composite"] == 5.0

    def test_perfect_tools(self):
        tools = [{
            "has_action_verb": True,
            "has_scenario_trigger": True,
            "has_param_docs": True,
            "has_error_guidance": True,
            "has_param_examples": True,
            "disambiguation_score": 1.0,
            "overall_score": 9.0,
        }]
        result = map_description_dimensions(tools)
        assert result["intent_clarity"] == 10.0
        assert result["permission_scope"] == 10.0

    def test_no_quality_signals(self):
        tools = [{
            "has_action_verb": False,
            "has_scenario_trigger": False,
            "has_param_docs": False,
            "has_error_guidance": False,
            "has_param_examples": False,
            "disambiguation_score": 0.0,
            "overall_score": 1.0,
        }]
        result = map_description_dimensions(tools)
        assert result["intent_clarity"] == 0.0
        assert result["permission_scope"] == 0.0


class TestMapSecurity:
    def test_clean_security(self):
        result = map_security(10.0, [], 8.0)
        assert result["score"] == 10.0
        assert result["critical_count"] == 0

    def test_with_issues(self):
        issues = [
            {"severity": "critical", "category": "rce", "file": "a.py", "description": "bad"},
            {"severity": "low", "category": "info", "file": "b.py", "description": "minor"},
        ]
        result = map_security(5.0, issues, 5.0)
        assert result["critical_count"] == 1
        assert result["low_count"] == 1
        assert len(result["issues"]) == 2


class TestParseOwnerRepo:
    def test_simple(self):
        assert parse_owner_repo("owner/repo") == ("owner", "repo")

    def test_github_url(self):
        assert parse_owner_repo("https://github.com/owner/repo") == ("owner", "repo")

    def test_github_url_with_git(self):
        assert parse_owner_repo("https://github.com/owner/repo.git") == ("owner", "repo")

    def test_invalid(self):
        import pytest
        with pytest.raises(ValueError):
            parse_owner_repo("noslash")


class TestConvert:
    def test_basic_conversion(self):
        report = {
            "tool_scores": [],
            "security_score": 8.0,
            "security_issues": [],
            "architecture_score": 7.0,
            "tool_count": 3,
            "license": "MIT",
        }
        meta = {"stars": 100, "forks": 10, "description": "Test", "license": "MIT"}
        result = convert(report, "owner", "repo", github_meta=meta)
        assert result["server"]["slug"] == "owner/repo"
        assert result["score"]["grade"] in ("A", "B", "C", "D", "F")
        assert "overall" in result["score"]
        assert result["tool_count"] == 3

    def test_critical_forces_f_grade(self):
        report = {
            "tool_scores": [],
            "security_score": 3.0,
            "security_issues": [{"severity": "critical", "category": "rce"}],
            "architecture_score": 5.0,
            "tool_count": 2,
        }
        meta = {"stars": 0, "forks": 0}
        result = convert(report, "o", "r", github_meta=meta)
        assert result["score"]["grade"] == "F"
        assert result["score"]["overall"] <= 2.0
