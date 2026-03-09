"""Tests for SARIF v2.1.0 output."""

from __future__ import annotations

import json

from teeshield.agent.models import (
    Finding,
    ScanResult,
    Severity,
    SkillFinding,
    SkillVerdict,
)
from teeshield.agent.sarif import (
    SARIF_VERSION,
    sarif_to_json,
    scan_result_to_sarif,
)


def _make_result(
    findings: list[Finding] | None = None,
    skill_findings: list[SkillFinding] | None = None,
) -> ScanResult:
    return ScanResult(
        config_path="~/.openclaw/config.yaml",
        version="1.0",
        findings=findings or [],
        skill_findings=skill_findings or [],
    )


class TestSarifStructure:
    def test_valid_sarif_envelope(self) -> None:
        result = _make_result()
        sarif = scan_result_to_sarif(result)
        assert sarif["version"] == SARIF_VERSION
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_tool_driver_info(self) -> None:
        result = _make_result()
        sarif = scan_result_to_sarif(result)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "TeeShield"
        assert "informationUri" in driver

    def test_empty_result_no_findings(self) -> None:
        result = _make_result()
        sarif = scan_result_to_sarif(result)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_serializable_to_json(self) -> None:
        result = _make_result(findings=[
            Finding(
                check_id="gateway_bind",
                title="Gateway bound to LAN",
                severity=Severity.CRITICAL,
                description="Gateway is accessible from the network",
            ),
        ])
        sarif = scan_result_to_sarif(result)
        json_str = sarif_to_json(sarif)
        parsed = json.loads(json_str)
        assert parsed["version"] == SARIF_VERSION


class TestConfigFindings:
    def test_critical_maps_to_error(self) -> None:
        result = _make_result(findings=[
            Finding(
                check_id="gateway_bind",
                title="Gateway bound to LAN",
                severity=Severity.CRITICAL,
                description="Gateway is accessible from the network",
            ),
        ])
        sarif = scan_result_to_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        assert len(rules) == 1
        assert rules[0]["id"] == "TS-gateway_bind"
        assert rules[0]["defaultConfiguration"]["level"] == "error"
        assert len(results) == 1
        assert results[0]["level"] == "error"

    def test_medium_maps_to_warning(self) -> None:
        result = _make_result(findings=[
            Finding(
                check_id="logging",
                title="Logging redact off",
                severity=Severity.MEDIUM,
                description="Sensitive data may appear in logs",
            ),
        ])
        sarif = scan_result_to_sarif(result)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_low_maps_to_note(self) -> None:
        result = _make_result(findings=[
            Finding(
                check_id="version_check",
                title="Old version",
                severity=Severity.LOW,
                description="Not the latest version",
            ),
        ])
        sarif = scan_result_to_sarif(result)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_fix_hint_in_message(self) -> None:
        result = _make_result(findings=[
            Finding(
                check_id="no_auth",
                title="No authentication",
                severity=Severity.HIGH,
                description="No auth configured",
                fix_hint="Add auth_token to config",
            ),
        ])
        sarif = scan_result_to_sarif(result)
        message = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "Fix:" in message
        assert "auth_token" in message

    def test_multiple_findings_multiple_rules(self) -> None:
        result = _make_result(findings=[
            Finding("a", "Title A", Severity.HIGH, "Desc A"),
            Finding("b", "Title B", Severity.MEDIUM, "Desc B"),
            Finding("c", "Title C", Severity.LOW, "Desc C"),
        ])
        sarif = scan_result_to_sarif(result)
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 3
        assert len(sarif["runs"][0]["results"]) == 3

    def test_duplicate_check_id_deduplicates_rules(self) -> None:
        result = _make_result(findings=[
            Finding("same_check", "Title", Severity.HIGH, "First"),
            Finding("same_check", "Title", Severity.HIGH, "Second"),
        ])
        sarif = scan_result_to_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        assert len(rules) == 1  # Deduplicated
        assert len(results) == 2  # Both results kept


class TestSkillFindings:
    def test_malicious_skill_is_error(self) -> None:
        result = _make_result(skill_findings=[
            SkillFinding(
                skill_name="evil-skill",
                skill_path="/tmp/evil/SKILL.md",
                verdict=SkillVerdict.MALICIOUS,
                issues=["Known malicious skill"],
                matched_patterns=["known_malicious_slug"],
            ),
        ])
        sarif = scan_result_to_sarif(result)
        assert sarif["runs"][0]["results"][0]["level"] == "error"
        assert "evil-skill" in sarif["runs"][0]["results"][0]["message"]["text"]

    def test_suspicious_skill_is_warning(self) -> None:
        result = _make_result(skill_findings=[
            SkillFinding(
                skill_name="sketchy",
                skill_path="/tmp/sketchy/SKILL.md",
                verdict=SkillVerdict.SUSPICIOUS,
                issues=["Possible typosquat"],
                matched_patterns=["typosquat"],
            ),
        ])
        sarif = scan_result_to_sarif(result)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_tampered_skill_is_error(self) -> None:
        result = _make_result(skill_findings=[
            SkillFinding(
                skill_name="tampered",
                skill_path="/tmp/tampered/SKILL.md",
                verdict=SkillVerdict.TAMPERED,
                issues=["Content changed since pinned"],
                matched_patterns=["pin_tampered"],
            ),
        ])
        sarif = scan_result_to_sarif(result)
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_safe_skill_is_none(self) -> None:
        result = _make_result(skill_findings=[
            SkillFinding(
                skill_name="good-skill",
                skill_path="/tmp/good/SKILL.md",
                verdict=SkillVerdict.SAFE,
                issues=[],
                matched_patterns=[],
            ),
        ])
        sarif = scan_result_to_sarif(result)
        assert len(sarif["runs"][0]["results"]) == 0

    def test_multiple_issues_per_skill(self) -> None:
        result = _make_result(skill_findings=[
            SkillFinding(
                skill_name="multi-threat",
                skill_path="/tmp/multi/SKILL.md",
                verdict=SkillVerdict.MALICIOUS,
                issues=[
                    "Base64 pipe to shell",
                    "Reverse shell detected",
                    "Credential theft attempt",
                ],
                matched_patterns=[
                    "base64_pipe_bash",
                    "reverse_shell",
                    "credential_theft",
                ],
            ),
        ])
        sarif = scan_result_to_sarif(result)
        assert len(sarif["runs"][0]["results"]) == 3
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert "TS-SKILL-base64_pipe_bash" in rule_ids
        assert "TS-SKILL-reverse_shell" in rule_ids
        assert "TS-SKILL-credential_theft" in rule_ids


class TestLocationInfo:
    def test_config_finding_has_location(self) -> None:
        result = _make_result(findings=[
            Finding("test", "Test", Severity.HIGH, "Test desc"),
        ])
        sarif = scan_result_to_sarif(result)
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "~/.openclaw/config.yaml"
        assert loc["physicalLocation"]["region"]["startLine"] == 1

    def test_skill_finding_has_path(self) -> None:
        result = _make_result(skill_findings=[
            SkillFinding(
                skill_name="test",
                skill_path="/home/user/.openclaw/skills/test/SKILL.md",
                verdict=SkillVerdict.MALICIOUS,
                issues=["Bad"],
                matched_patterns=["test_pattern"],
            ),
        ])
        sarif = scan_result_to_sarif(result)
        uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "SKILL.md" in uri


class TestMixedResults:
    def test_config_and_skill_findings_together(self) -> None:
        result = _make_result(
            findings=[
                Finding("no_auth", "No auth", Severity.CRITICAL, "Missing auth"),
            ],
            skill_findings=[
                SkillFinding(
                    skill_name="evil",
                    skill_path="/tmp/evil/SKILL.md",
                    verdict=SkillVerdict.MALICIOUS,
                    issues=["Reverse shell"],
                    matched_patterns=["reverse_shell"],
                ),
            ],
        )
        sarif = scan_result_to_sarif(result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        assert len(rules) == 2
        assert len(results) == 2
        rule_ids = {r["id"] for r in rules}
        assert "TS-no_auth" in rule_ids
        assert "TS-SKILL-reverse_shell" in rule_ids
