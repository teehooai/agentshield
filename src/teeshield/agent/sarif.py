"""SARIF v2.1.0 output for TeeShield agent scan results.

Produces GitHub Code Scanning compatible SARIF format.
Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from .models import ScanResult, Severity, SkillVerdict

# SARIF schema URI
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Tool info
TOOL_NAME = "TeeShield"
TOOL_URI = "https://github.com/teeshield/teeshield"

# Severity mapping to SARIF levels
_SEVERITY_TO_LEVEL: dict[str, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.OK: "none",
}

_VERDICT_TO_LEVEL: dict[str, str] = {
    SkillVerdict.MALICIOUS: "error",
    SkillVerdict.TAMPERED: "error",
    SkillVerdict.SUSPICIOUS: "warning",
    SkillVerdict.SAFE: "none",
    SkillVerdict.UNKNOWN: "note",
}


def _make_rule(rule_id: str, name: str, description: str, level: str) -> dict[str, Any]:
    """Create a SARIF reporting descriptor (rule)."""
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": description},
        "defaultConfiguration": {"level": level},
    }


def _make_result(
    rule_id: str,
    message: str,
    level: str,
    uri: str,
    line: int = 1,
) -> dict[str, Any]:
    """Create a SARIF result entry."""
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                },
            },
        ],
    }


def scan_result_to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to SARIF v2.1.0 format.

    Args:
        result: TeeShield agent scan result.

    Returns:
        SARIF JSON-compatible dict.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()

    # Config findings
    for finding in result.findings:
        rule_id = f"TS-{finding.check_id}"
        level = _SEVERITY_TO_LEVEL.get(finding.severity, "warning")

        if rule_id not in seen_rules:
            rules.append(_make_rule(
                rule_id=rule_id,
                name=finding.check_id,
                description=finding.title,
                level=level,
            ))
            seen_rules.add(rule_id)

        message = finding.description
        if finding.fix_hint:
            message += f" Fix: {finding.fix_hint}"

        results.append(_make_result(
            rule_id=rule_id,
            message=message,
            level=level,
            uri=result.config_path,
        ))

    # Skill findings
    for sf in result.skill_findings:
        level = _VERDICT_TO_LEVEL.get(sf.verdict, "warning")

        for i, issue in enumerate(sf.issues):
            if i < len(sf.matched_patterns):
                pattern = sf.matched_patterns[i]
            elif sf.matched_patterns:
                pattern = sf.matched_patterns[0]
            else:
                pattern = sf.verdict.value

            rule_id = f"TS-SKILL-{pattern}"

            if rule_id not in seen_rules:
                rules.append(_make_rule(
                    rule_id=rule_id,
                    name=pattern,
                    description=f"Skill scan: {pattern}",
                    level=level,
                ))
                seen_rules.add(rule_id)

            results.append(_make_result(
                rule_id=rule_id,
                message=f"[{sf.skill_name}] {issue}",
                level=level,
                uri=sf.skill_path,
            ))

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }

    return sarif


def sarif_to_json(sarif: dict[str, Any]) -> str:
    """Serialize SARIF dict to JSON string."""
    return json.dumps(sarif, indent=2, ensure_ascii=False)
