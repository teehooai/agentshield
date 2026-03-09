"""Convert TeeShield scan output to SpiderRating format.

Unifies TeeShield's scoring model to SpiderRating's standard:
    - Weights: description 35% + security 35% + metadata 30%
    - Grade scale: F / D / C / B / A
    - 5 description dimensions (mapped from TeeShield's 7 criteria)
    - Hard constraints: critical → F, no_tools → F, known_malicious → F, license_banned → D cap
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime


def fetch_github_metadata(owner: str, repo: str) -> dict:
    """Fetch metadata from GitHub API (best-effort, no auth required for public repos)."""
    meta = {
        "stars": 0, "forks": 0, "last_commit": None, "created_at": None,
        "description": "", "license": None, "npm_package": None, "pypi_package": None,
    }
    try:
        url = f"https://api.github.com/repos/{owner}/{repo}"
        req = urllib.request.Request(url, headers={"User-Agent": "teeshield/0.2"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            meta["stars"] = data.get("stargazers_count", 0)
            meta["forks"] = data.get("forks_count", 0)
            meta["description"] = data.get("description") or ""
            meta["created_at"] = data.get("created_at")
            meta["last_commit"] = data.get("pushed_at")
            lic = data.get("license")
            if lic and isinstance(lic, dict):
                meta["license"] = lic.get("spdx_id")
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        pass
    return meta


def compute_metadata_score(meta: dict) -> dict:
    """Compute SpiderRating metadata sub-scores from GitHub metadata."""
    # Provenance (0-10)
    provenance = 5.0
    if meta.get("license") and meta["license"] not in ("NOASSERTION", None):
        provenance += 2.0
    if meta.get("description") and len(meta["description"]) > 20:
        provenance += 1.5
    if meta.get("stars", 0) > 100:
        provenance += 1.0
    provenance = min(10.0, provenance)

    # Maintenance (0-10)
    maintenance = 5.0
    if meta.get("last_commit"):
        try:
            last = datetime.fromisoformat(meta["last_commit"].replace("Z", "+00:00"))
            days_ago = (datetime.now(tz=UTC) - last).days
            if days_ago < 30:
                maintenance = 9.0
            elif days_ago < 90:
                maintenance = 7.5
            elif days_ago < 180:
                maintenance = 6.0
            elif days_ago < 365:
                maintenance = 4.0
            else:
                maintenance = 2.0
        except (ValueError, TypeError):
            pass

    # Popularity (0-10)
    stars = meta.get("stars", 0)
    forks = meta.get("forks", 0)
    if stars >= 5000:
        popularity = 9.5
    elif stars >= 1000:
        popularity = 8.0
    elif stars >= 500:
        popularity = 7.0
    elif stars >= 100:
        popularity = 6.0
    elif stars >= 50:
        popularity = 5.0
    elif stars >= 10:
        popularity = 3.5
    else:
        popularity = 2.0
    if forks >= 100:
        popularity = min(10.0, popularity + 1.0)
    elif forks >= 20:
        popularity = min(10.0, popularity + 0.5)

    composite = round(provenance * 0.4 + maintenance * 0.35 + popularity * 0.25, 1)
    return {
        "provenance": round(provenance, 1),
        "maintenance": round(maintenance, 1),
        "popularity": round(popularity, 1),
        "composite": round(composite, 1),
    }


def map_description_dimensions(tool_scores: list[dict]) -> dict:
    """Map TeeShield's 7 description criteria to SpiderRating's 5 dimensions.

    Mapping:
        has_action_verb + has_scenario_trigger → intent_clarity
        has_param_docs → permission_scope
        has_error_guidance → side_effects
        has_param_examples + disambiguation → capability_disclosure
        overall_score (aggregate) → operational_boundaries
    """
    if not tool_scores:
        return {
            "intent_clarity": 5.0, "permission_scope": 5.0, "side_effects": 5.0,
            "capability_disclosure": 5.0, "operational_boundaries": 5.0, "composite": 5.0,
        }

    n = len(tool_scores)
    verb_count = sum(1 for t in tool_scores if t.get("has_action_verb"))
    scenario_count = sum(1 for t in tool_scores if t.get("has_scenario_trigger"))
    param_docs_count = sum(1 for t in tool_scores if t.get("has_param_docs"))
    error_count = sum(1 for t in tool_scores if t.get("has_error_guidance"))
    examples_count = sum(1 for t in tool_scores if t.get("has_param_examples"))
    avg_disambig = sum(t.get("disambiguation_score", 0.5) for t in tool_scores) / n
    avg_overall = sum(t.get("overall_score", 5.0) for t in tool_scores) / n

    intent_clarity = ((verb_count / n) * 0.4 + (scenario_count / n) * 0.6) * 10.0
    permission_scope = (param_docs_count / n) * 10.0
    side_effects = min(10.0, (error_count / n) * 10.0 + 2.0)
    capability_disclosure = ((examples_count / n) * 0.6 + avg_disambig * 0.4) * 10.0
    operational_boundaries = avg_overall

    composite = round(
        intent_clarity * 0.25 + permission_scope * 0.20 + side_effects * 0.20
        + capability_disclosure * 0.15 + operational_boundaries * 0.20, 1,
    )
    return {
        "intent_clarity": round(intent_clarity, 1),
        "permission_scope": round(permission_scope, 1),
        "side_effects": round(side_effects, 1),
        "capability_disclosure": round(capability_disclosure, 1),
        "operational_boundaries": round(operational_boundaries, 1),
        "composite": round(composite, 1),
    }


def map_security(
    security_score: float,
    security_issues: list[dict],
    architecture_score: float,
) -> dict:
    """Map TeeShield security + architecture to SpiderRating security format."""
    critical = sum(1 for i in security_issues if i.get("severity") == "critical")
    high = sum(1 for i in security_issues if i.get("severity") == "high")
    medium = sum(1 for i in security_issues if i.get("severity") == "medium")
    low = sum(1 for i in security_issues if i.get("severity") == "low")

    arch_bonus = min(3.0, architecture_score * 0.3)
    # Adjust for SpiderRating's softer low penalty (0.25 vs TeeShield's 0.5)
    adjusted = min(10.0, security_score + low * 0.25)

    mapped_issues = [
        {
            "code": i.get("category", "unknown"),
            "severity": i.get("severity", "medium"),
            "file": i.get("file", ""),
            "line": i.get("line"),
            "message": i.get("description", ""),
        }
        for i in security_issues
    ]
    return {
        "score": round(adjusted, 1),
        "architecture_bonus": round(arch_bonus, 1),
        "critical_count": critical, "high_count": high,
        "medium_count": medium, "low_count": low,
        "issues": mapped_issues,
    }


def compute_grade(overall: float, hard_constraint: str | None) -> str:
    """Compute SpiderRating grade (F/D/C/B/A)."""
    if hard_constraint and hard_constraint in (
        "critical_vulnerability", "no_tools", "known_malicious",
    ):
        return "F"
    if hard_constraint == "license_banned":
        return "D" if overall >= 4.0 else "F"
    if overall >= 8.5:
        return "A"
    if overall >= 7.0:
        return "B"
    if overall >= 5.0:
        return "C"
    if overall >= 3.0:
        return "D"
    return "F"


def detect_hard_constraints(
    security_issues: list[dict],
    tool_count: int,
    license_info: str | None,
) -> str | None:
    """Detect SpiderRating hard constraints."""
    if any(i.get("severity") == "critical" for i in security_issues):
        return "critical_vulnerability"
    if tool_count == 0:
        return "no_tools"
    banned = {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "BSL-1.1"}
    if license_info and license_info.upper() in {lic.upper() for lic in banned}:
        return "license_banned"
    return None


def score_skill_description(content: str) -> dict:
    """Score a skill's SKILL.md content on SpiderRating's 5 description dimensions.

    Skills don't have tool descriptions like MCP servers, so we analyze
    the SKILL.md content directly for clarity, scope, and safety signals.
    """
    import re

    lines = content.strip().splitlines()
    lower = content.lower()
    length = len(content)

    # intent_clarity: Does it clearly state what the skill does?
    # Look for: title line, action verbs in first paragraph, clear purpose statement
    has_title = bool(lines and lines[0].startswith("#"))
    has_purpose = bool(re.search(
        r"(this skill|this tool|purpose|designed to|helps? you|allows? you|enables?)",
        lower,
    ))
    first_para_verbs = bool(re.search(
        r"\b(create|analyze|search|generate|debug|test|build|deploy|monitor|scan|fix)\b",
        "\n".join(lines[:10]).lower(),
    ))
    intent_clarity = (
        (3.0 if has_title else 0.0)
        + (4.0 if has_purpose else 0.0)
        + (3.0 if first_para_verbs else 0.0)
    )

    # permission_scope: Does it document what it accesses / needs?
    has_requires = bool(re.search(r"requires?:?|dependencies|prerequisites|requirements?:?", lower))
    has_bins = bool(re.search(r"bins:\s*\[", content))
    has_file_access = bool(re.search(
        r"(read|write|access|modify)\s+(files?|directories|folders?)",
        lower,
    ))
    permission_scope = (
        (4.0 if has_requires else 0.0)
        + (3.0 if has_bins else 0.0)
        + (3.0 if has_file_access else 0.0)
    )

    # side_effects: Does it document what changes it makes?
    has_side_effects = bool(re.search(
        r"(side.?effects?|modif|changes?|creates?\s+files?|writes?\s+to|deletes?|removes?|warning|caution)",
        lower,
    ))
    has_undo = bool(re.search(r"(undo|revert|rollback|backup)", lower))
    side_effects = (
        (5.0 if has_side_effects else 2.0)  # Base 2.0: no side effects may mean none
        + (3.0 if has_undo else 0.0)
        + (2.0 if length > 200 else 0.0)  # Longer docs tend to cover more
    )
    side_effects = min(10.0, side_effects)

    # capability_disclosure: Does it show what it can/can't do?
    has_examples = bool(re.search(r"(example|e\.g\.|usage|demo|sample)", lower))
    has_limitations = bool(re.search(r"(limit|cannot|doesn.t|won.t|not supported|caveat)", lower))
    has_steps = bool(re.search(r"(step\s+\d|1\.|first,|then,)", lower))
    capability_disclosure = (
        (4.0 if has_examples else 0.0)
        + (3.0 if has_limitations else 0.0)
        + (3.0 if has_steps else 0.0)
    )

    # operational_boundaries: Does it define scope and constraints?
    has_scope = bool(re.search(
        r"(scope|boundary|boundaries|only\s+works|limited\s+to|specific\s+to)",
        lower,
    ))
    has_when_to_use = bool(re.search(
        r"(when\s+to\s+use|use\s+this\s+when|best\s+for|ideal\s+for)",
        lower,
    ))
    length_score = min(3.0, length / 500.0)  # Up to 3 points for adequate length
    operational_boundaries = (
        (4.0 if has_scope else 0.0)
        + (3.0 if has_when_to_use else 0.0)
        + length_score
    )

    composite = round(
        intent_clarity * 0.25 + permission_scope * 0.20 + side_effects * 0.20
        + capability_disclosure * 0.15 + operational_boundaries * 0.20, 1,
    )
    return {
        "intent_clarity": round(intent_clarity, 1),
        "permission_scope": round(permission_scope, 1),
        "side_effects": round(side_effects, 1),
        "capability_disclosure": round(capability_disclosure, 1),
        "operational_boundaries": round(operational_boundaries, 1),
        "composite": round(composite, 1),
    }


def skill_security_from_findings(
    findings: list[dict],
    skill_findings: list[dict],
) -> dict:
    """Compute SpiderRating security score from agent-check findings.

    Scoring: start at 10.0, deduct per finding severity.
    Penalties (SpiderRating standard):
        - critical / MALICIOUS: -3.0
        - high: -2.0
        - medium / SUSPICIOUS: -1.0
        - low: -0.25
    """
    score = 10.0
    critical = high = medium = low = 0
    issues = []

    # Config findings (Finding objects)
    for f in findings:
        sev = f.get("severity", "medium")
        if sev == "critical":
            score -= 3.0
            critical += 1
        elif sev == "high":
            score -= 2.0
            high += 1
        elif sev == "medium":
            score -= 1.0
            medium += 1
        elif sev == "low":
            score -= 0.25
            low += 1
        issues.append({
            "code": f.get("check_id", "unknown"),
            "severity": sev,
            "file": "",
            "line": None,
            "message": f.get("description", f.get("title", "")),
        })

    # Skill findings (SkillFinding objects)
    for sf in skill_findings:
        verdict = sf.get("verdict", "unknown")
        if verdict == "malicious":
            score -= 3.0
            critical += 1
            sev = "critical"
        elif verdict == "suspicious":
            score -= 1.0
            medium += 1
            sev = "medium"
        elif verdict == "tampered":
            score -= 2.0
            high += 1
            sev = "high"
        else:
            continue

        for issue_text in sf.get("issues", []):
            issues.append({
                "code": sf.get("skill_name", "unknown"),
                "severity": sev,
                "file": sf.get("skill_path", ""),
                "line": None,
                "message": issue_text,
            })

    return {
        "score": round(max(0.0, min(10.0, score)), 1),
        "architecture_bonus": 0.0,
        "critical_count": critical,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
        "issues": issues,
    }


def convert_skill(
    scan_result: dict,
    skill_name: str,
    owner: str,
    repo: str,
    skill_content: str = "",
    github_meta: dict | None = None,
) -> dict:
    """Convert agent-check ScanResult to SpiderRating format for a skill.

    Args:
        scan_result: Serialized ScanResult from agent-check (dataclasses.asdict output).
        skill_name: Display name for the skill.
        owner: GitHub owner.
        repo: GitHub repo name.
        skill_content: Raw SKILL.md content for description scoring.
        github_meta: Optional pre-fetched GitHub metadata.
    """
    start = time.time()

    if github_meta is None:
        github_meta = fetch_github_metadata(owner, repo)

    # Description scoring from SKILL.md content
    description = score_skill_description(skill_content) if skill_content else {
        "intent_clarity": 5.0, "permission_scope": 5.0, "side_effects": 5.0,
        "capability_disclosure": 5.0, "operational_boundaries": 5.0, "composite": 5.0,
    }

    # Security scoring from findings
    security = skill_security_from_findings(
        scan_result.get("findings", []),
        scan_result.get("skill_findings", []),
    )

    # Metadata from GitHub
    metadata = compute_metadata_score(github_meta)

    # SpiderRating weights: 35/35/30
    overall = round(
        description["composite"] * 0.35
        + security["score"] * 0.35
        + metadata["composite"] * 0.30, 1,
    )

    # Hard constraints for skills
    hard_constraint = None
    has_malicious = any(
        sf.get("verdict") == "malicious" for sf in scan_result.get("skill_findings", [])
    )
    has_critical = any(
        f.get("severity") == "critical" for f in scan_result.get("findings", [])
    )
    if has_malicious:
        hard_constraint = "known_malicious"
    elif has_critical:
        hard_constraint = "critical_vulnerability"

    grade = compute_grade(overall, hard_constraint)

    if grade == "F" and hard_constraint:
        overall = min(overall, 2.0)

    duration_ms = int((time.time() - start) * 1000)

    return {
        "server": {
            "slug": f"{owner}/{repo}",
            "owner": owner,
            "repo": repo,
            "name": skill_name or repo.replace("-", " ").replace("_", " ").title(),
            "description": github_meta.get("description", ""),
            "github_url": f"https://github.com/{owner}/{repo}",
            "npm_package": None,
            "pypi_package": None,
            "license": github_meta.get("license"),
            "version": None,
            "category": "skill",
            "transport": "skill",
            "stars": github_meta.get("stars", 0),
            "forks": github_meta.get("forks", 0),
            "last_commit": github_meta.get("last_commit"),
            "created_at": github_meta.get("created_at"),
        },
        "score": {
            "overall": overall,
            "grade": grade,
            "description": description,
            "security": security,
            "metadata": metadata,
            "hard_constraint_applied": hard_constraint,
        },
        "tool_count": 0,
        "scanned_at": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
        "scan_duration_ms": duration_ms,
    }


def parse_owner_repo(target: str) -> tuple[str, str]:
    """Extract owner/repo from various input formats."""
    target = target.rstrip("/").removesuffix(".git")
    if "github.com" in target:
        parts = target.split("github.com/")[-1].split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
    if "/" in target:
        parts = target.split("/")
        return parts[0], parts[1]
    raise ValueError(f"Cannot parse owner/repo from: {target}")


def convert(teeshield_report: dict, owner: str, repo: str, github_meta: dict | None = None) -> dict:
    """Convert a TeeShield ScanReport dict to SpiderRating ServerRating format."""
    start = time.time()

    if github_meta is None:
        github_meta = fetch_github_metadata(owner, repo)

    tool_scores_raw = teeshield_report.get("tool_scores", [])
    description = map_description_dimensions(tool_scores_raw)
    security = map_security(
        teeshield_report.get("security_score", 5.0),
        teeshield_report.get("security_issues", []),
        teeshield_report.get("architecture_score", 5.0),
    )
    metadata = compute_metadata_score(github_meta)

    # SpiderRating weights: 35/35/30
    overall = round(
        description["composite"] * 0.35
        + security["score"] * 0.35
        + metadata["composite"] * 0.30, 1,
    )

    tool_count = teeshield_report.get("tool_count", 0)
    hard_constraint = detect_hard_constraints(
        teeshield_report.get("security_issues", []), tool_count, teeshield_report.get("license"),
    )
    grade = compute_grade(overall, hard_constraint)

    if grade == "F" and hard_constraint:
        overall = min(overall, 2.0)
    elif grade == "D" and hard_constraint == "license_banned":
        overall = min(overall, 4.9)

    duration_ms = int((time.time() - start) * 1000)

    return {
        "server": {
            "slug": f"{owner}/{repo}",
            "owner": owner,
            "repo": repo,
            "name": repo.replace("-", " ").replace("_", " ").title(),
            "description": github_meta.get("description", ""),
            "github_url": f"https://github.com/{owner}/{repo}",
            "npm_package": github_meta.get("npm_package"),
            "pypi_package": github_meta.get("pypi_package"),
            "license": github_meta.get("license") or teeshield_report.get("license"),
            "version": None,
            "category": "utility",
            "transport": "stdio",
            "stars": github_meta.get("stars", 0),
            "forks": github_meta.get("forks", 0),
            "last_commit": github_meta.get("last_commit"),
            "created_at": github_meta.get("created_at"),
        },
        "score": {
            "overall": overall,
            "grade": grade,
            "description": description,
            "security": security,
            "metadata": metadata,
            "hard_constraint_applied": hard_constraint,
        },
        "tool_count": tool_count,
        "scanned_at": datetime.now(tz=UTC).isoformat().replace("+00:00", "Z"),
        "scan_duration_ms": duration_ms,
    }
