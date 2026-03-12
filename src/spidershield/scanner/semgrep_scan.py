"""Semgrep-based AST-aware security scanner.

Optional layer that replaces regex-based detection for covered categories
when Semgrep is installed.  Gracefully degrades to no-op if Semgrep is
absent so the regex fallback in security_scan.py takes over.

Usage from security_scan.py:
    from .semgrep_scan import run_semgrep, SEMGREP_COVERED_CATEGORIES

    if SEMGREP_AVAILABLE:
        sg_issues = run_semgrep(path)
    ...
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from spidershield.models import SecurityIssue

logger = logging.getLogger(__name__)

# Rules live alongside this file
_RULES_DIR = Path(__file__).parent / "rules"

# Semgrep binary presence (checked once at import time)
SEMGREP_AVAILABLE: bool = shutil.which("semgrep") is not None

# Categories fully replaced by Semgrep (regex disabled for these when Semgrep runs)
SEMGREP_COVERED_CATEGORIES: frozenset[str] = frozenset(
    {
        "dangerous_eval",
        "command_injection",
        "sql_injection",
        "ts_unsafe_eval",
        "child_process_injection",
        "ts_sql_injection",
    }
)

# Mapping from Semgrep rule metadata.category → our SecurityIssue fields
_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
}

# Semgrep severity → our severity (fallback when metadata.severity_level absent)
_SEMGREP_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": "medium",
}

# Brief fix hints per rule id (shown in SecurityIssue.fix_suggestion)
_FIX_HINTS: dict[str, str] = {
    "mcp-dangerous-eval": "Use ast.literal_eval for data parsing, or avoid eval entirely",
    "mcp-dangerous-exec": "Avoid exec(); refactor to use explicit function dispatch",
    "mcp-os-system-variable": "Use subprocess with shell=False and explicit argument lists",
    "mcp-os-popen-variable": "Use subprocess.run with shell=False and explicit argument lists",
    "mcp-subprocess-shell-true-variable": "Use shell=False with an explicit list of arguments",
    "mcp-subprocess-shell-true-fstring": "Never use f-strings with shell=True; use shell=False + arg list",
    "mcp-sql-execute-fstring": "Use parameterized queries with placeholder syntax (?, %s, :name)",
    "mcp-sql-execute-fstring-single": "Use parameterized queries with placeholder syntax (?, %s, :name)",
    "mcp-sql-execute-concat": "Use parameterized queries; never concatenate user input into SQL",
    "mcp-sql-execute-format": "Pass args as second argument to execute() instead of %-format",
    "mcp-ts-new-function": "Avoid new Function(); use structured data parsing instead",
    "mcp-ts-eval-variable": "Avoid eval; use structured data parsing instead",
    "mcp-ts-vm-run": "Avoid vm.runIn*Context(); use structured evaluation instead",
    "mcp-ts-child-process-exec-template": "Use child_process.execFile or spawn with explicit argument arrays",
    "mcp-ts-child-process-exec-variable": "Use child_process.execFile or spawn with explicit argument arrays",
    "mcp-ts-exec-sync-template": "Use spawnSync with explicit argument arrays instead of execSync",
    "mcp-ts-exec-sync-variable": "Use spawnSync with explicit argument arrays instead of execSync",
    "mcp-ts-query-template-literal": "Use parameterized queries ($1, $2) instead of template literal interpolation",
    "mcp-ts-execute-template-literal": "Use parameterized queries ($1, $2) instead of template literal interpolation",
}


def _parse_semgrep_output(raw: str, repo_root: Path) -> list[SecurityIssue]:
    """Parse Semgrep JSON output into SecurityIssue objects."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Semgrep produced invalid JSON output")
        return []

    issues: list[SecurityIssue] = []
    seen: set[tuple[str, int, str]] = set()

    for result in data.get("results", []):
        rule_id: str = result.get("check_id", "")
        # rule IDs are namespaced (e.g. "python.dangerous_eval.mcp-dangerous-eval")
        # extract the last component
        short_id = rule_id.split(".")[-1] if "." in rule_id else rule_id

        meta: dict = result.get("extra", {}).get("metadata", {})
        category: str = meta.get("category", "")
        if not category:
            # Derive category from rule id prefix (mcp-ts-* → ts_*)
            category = _rule_id_to_category(short_id)
        if not category:
            continue

        severity_raw: str = meta.get("severity_level", "")
        if not severity_raw:
            # Fall back to Semgrep severity field
            sg_sev = result.get("extra", {}).get("severity", "WARNING")
            severity_raw = _SEMGREP_SEVERITY_MAP.get(sg_sev, "medium")
        severity = _SEVERITY_MAP.get(severity_raw, "medium")

        path_str: str = result.get("path", "")
        try:
            rel_path = str(Path(path_str).relative_to(repo_root))
        except ValueError:
            rel_path = path_str

        line: int = result.get("start", {}).get("line", 0)
        message: str = result.get("extra", {}).get("message", "")
        fix: str = _FIX_HINTS.get(short_id, meta.get("fix", ""))

        key = (rel_path, line, category)
        if key in seen:
            continue
        seen.add(key)

        issues.append(
            SecurityIssue(
                severity=severity,
                category=category,
                file=rel_path,
                line=line,
                description=message,
                fix_suggestion=fix,
            )
        )

    return issues


def _rule_id_to_category(rule_id: str) -> str:
    """Derive our category name from a Semgrep rule ID."""
    mapping = {
        "mcp-dangerous-eval": "dangerous_eval",
        "mcp-dangerous-exec": "dangerous_eval",
        "mcp-os-system-variable": "command_injection",
        "mcp-os-popen-variable": "command_injection",
        "mcp-subprocess-shell-true-variable": "command_injection",
        "mcp-subprocess-shell-true-fstring": "command_injection",
        "mcp-sql-execute-fstring": "sql_injection",
        "mcp-sql-execute-fstring-single": "sql_injection",
        "mcp-sql-execute-concat": "sql_injection",
        "mcp-sql-execute-format": "sql_injection",
        "mcp-ts-new-function": "ts_unsafe_eval",
        "mcp-ts-eval-variable": "ts_unsafe_eval",
        "mcp-ts-vm-run": "ts_unsafe_eval",
        "mcp-ts-child-process-exec-template": "child_process_injection",
        "mcp-ts-child-process-exec-variable": "child_process_injection",
        "mcp-ts-exec-sync-template": "child_process_injection",
        "mcp-ts-exec-sync-variable": "child_process_injection",
        "mcp-ts-query-template-literal": "ts_sql_injection",
        "mcp-ts-execute-template-literal": "ts_sql_injection",
    }
    return mapping.get(rule_id, "")


def run_semgrep(path: Path, timeout: int = 60) -> list[SecurityIssue]:
    """Run Semgrep on *path* using our bundled rules.

    Returns list of SecurityIssue objects (empty if Semgrep fails/absent).
    Only categories in SEMGREP_COVERED_CATEGORIES are returned.
    """
    if not SEMGREP_AVAILABLE:
        return []

    if not _RULES_DIR.exists():
        logger.warning("Semgrep rules directory not found: %s", _RULES_DIR)
        return []

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--json",
                "--quiet",
                "--no-git-ignore",
                "--config", str(_RULES_DIR / "python"),
                "--config", str(_RULES_DIR / "typescript"),
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("Semgrep scan failed: %s", exc)
        return []

    if result.returncode not in (0, 1):
        # 0 = no findings, 1 = findings found; anything else is an error
        logger.warning("Semgrep exited %d: %s", result.returncode, result.stderr[:200])
        return []

    return _parse_semgrep_output(result.stdout, path)
