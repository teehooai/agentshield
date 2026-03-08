"""Static security scanning for MCP servers."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agentshield.models import SecurityIssue

# Patterns that indicate security risks
DANGEROUS_PATTERNS = {
    "path_traversal": {
        "patterns": [
            r"os\.path\.join\([^)]*\.\.",
            r"open\([^)]*\+",
            r'Path\([^)]*\+',
            r"\.\.\/",
            r"\.\.[/\\]",
        ],
        "severity": "high",
        "description": "Potential path traversal — user input may escape intended directory",
        "fix": "Validate and resolve paths against an allowed base directory",
    },
    "command_injection": {
        "patterns": [
            r"os\.system\(",
            r"os\.popen\(",
            r"subprocess\.(?:call|run|Popen)\([^)]*shell\s*=\s*True",
            r"exec\(",
            r"eval\(",
        ],
        "severity": "critical",
        "description": "Potential command injection — user input may be executed as shell command",
        "fix": "Use subprocess with shell=False and explicit argument lists",
    },
    "sql_injection": {
        "patterns": [
            r'f"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)',
            r"f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)",
            r'\.execute\(\s*f"',
            r"\.execute\(\s*f'",
            r'\.execute\([^)]*%\s',
            r'\.execute\([^)]*\+',
        ],
        "severity": "critical",
        "description": "Potential SQL injection — query built with string interpolation",
        "fix": "Use parameterized queries with placeholder syntax",
    },
    "credential_exposure": {
        "patterns": [
            r'(?:api_key|token|secret|password)\s*=\s*["\'][^"\']{8,}',
            r"os\.environ\.get\(['\"](?:API_KEY|TOKEN|SECRET|PASSWORD)",
            r"os\.getenv\(['\"](?:API_KEY|TOKEN|SECRET|PASSWORD)",
        ],
        "severity": "medium",
        "description": "Credentials handled via plain environment variables",
        "fix": "Use a secret manager or Astrix MCP Secret Wrapper",
    },
    "ssrf": {
        "patterns": [
            r"requests\.(?:get|post|put|delete)\([^)]*(?:url|endpoint)",
            r"httpx\.(?:get|post|put|delete)\([^)]*(?:url|endpoint)",
            r"fetch\([^)]*(?:url|endpoint)",
        ],
        "severity": "medium",
        "description": "Potential SSRF — unrestricted network requests with user-controlled URLs",
        "fix": "Validate URLs against an allowlist of permitted domains",
    },
    "no_input_validation": {
        "patterns": [
            r"def\s+\w+\(.*:\s*str\).*:\s*$",
        ],
        "severity": "low",
        "description": "Function accepts raw string input without validation",
        "fix": "Add input validation (length limits, allowlists, sanitization)",
    },
}


def scan_security(path: Path) -> tuple[float, list[SecurityIssue]]:
    """Scan for security issues in Python and TypeScript files.

    Returns (security_score, list_of_issues).
    """
    issues: list[SecurityIssue] = []

    source_files = list(path.rglob("*.py")) + list(path.rglob("*.ts")) + list(path.rglob("*.js"))
    # Exclude node_modules and test files from security scanning
    source_files = [
        f for f in source_files
        if "node_modules" not in str(f) and "__pycache__" not in str(f)
    ]

    for source_file in source_files:
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        rel_path = str(source_file.relative_to(path))

        for category, config in DANGEROUS_PATTERNS.items():
            for pattern in config["patterns"]:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    line_num = content[:match.start()].count("\n") + 1
                    issues.append(
                        SecurityIssue(
                            severity=config["severity"],
                            category=category,
                            file=rel_path,
                            line=line_num,
                            description=config["description"],
                            fix_suggestion=config["fix"],
                        )
                    )

    # Calculate score
    if not source_files:
        return 5.0, issues

    severity_weights = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5, "info": 0.1}
    total_penalty = sum(severity_weights.get(i.severity, 0.5) for i in issues)
    score = max(0.0, 10.0 - total_penalty)

    return round(score, 1), issues
