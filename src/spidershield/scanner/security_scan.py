"""Static security scanning for MCP servers.

Detection uses a hybrid strategy:
- If Semgrep is installed: AST-aware Semgrep rules handle the highest-FP
  categories (dangerous_eval, command_injection, sql_injection and their TS
  equivalents).  Regex is disabled for those categories to avoid duplicates.
- If Semgrep is absent: pure regex for all categories (existing behaviour).
"""

from __future__ import annotations

import re
from pathlib import Path

from spidershield.models import SecurityIssue
from .semgrep_scan import (
    SEMGREP_AVAILABLE,
    SEMGREP_COVERED_CATEGORIES,
    run_semgrep,
)

# Patterns that indicate security risks
DANGEROUS_PATTERNS = {
    "path_traversal": {
        "patterns": [
            r"os\.path\.join\([^)]*\.\.",
            r"open\([^)]*\+",
            r'Path\([^)]*\+',
        ],
        "severity": "high",
        "description": "Potential path traversal -- user input may escape intended directory",
        "fix": "Validate and resolve paths against an allowed base directory",
    },
    "command_injection": {
        "patterns": [
            # os.system() with variable (not just string literal)
            r"os\.system\(\s*(?![\"'])",
            r"os\.system\(\s*f[\"']",
            r"os\.popen\(\s*(?![\"'])",
            r"os\.popen\(\s*f[\"']",
            # shell=True with variable/f-string command (not hardcoded)
            r"subprocess\.(?:call|run|Popen)\(\s*f[\"'].*shell\s*=\s*True",
            r"subprocess\.(?:call|run|Popen)\(\s*\w+.*shell\s*=\s*True",
        ],
        "severity": "critical",
        "description": "Potential command injection -- user input may be executed as shell command",
        "fix": "Use subprocess with shell=False and explicit argument lists",
    },
    "dangerous_eval": {
        "patterns": [
            # exec/eval with variable input (not string literals)
            # Word boundary (?<!\w) prevents matching run_eval(), etc.
            # Negative lookbehind (?<!\.) excludes method calls like RegExp.exec(),
            # cursor.execute(), db.execute() — only flags bare exec()/eval() calls.
            r"(?<!\w)(?<!\.)exec\(\s*(?![\"\'])",
            r"(?<!\w)(?<!\.)eval\(\s*(?![\"\'])",
        ],
        "severity": "critical",
        "description": "Dynamic code execution -- user input may be executed as code",
        "fix": "Use ast.literal_eval for data parsing, or avoid eval/exec entirely",
    },
    "sql_injection": {
        "patterns": [
            # f-string with full SQL statement pattern (keyword + SQL target)
            (
                r'f"[^"]*(?:SELECT\s+[\w*].*?FROM'
                r"|INSERT\s+INTO"
                r"|UPDATE\s+\w+\s+SET"
                r"|DELETE\s+FROM"
                r"|DROP\s+(?:TABLE|INDEX|VIEW|DATABASE)"
                r"|CREATE\s+(?:TABLE|INDEX|VIEW|DATABASE))"
            ),
            (
                r"f'[^']*(?:SELECT\s+[\w*].*?FROM"
                r"|INSERT\s+INTO"
                r"|UPDATE\s+\w+\s+SET"
                r"|DELETE\s+FROM"
                r"|DROP\s+(?:TABLE|INDEX|VIEW|DATABASE)"
                r"|CREATE\s+(?:TABLE|INDEX|VIEW|DATABASE))"
            ),
            r'\.execute\(\s*f"',
            r"\.execute\(\s*f'",
            r'\.execute\([^)]*%\s',
            r'\.execute\([^)]*\+',
        ],
        "severity": "critical",
        "description": "Potential SQL injection -- query built with string interpolation",
        "fix": "Use parameterized queries with placeholder syntax",
    },
    "hardcoded_credential": {
        "patterns": [
            # Only flag hardcoded secrets outside docstrings/comments.
            # Exclude obvious placeholder/example values (common in README,
            # .env.example, and docstrings): values containing "example",
            # "placeholder", "your_", "changeme", "xxxx", "<", or all-same char.
            r'^[^#\n]*(?:api_key|token|secret|password)\s*=\s*["\'](?!.*(?:example|placeholder|your_|changeme|xxxxxx|<[A-Z_]+>))[^"\']{8,}',
        ],
        "severity": "high",
        "description": "Hardcoded credential -- secret value embedded in source code",
        "fix": "Move secrets to environment variables or a secret manager",
    },
    "unsafe_deserialization": {
        "patterns": [
            r"pickle\.loads?\(",
            r"yaml\.load\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)",
            r"yaml\.unsafe_load\(",
            r"marshal\.loads?\(",
            r"shelve\.open\(",
        ],
        "severity": "critical",
        "description": "Unsafe deserialization -- untrusted data may execute arbitrary code",
        "fix": "Use yaml.safe_load, json.loads, or other safe deserialization methods",
    },
    "ssrf": {
        "patterns": [
            r"requests\.(?:get|post|put|delete)\([^)]*(?:url|endpoint)",
            r"httpx\.(?:get|post|put|delete)\([^)]*(?:url|endpoint)",
            # fetch() is too broad — it's a standard API in JS/TS. Only flag Python
            # urllib/requests patterns. JS/TS fetch() is covered by manual review
            # since agent frameworks legitimately fetch user-provided URLs.
        ],
        "severity": "medium",
        "description": "Potential SSRF -- unrestricted network requests with user-controlled URLs",
        "fix": "Validate URLs against an allowlist of permitted domains",
    },
    "no_input_validation": {
        "patterns": [
            # Only flag MCP tool handler functions that take raw string params
            # (functions decorated with @tool, @server.tool, or named call_tool/handle)
            r"@(?:mcp|server|app)\.tool\b.*\n\s*(?:async\s+)?def\s+\w+\(.*:\s*str[,\)]",
            r"@tool\b.*\n\s*(?:async\s+)?def\s+\w+\(.*:\s*str[,\)]",
        ],
        "severity": "low",
        "description": "MCP tool handler accepts raw string input without validation",
        "fix": "Add input validation (length limits, allowlists, sanitization)",
    },
}

# TypeScript / JavaScript specific patterns (checked only for .ts/.js files)
TS_DANGEROUS_PATTERNS = {
    "prototype_pollution": {
        "patterns": [
            # Object.assign with user input, deep merge without protection
            r"Object\.assign\(\s*\{\s*\}\s*,",
            # Only flag dynamic property assignment from raw user input
            # (not this.map[id]=value which is controlled)
            r"(?<!\w)\w+\[(?:input|params|args|body|query|req)\[\w+\]\]\s*=",
            r"(?:lodash|_)\.merge\(",
        ],
        "severity": "high",
        "description": (
            "Potential prototype pollution -- user-controlled keys"
            " may modify Object.prototype"
        ),
        "fix": (
            "Use Map instead of plain objects, or validate keys"
            " against a denylist (__proto__, constructor, prototype)"
        ),
    },
    "child_process_injection": {
        "patterns": [
            # Only flag when command includes variable/template interpolation
            r"child_process\.exec\(\s*(?![\"'])",
            r"child_process\.exec\(\s*`[^`]*\$\{",
            r"child_process\.execSync\(\s*(?![\"'])",
            r"child_process\.execSync\(\s*`[^`]*\$\{",
            r"(?<!\w)execSync\(\s*(?![\"'])",
            r"(?<!\w)execSync\(\s*`[^`]*\$\{",
            r"(?<!\w)exec\(\s*`[^`]*\$\{",
        ],
        "severity": "critical",
        "description": (
            "Potential command injection via child_process"
            " -- user input may be executed as shell command"
        ),
        "fix": "Use child_process.execFile or spawn with explicit argument arrays",
    },
    "ts_unsafe_eval": {
        "patterns": [
            r"new\s+Function\(",
            # eval( — exclude method calls like RegExp.exec(), cursor.execute(),
            # and exclude word boundaries (e.g. retrieval, interval)
            r"(?<!\w)(?<!\.)eval\(\s*(?!['\"])",
            r"vm\.runInNewContext\(",
            r"vm\.runInThisContext\(",
        ],
        "severity": "critical",
        "description": (
            "Dynamic code execution via eval/Function/vm"
            " -- user input may run arbitrary code"
        ),
        "fix": "Avoid eval and new Function; use structured data parsing instead",
    },
    "ts_sql_injection": {
        "patterns": [
            r"\.query\(\s*`[^`]*\$\{",   # template literal with interpolation in query()
            r"\.execute\(\s*`[^`]*\$\{",  # template literal with interpolation in execute()
        ],
        "severity": "critical",
        "description": "Potential SQL injection -- query built with template literal interpolation",
        "fix": "Use parameterized queries ($1, $2) instead of template literal interpolation",
    },
    "ts_path_traversal": {
        "patterns": [
            # Only flag path.join with HTTP request inputs (req.params, req.query,
            # req.body) — not generic function params. which are usually safe internal
            # parameters in TS codebases. Also exclude test helper files.
            r"path\.join\([^)]*(?:req\.(?:params|query|body|path)|ctx\.(?:params|query))",
            r"fs\.(?:readFile|writeFile|unlink|rmdir|mkdir)(?:Sync)?\([^)]*\+",
        ],
        "severity": "high",
        "description": "Potential path traversal -- user input used in file system operations",
        "fix": (
            "Validate and resolve paths against an allowed base"
            " directory using path.resolve + startsWith check"
        ),
    },
}


def _scope_to_mcp_dir(root: Path, files: list[Path]) -> list[Path]:
    """Limit scanning scope to MCP-related directories in monorepos.

    If the repo has a clear MCP subdirectory (e.g. packages/mcp-server/,
    src/mcp/, server/), prefer files from that subtree. This prevents
    scanning unrelated SDKs, frameworks, or platform code that happen to
    live in the same repo.
    """
    if len(files) <= 50:
        return files  # Small repo, no need to scope

    # Look for MCP-indicator directories
    mcp_keywords = {"mcp", "server", "tool", "plugin", "agent-toolkit"}
    mcp_dirs: list[Path] = []

    for f in files:
        rel_parts = f.relative_to(root).parts
        for part in rel_parts[:-1]:  # skip filename
            if any(kw in part.lower() for kw in mcp_keywords):
                # Get the directory up to and including this part
                idx = rel_parts.index(part)
                mcp_dir = root / Path(*rel_parts[: idx + 1])
                if mcp_dir not in mcp_dirs:
                    mcp_dirs.append(mcp_dir)

    if not mcp_dirs:
        return files  # No MCP subdirectory detected

    # Filter to files under MCP directories
    scoped = [
        f for f in files
        if any(_is_under(f, d) for d in mcp_dirs)
    ]

    # Only apply scoping if it meaningfully reduces the set
    # (if >80% of files would remain, scoping isn't useful)
    if len(scoped) >= len(files) * 0.8 or len(scoped) == 0:
        return files

    return scoped


def _is_under(file_path: Path, dir_path: Path) -> bool:
    """Check if file_path is under dir_path."""
    try:
        file_path.relative_to(dir_path)
        return True
    except ValueError:
        return False


def scan_security(path: Path) -> tuple[float, list[SecurityIssue]]:
    """Scan for security issues in Python and TypeScript files.

    Returns (security_score, list_of_issues).

    When Semgrep is installed, AST-aware rules replace regex for the highest-FP
    categories so duplicate findings are not emitted.
    """
    issues: list[SecurityIssue] = []

    # --- Semgrep pass (AST-aware, higher precision) ---
    semgrep_issues: list[SecurityIssue] = []
    if SEMGREP_AVAILABLE:
        semgrep_issues = run_semgrep(path)
        issues.extend(semgrep_issues)

    source_files = list(path.rglob("*.py")) + list(path.rglob("*.ts")) + list(path.rglob("*.js"))
    # Exclude non-source directories from security scanning
    exclude_dirs = {
        "node_modules", "__pycache__", "__tests__", "tests", "test",
        ".git", "dist", "build", ".venv", "venv", ".tox",
        ".mypy_cache", "examples", "example",
        # S3 scope limiting: exclude benchmarks, fixtures, vendor, docs
        "benchmarks", "benchmark", "fixtures", "fixture",
        "vendor", "third_party", "third-party", "external",
        "docs", "doc", "documentation",
        "spec", "e2e", "integration_tests",
        ".next", ".nuxt", ".cache", "coverage",
        # Dev tooling: setup/migration/seed scripts are not MCP tool code
        "scripts", "migrations", "migration", "seeds", "seed",
    }
    source_files = [
        f for f in source_files
        if not any(part in exclude_dirs for part in f.parts)
        and not f.name.startswith("test_")
        and not f.name.endswith(".test.ts")
        and not f.name.endswith(".test.js")
        and not f.name.endswith(".spec.ts")
        and not f.name.endswith(".spec.js")
        and not f.name.endswith(".d.ts")  # type definitions, not source
        and not f.name.endswith(".min.js")  # minified bundles
        and not f.name.startswith("_test.")  # Go test files
        and not f.name.endswith("_test.go")  # Go test files
    ]

    # S3: Monorepo scope limiting — if we can identify the MCP-specific subdir,
    # limit scanning to only that directory to avoid false positives from
    # unrelated framework code (e.g. entire Stripe SDK, Vercel AI SDK)
    source_files = _scope_to_mcp_dir(path, source_files)

    for source_file in source_files:
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        rel_path = str(source_file.relative_to(path))
        is_ts_js = source_file.suffix in (".ts", ".js")

        # Check universal patterns (Python-oriented; skip Python-only
        # rules like dangerous_eval and sql_injection on TS/JS files
        # to avoid false positives from RegExp.exec(), cursor.execute(), etc.)
        # Also skip categories already covered by Semgrep to avoid duplicates.
        _PY_ONLY_RULES = {"dangerous_eval", "sql_injection", "unsafe_deserialization"}
        for category, config in DANGEROUS_PATTERNS.items():
            if is_ts_js and category in _PY_ONLY_RULES:
                continue
            if SEMGREP_AVAILABLE and category in SEMGREP_COVERED_CATEGORIES:
                continue  # Semgrep handles this category with higher precision
            flags = re.IGNORECASE if category != "sql_injection" else 0
            for pattern in config["patterns"]:
                for match in re.finditer(pattern, content, flags):
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

        # Check TS/JS-specific patterns (skip Semgrep-covered categories)
        if is_ts_js:
            for category, config in TS_DANGEROUS_PATTERNS.items():
                if SEMGREP_AVAILABLE and category in SEMGREP_COVERED_CATEGORIES:
                    continue  # Semgrep handles this category
                for pattern in config["patterns"]:
                    for match in re.finditer(pattern, content):
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

    severity_weights = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.25, "info": 0.1}
    total_penalty = sum(severity_weights.get(i.severity, 0.25) for i in issues)
    score = max(0.0, 10.0 - total_penalty)

    return round(score, 1), issues
