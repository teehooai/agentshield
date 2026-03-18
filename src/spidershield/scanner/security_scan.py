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
            # os.path.join with literal ".." is an unambiguous traversal indicator.
            # Broader open([^)]*\+) and Path([^)]*\+) patterns removed (P3 2026-03-17)
            # — they generated 3+ FPs per repo (constant-concat open calls).
            # open(f"...{var}...") and Path(var).read_text() are covered by the more
            # precise `unsafe_path_resolution` category instead.
            r"os\.path\.join\([^)]*\.\.",
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
            # [\s\S] crosses newlines for multi-line calls.
            # Reject matches that cross into another subprocess call.
            r"subprocess\.(?:call|run|Popen)\(\s*f[\"'](?:(?!subprocess\.).[\s\S]){0,200}shell\s*=\s*True",
            r"subprocess\.(?:call|run|Popen)\(\s*\w+(?:(?!subprocess\.).[\s\S]){0,200}shell\s*=\s*True",
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
            # Only flag when URL contains clear user-input signal (P3 2026-03-17).
            # Old patterns `requests.get([^)]*(?:url|endpoint))` caused 4+ FPs per repo
            # (any config variable named `url` or `endpoint` was flagged).
            # P1 (taint rules) will handle `requests.get(url)` where url flows from
            # MCP handler parameters — not solvable with regex alone.
            #
            # f-string interpolation in URL (strongest signal — variable in URL template)
            r"""requests\.(?:get|post|put|delete)\(\s*f["'][^"']*\{""",
            # String concat where right operand is a variable (not a string literal)
            r"""requests\.(?:get|post|put|delete)\([^"'()]*\+\s*(?!["'])[a-zA-Z_]""",
            r"""httpx\.(?:get|post|put|delete)\(\s*f["'][^"']*\{""",
            r"""httpx\.(?:get|post|put|delete)\([^"'()]*\+\s*(?!["'])[a-zA-Z_]""",
        ],
        "severity": "medium",
        "description": "Potential SSRF -- unrestricted network requests with user-controlled URLs",
        "fix": "Validate URLs against an allowlist of permitted domains",
    },
    "no_input_validation": {
        "patterns": [
            # Only flag MCP tool handler functions that take raw string params
            # (functions decorated with @tool, @server.tool, or named call_tool/handle)
            # Use [\s\S]{0,300} to match multi-line function signatures
            r"@(?:mcp|server|app)\.tool\b[\s\S]{0,300}?:\s*str\s*[,\)=]",
            r"@tool\b[\s\S]{0,300}?:\s*str\s*[,\)=]",
        ],
        "severity": "low",
        "description": "MCP tool handler accepts raw string input without validation",
        "fix": "Add input validation (length limits, allowlists, sanitization)",
    },
    "unsafe_path_resolution": {
        "patterns": [
            # Path(user_input).read_text() without prior resolve()/is_relative_to()
            # Only flag when the Path constructor wraps a variable (not a literal)
            r"Path\(\s*(?![\"\'/])\w+\s*\)\.(?:read_text|read_bytes|write_text|write_bytes|open|unlink|rmdir)\(",
            # open(f"...{var}...") without os.path.realpath / resolve
            r"open\(\s*f[\"'][^\"']*\{[^}]+\}",
        ],
        "severity": "high",
        "description": "File operation on user-controlled path without validation or sandboxing",
        "fix": "Resolve paths with Path.resolve() and verify with is_relative_to(base_dir)",
    },
    "async_shell_injection": {
        "patterns": [
            # asyncio.create_subprocess_shell with f-string or variable
            r"create_subprocess_shell\(\s*f[\"']",
            r"create_subprocess_shell\(\s*(?![\"'])\w+",
            # asyncio.subprocess via shell=True
            r"asyncio\.subprocess.*shell\s*=\s*True",
        ],
        "severity": "critical",
        "description": "Async shell command with user-controlled input -- command injection risk",
        "fix": "Use asyncio.create_subprocess_exec with explicit argument lists",
    },
    "basic_auth_in_url": {
        "patterns": [
            # http://user:password@host pattern in source code (not comments)
            r'^[^#\n]*["\']https?://[^/\s"\']*:[^/\s@"\']+@[^/\s"\']+',
        ],
        "severity": "high",
        "description": "Credentials embedded in URL -- basic auth in URL exposes secrets in logs and history",
        "fix": "Pass credentials via headers, environment variables, or a secret manager",
    },
    "timing_attack_comparison": {
        "patterns": [
            # Direct string comparison of secrets (== with password/token/secret variable)
            # Exclude comparisons to None, True, False, empty string
            r"(?:password|token|secret|api_key)\s*==\s*(?!(?:None|True|False|\"\")\b)\w",
            r"==\s*(?:password|token|secret|api_key)\b",
        ],
        "severity": "medium",
        "description": "Secret compared with == operator -- timing side-channel may leak value length",
        "fix": "Use hmac.compare_digest() or secrets.compare_digest() for constant-time comparison",
    },
}

# TypeScript / JavaScript specific patterns (checked only for .ts/.js files)
TS_DANGEROUS_PATTERNS = {
    "prototype_pollution": {
        "patterns": [
            # Object.assign to existing object (not safe shallow-copy to {})
            r"Object\.assign\(\s*(?!\{\s*\})\w+\s*,",
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
    "ts_async_injection": {
        "patterns": [
            # Bun.spawn / Deno.run with template literal
            r"Bun\.spawn\(\s*`[^`]*\$\{",
            r"Deno\.run\(\s*\{[^}]*cmd\s*:\s*`[^`]*\$\{",
            # Node child_process.spawn with shell: true + template
            r"spawn\([^)]*\{[^}]*shell\s*:\s*true",
        ],
        "severity": "critical",
        "description": "Async process spawn with user-controlled command -- injection risk",
        "fix": "Use explicit argument arrays instead of shell strings",
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


# L3 Phase 1b: safe-pattern allowlist → confidence="low"
# When any of these patterns appear in the *same file* as a finding, the
# finding is downgraded to confidence="low" because a defensive pattern is
# present. bug_hunter skips low-confidence issues, keeping noise out of the
# clone-verify loop. The finding is still recorded for audit purposes.
_SAFE_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "unsafe_deserialization": [
        re.compile(r"yaml\.load\([^,)]+,\s*Loader\s*=\s*yaml\.SafeLoader"),
        re.compile(r"yaml\.safe_load\("),
        # pickle on a local file (open/Path) is not network-sourced (P4: from FP_RULES)
        re.compile(r"pickle\.loads?\(\s*(?:open|Path)"),
        # Pattern in a security scanner's blocklist/denylist (not actual usage)
        re.compile(r"(?:BLOCKED_|DANGEROUS_|FORBIDDEN_|blacklist|blocklist).*(?:pickle|eval|exec)"),
    ],
    "command_injection": [
        re.compile(r"shlex\.quote\("),
        re.compile(r"subprocess\.\w+\(\s*\["),  # list-form subprocess (no shell=True)
        # shell=True guarded by Windows platform check (npm/nvm pattern) (P4: from FP_RULES)
        re.compile(r'platform\.system\(\)\s*==\s*["\']Windows["\']'),
        # Kernel PID is not user-controllable input (P4: from FP_RULES)
        re.compile(r"(?:process\.ppid|process\.pid|os\.getpid|os\.getppid)"),
    ],
    "sql_injection": [
        re.compile(r"\.execute\(\s*\w+\s*,\s*[\[\(]"),   # execute(q, [params])
        re.compile(r"\.execute\(\s*\w+\s*,\s*\{"),        # execute(q, {k: v})
        # ? placeholders assembled with join() — parameterized query (P4: from FP_RULES)
        # Matches: join("?") and join(["?" ...]) forms
        re.compile(r"placeholders\s*=.*join\(\s*\[?[\"']\?"),
    ],
    "timing_attack_comparison": [
        re.compile(r"hmac\.compare_digest\("),
        re.compile(r"secrets\.compare_digest\("),
    ],
    "path_traversal": [
        re.compile(r"\.resolve\(\).*is_relative_to\("),
        re.compile(r"os\.path\.realpath\("),
    ],
    "dangerous_eval": [
        re.compile(r"ast\.literal_eval\("),
        # eval on config/settings/env — not user MCP input (P4: from FP_RULES)
        re.compile(r"eval\(\s*(?:config|settings|ENV|os\.environ)"),
        # File is a security scanner/linter — eval pattern appears as a regex
        # string literal, not as executable code (e.g. r"eval\(", "eval(")
        # Catches repos like mini_claude whose scanner lists dangerous patterns.
        re.compile(r"""[rR]['"][^'"]*eval\s*\\?\("""),
        # File defines scanner rule sets (DANGEROUS_PATTERNS, FP_RULES, etc.)
        # These files describe eval patterns but don't execute them.
        re.compile(r"DANGEROUS_PATTERNS|FP_RULES|_SAFE_PATTERNS|PATTERN_LIST"),
    ],
    "hardcoded_credential": [
        re.compile(r"os\.environ\.get\("),
        re.compile(r"\bgetenv\("),
    ],
}


def _has_safe_pattern(category: str, file_content: str) -> bool:
    """Return True if *file_content* contains a defensive pattern for *category*.

    Used to downgrade regex findings to confidence="low" when a mitigation
    exists in the same file (L3 Phase 1b).
    """
    for pat in _SAFE_PATTERNS.get(category, []):
        if pat.search(file_content):
            return True
    return False


# L2: classify file paths NOT already excluded by _EXCLUDE_DIRS into a context
# bucket so downstream filters (bug_hunter L2) can skip non-runtime findings.
# Only covers the gap paths that _EXCLUDE_DIRS misses (filename patterns and
# sub-directory paths like bin/start*, electron/main/platform/, etc.).
_CTX_CLI = re.compile(
    r"(?:^|/)bin/(?:start|cli|run|server)[^/]*"       # bin/start.sh, bin/cli.js …
    r"|(?:^|/)cli/src/utils/"                          # cli/src/utils/
    # Files whose name implies shell/terminal is the product's core feature.
    # (P4: mirrors bug_hunter FP_RULES "feature_is_shell" condition)
    r"|(?:^|/)(?:terminal|commander|shell_wrapper|console_runner)[^/]*\.[jt]sx?$",
    re.IGNORECASE,
)
_CTX_BUILD = re.compile(
    r"(?:^|/)electron/main/platform/"              # Electron platform bootstrap
    r"|(?:^|/)ingest/"                             # ETL / ingestion scripts
    r"|(?:^|/)release\.[jt]sx?$"                  # release.ts / release.js
    r"|(?:^|/)download[_-][^/]*\.[jt]sx?$",       # download-*.ts / download-*.js
    re.IGNORECASE,
)
_CTX_CTF = re.compile(
    r"(?:^|/)(?:challenges|ctf|hackable)/"         # challenge dirs
    r"|damn[_-]?vulnerable",                       # DVMCP-style repos
    re.IGNORECASE,
)
_CTX_BENCHMARK = re.compile(
    r"(?:^|/)(?:eval|evals|synthesis|test[_-]evals)/",
    re.IGNORECASE,
)


def _classify_file_context(rel_path: str) -> str:
    """Return the file context bucket for *rel_path*.

    Buckets: 'runtime' | 'build' | 'test' | 'cli' | 'benchmark' | 'ctf'

    Only files that survived _EXCLUDE_DIRS (i.e. not already excluded) reach
    this function, so 'test', 'scripts', 'migrations' etc. are rare here.
    The function handles the gap paths that _EXCLUDE_DIRS does not cover.
    """
    norm = rel_path.replace("\\", "/")
    if _CTX_CTF.search(norm):
        return "ctf"
    if _CTX_BENCHMARK.search(norm):
        return "benchmark"
    if _CTX_CLI.search(norm):
        return "cli"
    if _CTX_BUILD.search(norm):
        return "build"
    return "runtime"


_EXCLUDE_DIRS = frozenset({
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
})


def _is_excluded_file(rel_path: str) -> bool:
    """Check if a relative path should be excluded from security scanning."""
    parts = Path(rel_path).parts
    if any(part in _EXCLUDE_DIRS for part in parts):
        return True
    name = Path(rel_path).name
    return (
        name.startswith("test_")
        or name.endswith(".test.ts")
        or name.endswith(".test.js")
        or name.endswith(".spec.ts")
        or name.endswith(".spec.js")
        or name.endswith(".d.ts")
        or name.endswith(".min.js")
        or name.startswith("_test.")
        or name.endswith("_test.go")
    )


def _get_function_body(content: str, start: int, max_lines: int = 30) -> str:
    """Extract the body of a Python function starting after the def line.

    *start* points just past the regex match (end of ``def f(x: str)``).
    We skip the remainder of the signature, any docstring, then collect
    up to *max_lines* of the indented body.
    """
    lines = content[start:].split("\n")
    body_lines: list[str] = []
    body_indent = 0
    in_docstring = False
    past_preamble = False  # True once we've passed docstring / def tail

    for line in lines:
        stripped = line.lstrip()

        # --- skip inside multi-line docstring ---
        if in_docstring:
            if '"""' in stripped or "'''" in stripped:
                in_docstring = False
            continue

        # --- skip blank / comment / trailing def lines before body ---
        if not past_preamble:
            if not stripped or stripped.startswith("#"):
                continue
            # Detect docstring start
            for quote in ('"""', "'''"):
                if stripped.startswith(quote):
                    # Single-line docstring: opening and closing on same line
                    if stripped.count(quote) >= 2:
                        # e.g. """Some doc."""  — skip entire line
                        pass
                    else:
                        in_docstring = True
                    break
            else:
                # First real code line — start collecting body
                past_preamble = True
                body_indent = len(line) - len(stripped)
            if not past_preamble:
                continue

        # --- collect body lines ---
        if stripped == "":
            body_lines.append("")
            continue
        current_indent = len(line) - len(stripped)
        if current_indent < body_indent:
            break  # dedent = end of function
        body_lines.append(stripped)
        if len(body_lines) >= max_lines:
            break

    return "\n".join(body_lines)


_VALIDATION_INDICATORS = re.compile(
    r"(?:"
    r"validate|sanitize|check_|_check\b|_valid"
    r"|raise\s+(?:ValueError|TypeError)"
    r"|isinstance\s*\("
    r"|len\s*\(.*[<>]"  # length checks like len(x) > N
    r"|not\s+\w+\s+or\s+len\s*\("  # guard clauses like `not x or len(x)`
    r")",
    re.IGNORECASE,
)


def _has_validation(func_body: str) -> bool:
    """Check if a function body contains input validation indicators."""
    return bool(_VALIDATION_INDICATORS.search(func_body))


def scan_security(path: Path) -> tuple[float, list[SecurityIssue]]:
    """Scan for security issues in Python and TypeScript files.

    Returns (security_score, list_of_issues).

    When Semgrep is installed, AST-aware rules replace regex for the highest-FP
    categories so duplicate findings are not emitted.
    """
    issues: list[SecurityIssue] = []

    # --- Semgrep pass (AST-aware, higher precision) ---
    # Semgrep results are collected here but added to issues AFTER scoping,
    # so they respect the same exclusion and monorepo rules as regex.
    semgrep_issues: list[SecurityIssue] = []
    if SEMGREP_AVAILABLE:
        semgrep_issues = run_semgrep(path)
        semgrep_issues = [i for i in semgrep_issues if not _is_excluded_file(i.file)]

    source_files = list(path.rglob("*.py")) + list(path.rglob("*.ts")) + list(path.rglob("*.js"))
    source_files = [
        f for f in source_files
        if not any(part in _EXCLUDE_DIRS for part in f.relative_to(path).parts)
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

    # Apply monorepo scoping to Semgrep results as well
    if semgrep_issues and source_files:
        scoped_dirs = {f.relative_to(path).parts[0] for f in source_files if f.relative_to(path).parts}
        semgrep_issues = [
            i for i in semgrep_issues
            if not Path(i.file).parts or Path(i.file).parts[0] in scoped_dirs
        ]
    # L2: apply file_context to Semgrep issues (confidence already set to "high"
    # by semgrep_scan.py; file_context classification lives here to keep it DRY).
    for issue in semgrep_issues:
        issue.file_context = _classify_file_context(issue.file)
    issues.extend(semgrep_issues)

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
        _py_only_rules = {"dangerous_eval", "sql_injection", "unsafe_deserialization"}
        for category, config in DANGEROUS_PATTERNS.items():
            if is_ts_js and category in _py_only_rules:
                continue
            if SEMGREP_AVAILABLE and category in SEMGREP_COVERED_CATEGORIES:
                continue  # Semgrep handles this category with higher precision
            flags = re.IGNORECASE
            for pattern in config["patterns"]:
                # Patterns using ^ need MULTILINE to match per-line
                pat_flags = flags | re.MULTILINE if pattern.startswith("^") else flags
                for match in re.finditer(pattern, content, pat_flags):
                    line_num = content[:match.start()].count("\n") + 1
                    # For no_input_validation: suppress if function body
                    # contains validation (len check, validate call, raise,
                    # or isinstance).  This avoids flagging functions that
                    # *do* validate their str inputs.
                    if category == "no_input_validation":
                        func_body = _get_function_body(content, match.end())
                        if _has_validation(func_body):
                            continue
                    # L3 Phase 1b: downgrade to "low" when a safe/defensive pattern
                    # exists in the same file (e.g. shlex.quote, SafeLoader, hmac).
                    conf = (
                        "low"
                        if _has_safe_pattern(category, content)
                        else "medium"
                    )
                    issues.append(
                        SecurityIssue(
                            severity=config["severity"],
                            category=category,
                            file=rel_path,
                            line=line_num,
                            description=config["description"],
                            fix_suggestion=config["fix"],
                            file_context=_classify_file_context(rel_path),
                            confidence=conf,
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
                        conf = (
                            "low"
                            if _has_safe_pattern(category, content)
                            else "medium"
                        )
                        issues.append(
                            SecurityIssue(
                                severity=config["severity"],
                                category=category,
                                file=rel_path,
                                line=line_num,
                                description=config["description"],
                                fix_suggestion=config["fix"],
                                file_context=_classify_file_context(rel_path),
                                confidence=conf,
                            )
                        )

    # Calculate score
    if not source_files:
        return 5.0, issues

    severity_weights = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.25, "info": 0.1}
    total_penalty = sum(severity_weights.get(i.severity, 0.25) for i in issues)
    score = max(0.0, 10.0 - total_penalty)

    return round(score, 1), issues
