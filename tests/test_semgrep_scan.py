"""Tests for Semgrep integration (semgrep_scan.py).

When Semgrep is not installed the module exports SEMGREP_AVAILABLE=False and
run_semgrep() returns [].  All tests must work regardless of whether Semgrep
is installed in the test environment.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from spidershield.scanner.security_scan import scan_security
from spidershield.scanner.semgrep_scan import (
    SEMGREP_COVERED_CATEGORIES,
    _parse_semgrep_output,
    _rule_id_to_category,
    run_semgrep,
)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

def test_semgrep_covered_categories_not_empty():
    assert len(SEMGREP_COVERED_CATEGORIES) >= 6


def test_semgrep_covered_categories_contains_key_patterns():
    assert "dangerous_eval" in SEMGREP_COVERED_CATEGORIES
    assert "command_injection" in SEMGREP_COVERED_CATEGORIES
    assert "sql_injection" in SEMGREP_COVERED_CATEGORIES
    assert "ts_unsafe_eval" in SEMGREP_COVERED_CATEGORIES
    assert "child_process_injection" in SEMGREP_COVERED_CATEGORIES
    assert "ts_sql_injection" in SEMGREP_COVERED_CATEGORIES


# ---------------------------------------------------------------------------
# _rule_id_to_category
# ---------------------------------------------------------------------------

def test_rule_id_to_category_known_rules():
    assert _rule_id_to_category("mcp-dangerous-eval") == "dangerous_eval"
    assert _rule_id_to_category("mcp-dangerous-exec") == "dangerous_eval"
    assert _rule_id_to_category("mcp-os-system-variable") == "command_injection"
    assert _rule_id_to_category("mcp-subprocess-shell-true-fstring") == "command_injection"
    assert _rule_id_to_category("mcp-sql-execute-fstring") == "sql_injection"
    assert _rule_id_to_category("mcp-ts-new-function") == "ts_unsafe_eval"
    assert _rule_id_to_category("mcp-ts-eval-variable") == "ts_unsafe_eval"
    assert _rule_id_to_category("mcp-ts-exec-sync-template") == "child_process_injection"
    assert _rule_id_to_category("mcp-ts-query-template-literal") == "ts_sql_injection"


def test_rule_id_to_category_unknown_returns_empty():
    assert _rule_id_to_category("some-unknown-rule") == ""


# ---------------------------------------------------------------------------
# _parse_semgrep_output
# ---------------------------------------------------------------------------

def _make_semgrep_result(
    rule_id: str,
    path: str,
    line: int,
    message: str = "test finding",
    category: str = "",
    severity_level: str = "critical",
) -> dict:
    return {
        "check_id": rule_id,
        "path": path,
        "start": {"line": line, "col": 1},
        "end": {"line": line, "col": 10},
        "extra": {
            "message": message,
            "severity": "ERROR",
            "metadata": {
                "category": category,
                "severity_level": severity_level,
            },
        },
    }


def test_parse_semgrep_output_basic(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = str(repo / "server.py")

    raw = json.dumps(
        {
            "results": [
                _make_semgrep_result(
                    "python.dangerous_eval.mcp-dangerous-eval",
                    target,
                    10,
                    "Dynamic code execution",
                    category="dangerous_eval",
                )
            ],
            "errors": [],
        }
    )
    issues = _parse_semgrep_output(raw, repo)
    assert len(issues) == 1
    assert issues[0].category == "dangerous_eval"
    assert issues[0].severity == "critical"
    assert issues[0].line == 10
    assert issues[0].file == "server.py"


def test_parse_semgrep_output_deduplication(tmp_path: Path):
    """Same (file, line, category) should appear only once."""
    repo = tmp_path / "repo"
    repo.mkdir()
    target = str(repo / "server.py")

    result = _make_semgrep_result(
        "mcp-dangerous-eval", target, 5, category="dangerous_eval"
    )
    raw = json.dumps({"results": [result, result], "errors": []})
    issues = _parse_semgrep_output(raw, repo)
    assert len(issues) == 1


def test_parse_semgrep_output_category_from_rule_id(tmp_path: Path):
    """When metadata.category is empty, derive from rule ID."""
    repo = tmp_path / "repo"
    repo.mkdir()
    target = str(repo / "server.py")

    raw = json.dumps(
        {
            "results": [
                {
                    "check_id": "mcp-os-system-variable",
                    "path": target,
                    "start": {"line": 3},
                    "extra": {
                        "message": "os.system with variable",
                        "severity": "ERROR",
                        "metadata": {},
                    },
                }
            ],
            "errors": [],
        }
    )
    issues = _parse_semgrep_output(raw, repo)
    assert issues[0].category == "command_injection"


def test_parse_semgrep_output_invalid_json(tmp_path: Path):
    issues = _parse_semgrep_output("not-json", tmp_path)
    assert issues == []


def test_parse_semgrep_output_empty_results(tmp_path: Path):
    raw = json.dumps({"results": [], "errors": []})
    issues = _parse_semgrep_output(raw, tmp_path)
    assert issues == []


# ---------------------------------------------------------------------------
# run_semgrep — mocked subprocess
# ---------------------------------------------------------------------------

def _fake_semgrep_json(repo: Path) -> str:
    return json.dumps(
        {
            "results": [
                _make_semgrep_result(
                    "mcp-dangerous-eval",
                    str(repo / "app.py"),
                    7,
                    "eval with variable",
                    category="dangerous_eval",
                )
            ],
            "errors": [],
        }
    )


def test_run_semgrep_when_available(tmp_path: Path):
    with (
        patch("spidershield.scanner.semgrep_scan.SEMGREP_AVAILABLE", True),
        patch("spidershield.scanner.semgrep_scan._SEMGREP_BIN", "/usr/bin/semgrep"),
        patch("spidershield.scanner.semgrep_scan.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout=_fake_semgrep_json(tmp_path),
            stderr="",
        )
        issues = run_semgrep(tmp_path)

    assert len(issues) == 1
    assert issues[0].category == "dangerous_eval"


def test_run_semgrep_when_unavailable(tmp_path: Path):
    with patch("spidershield.scanner.semgrep_scan.SEMGREP_AVAILABLE", False):
        issues = run_semgrep(tmp_path)
    assert issues == []


def test_run_semgrep_timeout_returns_empty(tmp_path: Path):
    import subprocess as sp

    with (
        patch("spidershield.scanner.semgrep_scan.SEMGREP_AVAILABLE", True),
        patch("spidershield.scanner.semgrep_scan._SEMGREP_BIN", "/usr/bin/semgrep"),
        patch(
            "spidershield.scanner.semgrep_scan.subprocess.run",
            side_effect=sp.TimeoutExpired("semgrep", 60),
        ),
    ):
        issues = run_semgrep(tmp_path)
    assert issues == []


def test_run_semgrep_error_exit_returns_empty(tmp_path: Path):
    with (
        patch("spidershield.scanner.semgrep_scan.SEMGREP_AVAILABLE", True),
        patch("spidershield.scanner.semgrep_scan._SEMGREP_BIN", "/usr/bin/semgrep"),
        patch("spidershield.scanner.semgrep_scan.subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="fatal error")
        issues = run_semgrep(tmp_path)
    assert issues == []


# ---------------------------------------------------------------------------
# Hybrid scan_security integration
# ---------------------------------------------------------------------------

def test_scan_security_semgrep_replaces_regex_for_covered_categories(tmp_path: Path):
    """When Semgrep is 'available', regex must NOT fire for covered categories."""
    py_file = tmp_path / "server.py"
    py_file.write_text("import os\ndef run(cmd):\n    os.system(cmd)\n")

    semgrep_issue_json = json.dumps(
        {
            "results": [
                _make_semgrep_result(
                    "mcp-os-system-variable",
                    str(tmp_path / "server.py"),
                    3,
                    "os.system with variable",
                    category="command_injection",
                )
            ],
            "errors": [],
        }
    )

    with (
        patch("spidershield.scanner.security_scan.SEMGREP_AVAILABLE", True),
        patch("spidershield.scanner.security_scan.SEMGREP_COVERED_CATEGORIES",
              frozenset({"command_injection"})),
        patch("spidershield.scanner.security_scan.run_semgrep") as mock_sg,
    ):
        from spidershield.scanner.semgrep_scan import _parse_semgrep_output
        mock_sg.return_value = _parse_semgrep_output(semgrep_issue_json, tmp_path)
        score, issues = scan_security(tmp_path)

    cmd_issues = [i for i in issues if i.category == "command_injection"]
    # Semgrep found 1; regex should be skipped → exactly 1 total
    assert len(cmd_issues) == 1


def test_scan_security_regex_fallback_when_semgrep_absent(tmp_path: Path):
    """When Semgrep is absent, regex still catches dangerous patterns."""
    py_file = tmp_path / "server.py"
    py_file.write_text("import os\ndef run(cmd):\n    os.system(cmd)\n")

    with patch("spidershield.scanner.security_scan.SEMGREP_AVAILABLE", False):
        score, issues = scan_security(tmp_path)

    assert any(i.category == "command_injection" for i in issues)


def test_scan_security_non_covered_categories_always_use_regex(tmp_path: Path):
    """Categories not in SEMGREP_COVERED_CATEGORIES always use regex."""
    py_file = tmp_path / "server.py"
    py_file.write_text('import pickle\ndata = pickle.loads(b"...")\n')

    with (
        patch("spidershield.scanner.security_scan.SEMGREP_AVAILABLE", True),
        patch("spidershield.scanner.security_scan.run_semgrep", return_value=[]),
    ):
        score, issues = scan_security(tmp_path)

    # unsafe_deserialization is NOT in SEMGREP_COVERED_CATEGORIES → regex fires
    assert any(i.category == "unsafe_deserialization" for i in issues)
