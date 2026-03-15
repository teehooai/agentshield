"""End-to-end integration tests for the full scan pipeline.

These tests exercise the complete scan → score → grade pipeline on
synthetic servers with known characteristics, catching regressions
like BUG-4 (path exclusion) that unit tests miss.
"""

from __future__ import annotations

from pathlib import Path

from spidershield.scanner.runner import run_scan_report


def _make_mcp_tool(name: str, desc: str) -> str:
    """Generate a Python MCP tool function."""
    return f'''
@server.tool()
async def {name}(input: str) -> str:
    """{desc}"""
    try:
        return "ok"
    except ValueError:
        return "error"
'''


def _make_server(tmp_path: Path, tools: list[tuple[str, str]], *,
                 add_readme: bool = True,
                 add_tests: bool = True,
                 add_security_issue: str | None = None) -> Path:
    """Create a synthetic MCP server directory with given tools."""
    server_code = '"""Synthetic MCP server for testing."""\n'
    server_code += "from pathlib import Path\n"
    server_code += "from mcp.server import Server\n\n"
    server_code += 'server = Server("test-server")\n\n'

    for name, desc in tools:
        server_code += _make_mcp_tool(name, desc)

    if add_security_issue:
        server_code += f"\n{add_security_issue}\n"

    (tmp_path / "server.py").write_text(server_code)

    if add_readme:
        (tmp_path / "README.md").write_text(
            "# Test Server\n\nA test MCP server with multiple tools.\n"
            "Designed for integration testing of the SpiderShield scan pipeline.\n"
            "Includes examples, installation instructions, and usage documentation.\n"
            * 3  # Ensure >1000 chars for full README score
        )

    if add_tests:
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        for i in range(5):
            (tests_dir / f"test_tool_{i}.py").write_text(
                f"def test_tool_{i}():\n    assert True\n"
            )

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "test"\nversion = "0.1.0"\n'
    )
    (tmp_path / "requirements.txt").write_text("mcp>=1.0\n")

    return tmp_path


# --- Well-described tools (high description score expected) ---

_GOOD_TOOLS: list[tuple[str, str]] = [
    ("read_file", (
        "Read a file from the workspace. Use when the user wants to view "
        "file contents. Accepts `path` — a relative file path (e.g., "
        "'src/main.py'). Returns the full text content. If the file does "
        "not exist, returns an error message."
    )),
    ("write_file", (
        "Write content to a file in the workspace. Use when the user wants "
        "to create or overwrite a file. Accepts `path` and `content` parameters "
        "(e.g., path='output.txt', content='hello'). Returns a confirmation "
        "message. Fails if the path is outside the workspace."
    )),
    ("list_files", (
        "List files in a directory. Use when the user wants to browse "
        "available files. Accepts `directory` — a relative path (e.g., "
        "'src/utils'). Returns one filename per line. If the directory does "
        "not exist, returns an error."
    )),
    ("search_files", (
        "Search for files matching a glob pattern. Use when the user wants "
        "to find files by name or extension (e.g., '*.py', 'test_*'). "
        "Accepts `pattern` parameter. Returns matching paths, limited "
        "to 50 results. Returns an empty string if no matches found."
    )),
    ("delete_file", (
        "Delete a file from the workspace. Use when the user wants to "
        "remove a specific file. Accepts `path` — the file to delete "
        "(e.g., 'temp/cache.json'). Returns confirmation or error if "
        "the file doesn't exist or is outside the workspace."
    )),
    ("create_directory", (
        "Create a new directory in the workspace. Use when the user needs "
        "to organize files. Accepts `path` (e.g., 'src/components'). "
        "Returns confirmation. Fails with error if the directory already "
        "exists or the path is invalid."
    )),
    ("get_file_info", (
        "Retrieve metadata about a file. Use when the user wants to check "
        "file size, modification date, or permissions. Accepts `path` "
        "(e.g., 'data/input.csv'). Returns a JSON object with size, "
        "modified, and permissions fields. Error if file not found."
    )),
    ("rename_file", (
        "Rename or move a file within the workspace. Use when the user "
        "wants to change a filename or relocate a file. Accepts `old_path` "
        "and `new_path` (e.g., 'draft.txt' to 'final.txt'). Returns "
        "confirmation. Error if source doesn't exist."
    )),
    ("compare_files", (
        "Compare two files and show differences. Use when the user wants "
        "to see what changed between versions. Accepts `path_a` and "
        "`path_b` (e.g., 'v1.py', 'v2.py'). Returns a unified diff. "
        "Error if either file is missing."
    )),
    ("execute_query", (
        "Run a read-only SQL query against the database. Use when the "
        "user wants to inspect data. Accepts `query` — a SQL SELECT "
        "statement (e.g., 'SELECT count(*) FROM users'). Returns "
        "results as JSON array. Error if query is not SELECT."
    )),
    ("check_health", (
        "Check the health status of connected services. Use when the "
        "user wants to verify system availability. Takes no parameters. "
        "Returns a JSON object with service statuses. Error if health "
        "endpoint is unreachable."
    )),
    ("upload_file", (
        "Upload a file to cloud storage. Use when the user wants to "
        "share or backup a file. Accepts `path` — the local file "
        "(e.g., 'reports/monthly.pdf'). Returns the download URL. "
        "Fails with error if file exceeds 100MB or path is invalid."
    )),
]


class TestFullPipeline:
    """Integration tests for the complete scan pipeline."""

    def test_clean_server_high_score(self, tmp_path: Path) -> None:
        """A server with 12 well-described tools should score ≥7.5 (B+).

        Note: synthetic stubs trigger no_input_validation (low severity)
        because tool handlers accept raw str params without validation.
        This is expected scanner behaviour, not a test bug.
        """
        _make_server(tmp_path, _GOOD_TOOLS)
        report = run_scan_report(str(tmp_path))
        assert report.overall_score >= 7.5, (
            f"Expected ≥7.5, got {report.overall_score} "
            f"(desc={report.description_score}, sec={report.security_score}, "
            f"arch={report.architecture_score})"
        )
        assert report.tool_count == 12
        assert report.description_score >= 9.0

    def test_server_with_security_issue(self, tmp_path: Path) -> None:
        """A server with a SQL injection should score lower."""
        _make_server(tmp_path, _GOOD_TOOLS[:5],
                     add_security_issue='cursor.execute(f"SELECT * FROM t WHERE id={uid}")')
        report = run_scan_report(str(tmp_path))
        assert any(i.category == "sql_injection" for i in report.security_issues)
        assert report.security_score < 10.0

    def test_server_no_tools(self, tmp_path: Path) -> None:
        """A server with no tools should get F rating."""
        (tmp_path / "server.py").write_text("# empty server\n")
        report = run_scan_report(str(tmp_path))
        assert report.tool_count == 0
        assert report.rating.value == "F"

    def test_server_poor_descriptions(self, tmp_path: Path) -> None:
        """Terse one-word descriptions should score low."""
        poor_tools = [
            ("read", "Read."),
            ("write", "Write."),
            ("delete", "Delete."),
        ]
        _make_server(tmp_path, poor_tools)
        report = run_scan_report(str(tmp_path))
        assert report.description_score < 4.0

    def test_description_scorer_return_docs(self, tmp_path: Path) -> None:
        """Tools with return documentation should score higher."""
        with_returns = [("tool_a", "Get data. Returns JSON array of results.")]
        without_returns = [("tool_b", "Get data.")]
        _make_server(tmp_path, with_returns + without_returns)
        report = run_scan_report(str(tmp_path))
        scores = {s.tool_name: s for s in report.tool_scores}
        assert scores["tool_a"].has_return_docs is True
        assert scores["tool_b"].has_return_docs is False
        assert scores["tool_a"].overall_score > scores["tool_b"].overall_score

    def test_architecture_scoring(self, tmp_path: Path) -> None:
        """Server with README + tests should score ≥6.0."""
        _make_server(tmp_path, _GOOD_TOOLS[:3], add_readme=True, add_tests=True)
        report = run_scan_report(str(tmp_path))
        assert report.architecture_score >= 6.0
        assert report.has_tests is True

    def test_nested_directory_not_excluded(self, tmp_path: Path) -> None:
        """Scanning a target inside 'examples/' dir must not return 5.0.
        Regression test for BUG-4 (path exclusion bug).
        """
        nested = tmp_path / "examples" / "my-server"
        nested.mkdir(parents=True)
        (nested / "server.py").write_text(
            'import os\nos.system(f"rm {user_input}")\n'
        )
        report = run_scan_report(str(nested))
        # Must find the command injection, not return default 5.0
        assert report.security_score != 5.0 or len(report.security_issues) > 0

    def test_report_json_serializable(self, tmp_path: Path) -> None:
        """ScanReport must be fully JSON-serializable."""
        import json
        _make_server(tmp_path, _GOOD_TOOLS[:3])
        report = run_scan_report(str(tmp_path))
        data = json.loads(report.model_dump_json())
        assert "overall_score" in data
        assert "tool_scores" in data
        assert len(data["tool_scores"]) == 3

    def test_all_new_model_fields_in_output(self, tmp_path: Path) -> None:
        """Verify has_return_docs appears in tool score output."""
        _make_server(tmp_path, _GOOD_TOOLS[:1])
        report = run_scan_report(str(tmp_path))
        score_dict = report.tool_scores[0].model_dump()
        assert "has_return_docs" in score_dict
