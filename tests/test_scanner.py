"""Tests for the scanner module."""

from pathlib import Path

from agentshield.scanner.license_check import check_license
from agentshield.scanner.security_scan import scan_security
from agentshield.scanner.description_quality import score_descriptions
from agentshield.scanner.architecture_check import check_architecture


def test_license_check_mit(tmp_path: Path):
    """Test MIT license detection."""
    license_file = tmp_path / "LICENSE"
    license_file.write_text("MIT License\n\nPermission is hereby granted, free of charge...")
    name, ok = check_license(tmp_path)
    assert name == "MIT"
    assert ok is True


def test_license_check_gpl(tmp_path: Path):
    """Test GPL license detection (should not be fork-safe)."""
    license_file = tmp_path / "LICENSE"
    license_file.write_text("GNU General Public License version 3")
    name, ok = check_license(tmp_path)
    assert name == "GPL"
    assert ok is False


def test_license_check_missing(tmp_path: Path):
    """Test missing license."""
    name, ok = check_license(tmp_path)
    assert name is None
    assert ok is False


def test_security_scan_clean(tmp_path: Path):
    """Test scanning a clean file."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def hello():\n    return "world"\n')
    score, issues = scan_security(tmp_path)
    assert score >= 8.0
    assert len(issues) == 0


def test_security_scan_sql_injection(tmp_path: Path):
    """Test detection of SQL injection."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def query(sql):\n    db.execute(f"SELECT * FROM {sql}")\n')
    score, issues = scan_security(tmp_path)
    assert score < 8.0
    assert any(i.category == "sql_injection" for i in issues)


def test_security_scan_command_injection(tmp_path: Path):
    """Test detection of command injection."""
    py_file = tmp_path / "server.py"
    py_file.write_text('import os\ndef run(cmd):\n    os.system(cmd)\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "command_injection" for i in issues)
    assert any(i.severity == "critical" for i in issues)


def test_description_quality_good(tmp_path: Path):
    """Test scoring of a well-described tool."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def list_tables():
    """List all tables in the database.

    Use when the user wants to see available tables.
    Example: Returns ['users', 'orders', 'products'].
    If the connection fails, check your database URL.
    """
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert len(names) == 1
    assert names[0] == "list_tables"
    assert tool_scores[0].has_scenario_trigger is True
    assert tool_scores[0].has_param_examples is True
    assert tool_scores[0].has_error_guidance is True


def test_description_quality_poor(tmp_path: Path):
    """Test scoring of a poorly-described tool."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def query(sql):
    """Execute a query."""
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert tool_scores[0].has_scenario_trigger is False
    assert tool_scores[0].has_param_examples is False
    assert tool_scores[0].overall_score < 5.0


def test_architecture_check(tmp_path: Path):
    """Test architecture quality checks."""
    # No tests, no error handling
    py_file = tmp_path / "server.py"
    py_file.write_text('def hello():\n    return "world"\n')
    score, has_tests, has_error = check_architecture(tmp_path)
    assert has_tests is False
    assert has_error is False

    # Add a test file
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_server.py").write_text("def test_hello(): pass")
    score2, has_tests2, _ = check_architecture(tmp_path)
    assert has_tests2 is True
    assert score2 > score
