"""Architecture quality checks for MCP servers."""

from __future__ import annotations

from pathlib import Path


def check_architecture(path: Path) -> tuple[float, bool, bool]:
    """Check architecture quality of an MCP server.

    Returns (score, has_tests, has_error_handling).
    """
    has_tests = _has_tests(path)
    has_error_handling = _has_error_handling(path)
    has_readme = (path / "README.md").exists() or (path / "readme.md").exists()
    has_types = _has_type_hints(path)

    score = 0.0
    score += 3.0 if has_tests else 0.0
    score += 3.0 if has_error_handling else 0.0
    score += 2.0 if has_readme else 0.0
    score += 2.0 if has_types else 0.0

    return round(score, 1), has_tests, has_error_handling


def _has_tests(path: Path) -> bool:
    """Check if the project has any test files."""
    test_patterns = ["test_*.py", "*_test.py", "*.test.ts", "*.spec.ts", "*.test.js", "*.spec.js"]
    test_dirs = ["tests", "test", "__tests__", "spec"]

    for pattern in test_patterns:
        if list(path.rglob(pattern)):
            return True

    for dirname in test_dirs:
        if (path / dirname).exists():
            return True

    return False


def _has_error_handling(path: Path) -> bool:
    """Check if source code contains error handling patterns."""
    for source_file in list(path.rglob("*.py")) + list(path.rglob("*.ts")):
        if "node_modules" in str(source_file) or "__pycache__" in str(source_file):
            continue
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        if "try:" in content or "try {" in content or "catch" in content:
            return True

    return False


def _has_type_hints(path: Path) -> bool:
    """Check if Python code has type hints or TypeScript is used."""
    # TypeScript is inherently typed
    if list(path.rglob("*.ts")):
        return True

    for py_file in path.rglob("*.py"):
        if "node_modules" in str(py_file) or "__pycache__" in str(py_file):
            continue
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue

        # Check for type annotations in function signatures
        if ") ->" in content or ": str" in content or ": int" in content:
            return True

    return False
