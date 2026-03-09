"""Hardener runner -- suggests security fixes for MCP servers (advisory only)."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

console = Console()


def run_harden(
    server_path: str,
    read_only: bool = True,
    truncate_limit: int = 100,
):
    """Suggest security hardening for an MCP server (advisory only, no files modified)."""
    path = Path(server_path)
    if not path.exists():
        console.print(f"[red]Path not found: {server_path}[/red]")
        raise SystemExit(1)

    console.print(f"\n[bold]Security suggestions for:[/bold] {server_path}")
    console.print(f"[dim]Read-only default: {read_only} | Truncate limit: {truncate_limit}[/dim]\n")

    fixes_applied = []

    # Check 1: Credential handling
    cred_fixes = _fix_credentials(path)
    if cred_fixes:
        fixes_applied.extend(cred_fixes)

    # Check 2: Input validation
    validation_fixes = _add_input_validation(path)
    if validation_fixes:
        fixes_applied.extend(validation_fixes)

    # Check 3: Result truncation
    truncation_fixes = _add_result_truncation(path, truncate_limit)
    if truncation_fixes:
        fixes_applied.extend(truncation_fixes)

    # Check 4: Read-only defaults
    if read_only:
        readonly_fixes = _add_read_only_defaults(path)
        if readonly_fixes:
            fixes_applied.extend(readonly_fixes)

    # Summary
    if fixes_applied:
        console.print(f"\n[bold]Found {len(fixes_applied)} suggestion(s):[/bold]")
        for fix in fixes_applied:
            console.print(f"  [yellow]![/yellow] {fix}")
        console.print("\n[dim]These are advisory suggestions. No files were modified.[/dim]")
    else:
        console.print("\n[green]No issues found.[/green]")


def _fix_credentials(path: Path) -> list[str]:
    """Detect insecure credential handling."""
    fixes = []
    for source_file in list(path.rglob("*.py")) + list(path.rglob("*.ts")):
        if "node_modules" in str(source_file):
            continue
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        if "os.environ" in content or "os.getenv" in content or "process.env" in content:
            rel = source_file.relative_to(path)
            fixes.append(
                f"[credential] {rel}: Plain env var credential"
                " -- wrap with secret manager"
            )
    return fixes


def _add_input_validation(path: Path) -> list[str]:
    """Detect missing input validation and suggest fixes."""
    import re

    fixes = []
    for py_file in path.rglob("*.py"):
        if "node_modules" in str(py_file) or "__pycache__" in str(py_file):
            continue
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue

        # Detect path operations without validation
        if re.search(r"open\(|Path\(", content) and ".." not in content:
            if "resolve" not in content and "is_relative_to" not in content:
                rel = py_file.relative_to(path)
                fixes.append(
                    f"[path_traversal] {rel}: Add path validation"
                    " (resolve + is_relative_to check)"
                )

        # Detect SQL without parameterization
        if re.search(r'execute\(.*f["\']', content):
            rel = py_file.relative_to(path)
            fixes.append(f"[sql_injection] {rel}: Use parameterized queries instead of f-strings")

    return fixes


def _add_result_truncation(path: Path, limit: int) -> list[str]:
    """Detect tools that may return unbounded results."""
    fixes = []
    for py_file in path.rglob("*.py"):
        if "node_modules" in str(py_file) or "__pycache__" in str(py_file):
            continue
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue

        if "fetchall" in content or "SELECT" in content.upper():
            if "LIMIT" not in content.upper() and str(limit) not in content:
                rel = py_file.relative_to(path)
                fixes.append(
                    f"[truncation] {rel}: Add LIMIT {limit}"
                    " to queries to prevent context explosion"
                )

    return fixes


def _add_read_only_defaults(path: Path) -> list[str]:
    """Detect write operations that should be read-only by default."""
    import re

    fixes = []
    dangerous_sql = re.compile(r"(?:INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE)", re.I)

    for py_file in path.rglob("*.py"):
        if "node_modules" in str(py_file) or "__pycache__" in str(py_file):
            continue
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue

        if dangerous_sql.search(content):
            if "read_only" not in content and "readonly" not in content:
                rel = py_file.relative_to(path)
                fixes.append(
                    f"[read_only] {rel}: Add read-only mode"
                    " (block INSERT/UPDATE/DELETE/DROP by default)"
                )

    return fixes
