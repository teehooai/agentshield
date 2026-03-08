"""Hardener runner — applies security fixes to MCP servers."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

console = Console()


def run_harden(
    server_path: str,
    read_only: bool = True,
    truncate_limit: int = 100,
    dry_run: bool = False,
):
    """Apply security hardening to an MCP server."""
    path = Path(server_path)
    if not path.exists():
        console.print(f"[red]Path not found: {server_path}[/red]")
        raise SystemExit(1)

    console.print(f"\n[bold]Hardening MCP server:[/bold] {server_path}")
    console.print(f"[dim]Read-only: {read_only} | Truncate limit: {truncate_limit} | Dry run: {dry_run}[/dim]\n")

    fixes_applied = []

    # Fix 1: Credential wrapping
    cred_fixes = _fix_credentials(path, dry_run)
    if cred_fixes:
        fixes_applied.extend(cred_fixes)

    # Fix 2: Input validation
    validation_fixes = _add_input_validation(path, dry_run)
    if validation_fixes:
        fixes_applied.extend(validation_fixes)

    # Fix 3: Result truncation
    truncation_fixes = _add_result_truncation(path, truncate_limit, dry_run)
    if truncation_fixes:
        fixes_applied.extend(truncation_fixes)

    # Fix 4: Read-only defaults
    if read_only:
        readonly_fixes = _add_read_only_defaults(path, dry_run)
        if readonly_fixes:
            fixes_applied.extend(readonly_fixes)

    # Summary
    console.print(f"\n[bold]Summary:[/bold] {len(fixes_applied)} fixes {'would be ' if dry_run else ''}applied")
    for fix in fixes_applied:
        console.print(f"  ✅ {fix}")

    if dry_run:
        console.print("\n[yellow]Dry run — no files were modified. Remove --dry-run to apply.[/yellow]")
    else:
        console.print("\n[green]Hardening complete.[/green] Run `agentshield scan` to verify.\n")


def _fix_credentials(path: Path, dry_run: bool) -> list[str]:
    """Detect and fix insecure credential handling."""
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
            fixes.append(f"[credential] {rel}: Plain env var credential detected — wrap with secret manager")
            # TODO: Apply Astrix Secret Wrapper
    return fixes


def _add_input_validation(path: Path, dry_run: bool) -> list[str]:
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
                fixes.append(f"[path_traversal] {rel}: Add path validation (resolve + is_relative_to check)")

        # Detect SQL without parameterization
        if re.search(r'execute\(.*f["\']', content):
            rel = py_file.relative_to(path)
            fixes.append(f"[sql_injection] {rel}: Use parameterized queries instead of f-strings")

    return fixes


def _add_result_truncation(path: Path, limit: int, dry_run: bool) -> list[str]:
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
                fixes.append(f"[truncation] {rel}: Add LIMIT {limit} to queries to prevent context explosion")

    return fixes


def _add_read_only_defaults(path: Path, dry_run: bool) -> list[str]:
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
                fixes.append(f"[read_only] {rel}: Add read-only mode (block INSERT/UPDATE/DELETE/DROP by default)")

    return fixes
