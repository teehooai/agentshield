"""Scanner runner — orchestrates all scan stages."""

from __future__ import annotations

import json
from pathlib import Path

import sys

from rich.console import Console
from rich.table import Table

from teeshield.models import ScanReport
from teeshield.scanner.license_check import check_license
from teeshield.scanner.security_scan import scan_security
from teeshield.scanner.description_quality import score_descriptions
from teeshield.scanner.architecture_check import check_architecture

console = Console()
stderr_console = Console(file=sys.stderr)


def resolve_target(target: str) -> Path:
    """Resolve target to a local path. Clone from GitHub if needed."""
    path = Path(target)
    if path.exists():
        return path

    if target.startswith(("http://", "https://", "git@", "github.com")):
        import subprocess

        clone_dir = Path("./tmp_scan") / target.split("/")[-1].replace(".git", "")
        if clone_dir.exists():
            import shutil

            shutil.rmtree(clone_dir)
        subprocess.run(["git", "clone", "--depth", "1", target, str(clone_dir)], check=True)
        return clone_dir

    console.print(f"[red]Target not found: {target}[/red]")
    raise SystemExit(1)


def run_scan(target: str, output_path: str | None = None, output_format: str = "table"):
    """Run a full scan on an MCP server."""
    # Use stderr for progress when outputting JSON to stdout
    log = stderr_console if (output_format == "json" and not output_path) else console
    log.print(f"\n[bold]Scanning:[/bold] {target}\n")

    path = resolve_target(target)

    # Stage 1: License
    log.print("[dim]Stage 1/4: License check...[/dim]")
    license_info, license_ok = check_license(path)

    # Stage 2: Security
    log.print("[dim]Stage 2/4: Security scan...[/dim]")
    security_score, security_issues = scan_security(path)

    # Stage 3: Description quality
    log.print("[dim]Stage 3/4: Description quality...[/dim]")
    desc_score, tool_scores, tool_names = score_descriptions(path)

    # Stage 4: Architecture
    log.print("[dim]Stage 4/4: Architecture check...[/dim]")
    arch_score, has_tests, has_error_handling = check_architecture(path)

    # Compute overall
    overall = (security_score * 0.4 + desc_score * 0.35 + arch_score * 0.25)
    improvement_potential = 10.0 - overall

    # Determine rating
    from teeshield.models import Rating
    if any(i.severity == "critical" for i in security_issues):
        rating = Rating.F
    elif overall >= 9.0:
        rating = Rating.A_PLUS
    elif overall >= 8.0:
        rating = Rating.A
    elif overall >= 6.0:
        rating = Rating.B
    elif overall >= 4.0:
        rating = Rating.C
    else:
        rating = Rating.F

    # Build recommendations
    recommendations = []
    if desc_score < 6.0:
        recommendations.append("Run `teeshield rewrite` to optimize tool descriptions for LLMs")
    if security_score < 6.0:
        recommendations.append("Run `teeshield harden` to fix security issues")
    if len(tool_names) > 40:
        recommendations.append(
            f"Too many tools ({len(tool_names)}). Consider splitting into multiple servers"
        )
    if not has_tests:
        recommendations.append("Add automated tests for reliability")

    report = ScanReport(
        target=target,
        license=license_info,
        license_ok=license_ok,
        tool_count=len(tool_names),
        tool_names=tool_names,
        security_score=round(security_score, 1),
        security_issues=security_issues,
        description_score=round(desc_score, 1),
        tool_scores=tool_scores,
        architecture_score=round(arch_score, 1),
        has_tests=has_tests,
        has_error_handling=has_error_handling,
        overall_score=round(overall, 1),
        improvement_potential=round(improvement_potential, 1),
        rating=rating,
        recommendations=recommendations,
    )

    if output_format == "json" or output_path:
        json_str = report.model_dump_json(indent=2)
        if output_path:
            Path(output_path).write_text(json_str)
            console.print(f"\n[green]Report saved to {output_path}[/green]")
        else:
            console.print(json_str)
    else:
        _print_table(report)


def _print_table(report: ScanReport):
    """Print a rich table summary."""
    table = Table(title=f"TeeShield Scan Report - {report.target}")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_column("Score", justify="right")

    ok = "[green]OK[/green]"
    fail = "[red]FAIL[/red]"
    warn = "[yellow]WARN[/yellow]"
    table.add_row("License", report.license or "Unknown", ok if report.license_ok else fail)
    table.add_row("Tools", str(report.tool_count), warn if report.tool_count > 40 else ok)
    table.add_row("Security", f"{len(report.security_issues)} issues", f"{report.security_score}/10")
    table.add_row("Descriptions", "", f"{report.description_score}/10")
    table.add_row("Architecture", "", f"{report.architecture_score}/10")
    table.add_row("Tests", "Yes" if report.has_tests else "No", ok if report.has_tests else fail)
    table.add_row("", "", "")
    table.add_row("[bold]Overall[/bold]", f"Rating: {report.rating.value}", f"[bold]{report.overall_score}/10[/bold]")
    table.add_row("Improvement Potential", "", f"{report.improvement_potential}/10")

    console.print(table)

    if report.security_issues:
        console.print(f"\n[yellow]Security Issues ({len(report.security_issues)}):[/yellow]")
        for issue in report.security_issues[:10]:
            console.print(f"  [{issue.severity}] {issue.category}: {issue.description} ({issue.file}:{issue.line})")

    if report.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            console.print(f"  > {rec}")

    console.print()
