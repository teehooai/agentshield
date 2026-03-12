"""Scanner runner -- orchestrates all scan stages."""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from spidershield.models import ScanReport
from spidershield.scanner.architecture_check import check_architecture
from spidershield.scanner.description_quality import score_descriptions
from spidershield.scanner.license_check import check_license
from spidershield.scanner.security_scan import scan_security
from spidershield.scoring_spec import spec_architecture_bonus, spec_grade

console = Console()
stderr_console = Console(file=sys.stderr)


def resolve_target(target: str) -> Path:
    """Resolve target to a local path. Clone from GitHub if needed."""
    path = Path(target)
    if path.exists():
        return path

    if target.startswith(("http://", "https://", "git@", "github.com")):
        import subprocess
        import tempfile

        repo_name = target.split("/")[-1].replace(".git", "")
        clone_dir = Path(tempfile.mkdtemp(prefix="spidershield_")) / repo_name
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", target, str(clone_dir)],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Failed to clone {target}: {e.stderr.decode().strip()}[/red]")
            raise SystemExit(1)
        return clone_dir

    console.print(f"[red]Target not found: {target}[/red]")
    raise SystemExit(1)


def _compute_pattern_set_hash() -> str:
    """SHA-256 hash of sorted pattern names for change detection."""
    import hashlib

    from spidershield.scanner.security_scan import (
        DANGEROUS_PATTERNS,
        TS_DANGEROUS_PATTERNS,
    )

    names = sorted(DANGEROUS_PATTERNS.keys()) + sorted(
        TS_DANGEROUS_PATTERNS.keys()
    )
    return hashlib.sha256(
        "|".join(names).encode()
    ).hexdigest()[:16]


def run_scan_report(target: str, tools_json: str | None = None) -> ScanReport:
    """Run a full scan and return the report object."""
    import time as _time

    _scan_start = _time.monotonic()
    path = resolve_target(target)

    license_info, license_ok = check_license(path)
    security_score, security_issues = scan_security(path)
    desc_score, tool_scores, tool_names = score_descriptions(path, tools_json=tools_json)
    arch_score, has_tests, has_error_handling = check_architecture(path)

    # SpiderRating formula: description 35% + security 35% + architecture 30%
    # Architecture replaces metadata locally (metadata requires GitHub API).
    # Architecture bonus (0-2) also folds into security for richer signal.
    arch_bonus = spec_architecture_bonus(arch_score)
    security_adjusted = min(10.0, security_score + arch_bonus)
    overall = (desc_score * 0.35 + security_adjusted * 0.35 + arch_score * 0.30)
    improvement_potential = 10.0 - overall

    from spidershield.models import Rating

    # Hard constraints (checked before grade thresholds)
    hard_constraint = None
    if any(i.severity == "critical" for i in security_issues):
        hard_constraint = "critical_vulnerability"
    elif len(tool_names) == 0:
        hard_constraint = "no_tools"
    else:
        banned = {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "BSL-1.1"}
        if license_info and license_info.upper() in {lic.upper() for lic in banned}:
            hard_constraint = "license_banned"

    # Grade from scoring spec (hard constraints handled locally for CLI)
    if hard_constraint in ("critical_vulnerability", "no_tools"):
        rating = Rating.F
    elif hard_constraint == "license_banned":
        rating = Rating.D if overall >= 3.0 else Rating.F
    else:
        rating = Rating(spec_grade(overall))

    recommendations = []
    if desc_score < 6.0:
        worst = sorted(tool_scores, key=lambda s: s.overall_score)[:3]
        worst_names = ", ".join(f"`{s.tool_name}` ({s.overall_score}/10)" for s in worst)
        recommendations.append(f"Run `spidershield rewrite` -- worst tools: {worst_names}")
        # Actionable hints based on what's missing across tools
        missing = {"verb": 0, "scenario": 0, "params": 0, "examples": 0}
        for s in tool_scores:
            if not s.has_action_verb:
                missing["verb"] += 1
            if not s.has_scenario_trigger:
                missing["scenario"] += 1
            if not s.has_param_docs:
                missing["params"] += 1
            if not s.has_param_examples:
                missing["examples"] += 1
        top_missing = sorted(missing.items(), key=lambda x: -x[1])[:2]
        hints = {"verb": "start with an action verb", "scenario": "add 'Use when...' guidance",
                 "params": "document parameters", "examples": "add concrete examples"}
        for key, count in top_missing:
            if count > 0:
                recommendations.append(f"  {count}/{len(tool_scores)} tools: {hints[key]}")
    if security_score < 6.0:
        crit = [i for i in security_issues if i.severity == "critical"]
        if crit:
            categories = set(i.category for i in crit)
            recommendations.append(
                f"Run `spidershield harden` -- {len(crit)} critical: {', '.join(categories)}"
            )
        else:
            recommendations.append("Run `spidershield harden` to fix security issues")
    if len(tool_names) > 40:
        recommendations.append(
            f"Too many tools ({len(tool_names)}). Consider splitting into multiple servers"
        )
    if not has_tests:
        recommendations.append("Add automated tests for reliability")

    scan_duration_ms = int((_time.monotonic() - _scan_start) * 1000)

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
    # Attach scan metadata for dataset recording (not serialized in report)
    report._scan_duration_ms = scan_duration_ms
    report._pattern_set_hash = _compute_pattern_set_hash()
    return report


def run_scan(
    target: str, output_path: str | None = None, output_format: str = "table",
    tools_json: str | None = None,
):
    """Run a full scan on an MCP server."""
    # Use stderr for progress when outputting JSON to stdout
    log = stderr_console if (output_format == "json" and not output_path) else console
    log.print(f"\n[bold]Scanning:[/bold] {target}\n")

    log.print("[dim]Stage 1/4: License check...[/dim]")
    log.print("[dim]Stage 2/4: Security scan...[/dim]")
    log.print("[dim]Stage 3/4: Description quality...[/dim]")
    log.print("[dim]Stage 4/4: Architecture check...[/dim]")

    report = run_scan_report(target, tools_json=tools_json)

    # Record to local dataset (best-effort, never fails the scan)
    from spidershield.dataset.collector import record_scan
    record_scan(
        report,
        scoring_version="v2",
        pattern_set_hash=getattr(report, "_pattern_set_hash", None),
        scan_duration_ms=getattr(report, "_scan_duration_ms", None),
        source_type="local",
    )

    if output_format == "json" or output_path:
        json_str = report.model_dump_json(indent=2)
        if output_path:
            Path(output_path).write_text(json_str)
            console.print(f"\n[green]Report saved to {output_path}[/green]")
        else:
            print(json_str)
    else:
        _print_table(report)


def _score_color(score: float) -> str:
    """Return a Rich color tag for a numeric score."""
    if score >= 8.0:
        return "green"
    if score >= 5.0:
        return "yellow"
    return "red"


def _severity_color(severity: str) -> str:
    """Return a Rich color tag for a severity level."""
    colors = {
        "critical": "red bold", "high": "red",
        "medium": "yellow", "low": "dim",
    }
    return colors.get(severity, "dim")


def _print_table(report: ScanReport):
    """Print a rich table summary."""
    # --- Summary table ---
    table = Table(title=f"SpiderScore (local) - {report.target}")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_column("Score", justify="right")

    ok = "[green]OK[/green]"
    fail = "[red]FAIL[/red]"
    warn = "[yellow]WARN[/yellow]"
    table.add_row("License", report.license or "Unknown", ok if report.license_ok else fail)
    table.add_row("Tools", str(report.tool_count), warn if report.tool_count > 40 else ok)

    sc = _score_color(report.security_score)
    sec_val = f"{len(report.security_issues)} issues"
    table.add_row("Security", sec_val, f"[{sc}]{report.security_score}/10[/{sc}]")
    dc = _score_color(report.description_score)
    table.add_row("Descriptions", "", f"[{dc}]{report.description_score}/10[/{dc}]")
    ac = _score_color(report.architecture_score)
    table.add_row("Architecture", "", f"[{ac}]{report.architecture_score}/10[/{ac}]")
    table.add_row("Tests", "Yes" if report.has_tests else "No", ok if report.has_tests else fail)
    table.add_row("", "", "")

    oc = _score_color(report.overall_score)
    table.add_row(
        "[bold]SpiderScore[/bold]",
        f"Grade: [{oc}]{report.rating.value}[/{oc}] [dim](local)[/dim]",
        f"[bold {oc}]{report.overall_score}/10[/bold {oc}]",
    )

    console.print(table)

    # --- Per-tool description scores ---
    if report.tool_scores:
        tool_table = Table(title="Tool Description Quality")
        tool_table.add_column("Tool", style="bold")
        tool_table.add_column("Score", justify="right")
        tool_table.add_column("Verb")
        tool_table.add_column("Scenario")
        tool_table.add_column("Params")
        tool_table.add_column("Examples")
        tool_table.add_column("Errors")

        check = "[green]Y[/green]"
        cross = "[red]N[/red]"
        for ts in sorted(report.tool_scores, key=lambda s: s.overall_score):
            c = _score_color(ts.overall_score)
            tool_table.add_row(
                ts.tool_name,
                f"[{c}]{ts.overall_score}[/{c}]",
                check if ts.has_action_verb else cross,
                check if ts.has_scenario_trigger else cross,
                check if ts.has_param_docs else cross,
                check if ts.has_param_examples else cross,
                check if ts.has_error_guidance else cross,
            )
        console.print(tool_table)

    # --- Security issues ---
    if report.security_issues:
        console.print(f"\n[yellow]Security Issues ({len(report.security_issues)}):[/yellow]")
        for issue in report.security_issues[:15]:
            sc = _severity_color(issue.severity)
            console.print(
                f"  [{sc}]{issue.severity.upper():8s}[/{sc}] "
                f"{issue.category} -- {issue.file}:{issue.line}"
            )
            if issue.fix_suggestion:
                console.print(f"           [dim]Fix: {issue.fix_suggestion}[/dim]")

    # --- Recommendations ---
    if report.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            console.print(f"  > {rec}")

    console.print()
