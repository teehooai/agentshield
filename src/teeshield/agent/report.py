"""Rich terminal report for agent security scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import ScanResult, Severity, SkillFinding, SkillVerdict

console = Console()

SEVERITY_STYLES = {
    Severity.CRITICAL: ("bold red", "CRITICAL"),
    Severity.HIGH: ("bold yellow", "HIGH"),
    Severity.MEDIUM: ("yellow", "MEDIUM"),
    Severity.LOW: ("dim", "LOW"),
    Severity.OK: ("green", "OK"),
}

VERDICT_STYLES = {
    SkillVerdict.MALICIOUS: ("bold red", "MALICIOUS"),
    SkillVerdict.SUSPICIOUS: ("bold yellow", "SUSPICIOUS"),
    SkillVerdict.SAFE: ("green", "SAFE"),
    SkillVerdict.UNKNOWN: ("dim", "UNKNOWN"),
}


def print_report(result: ScanResult) -> None:
    """Print the full security scan report."""
    console.print()
    console.print(
        Panel.fit(
            "[bold]TeeShield Agent Security Check[/bold]",
            subtitle=f"Config: {result.config_path}",
        )
    )
    console.print()

    # Config findings
    if result.findings:
        _print_config_findings(result)
    else:
        console.print("[green]No configuration issues found.[/green]")
        console.print()

    # Skill findings
    if result.skill_findings:
        _print_skill_findings(result.skill_findings)

    # Summary
    _print_summary(result)


def _print_config_findings(result: ScanResult) -> None:
    """Print config security findings."""
    table = Table(title="Configuration Security Checks", show_lines=True)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Check", width=30)
    table.add_column("Details", width=50)
    table.add_column("Fix", width=6, justify="center")

    for f in sorted(result.findings, key=lambda x: list(Severity).index(x.severity)):
        style, label = SEVERITY_STYLES[f.severity]
        severity_text = Text(label, style=style)
        details = f.description
        if f.fix_hint:
            details += f"\n[dim]{f.fix_hint}[/dim]"
        fix_icon = "[green]AUTO[/green]" if f.auto_fixable else ""
        table.add_row(severity_text, f.title, details, fix_icon)

    console.print(table)
    console.print()


def _print_skill_findings(skill_findings: list[SkillFinding]) -> None:
    """Print skill scan findings."""
    table = Table(title="Skill Security Scan", show_lines=True)
    table.add_column("Verdict", width=12, justify="center")
    table.add_column("Skill", width=25)
    table.add_column("Issues", width=55)

    for sf in sorted(
        skill_findings,
        key=lambda x: list(SkillVerdict).index(x.verdict),
    ):
        style, label = VERDICT_STYLES[sf.verdict]
        verdict_text = Text(label, style=style)
        issues_text = "\n".join(sf.issues) if sf.issues else "No issues"
        table.add_row(verdict_text, sf.skill_name, issues_text)

    console.print(table)
    console.print()


def _print_summary(result: ScanResult) -> None:
    """Print overall score and summary."""
    score = result.score

    if score >= 8:
        score_style = "bold green"
        grade = "Good"
    elif score >= 5:
        score_style = "bold yellow"
        grade = "Needs Attention"
    else:
        score_style = "bold red"
        grade = "Dangerous"

    malicious = sum(1 for s in result.skill_findings if s.verdict == SkillVerdict.MALICIOUS)
    suspicious = sum(1 for s in result.skill_findings if s.verdict == SkillVerdict.SUSPICIOUS)
    safe = sum(1 for s in result.skill_findings if s.verdict == SkillVerdict.SAFE)

    summary_parts = [f"[{score_style}]Score: {score}/10 ({grade})[/{score_style}]"]

    if result.findings:
        summary_parts.append(
            f"Config: {result.critical_count} critical, {result.high_count} high"
        )

    if result.skill_findings:
        summary_parts.append(
            f"Skills: {safe} safe, {suspicious} suspicious, {malicious} malicious"
        )

    fixable = sum(1 for f in result.findings if f.auto_fixable)
    if fixable:
        summary_parts.append(
            f"\n[dim]Run [bold]teeshield agent-check --fix[/bold] to auto-fix "
            f"{fixable} issue(s)[/dim]"
        )

    console.print(Panel("\n".join(summary_parts), title="Summary"))
    console.print()


def print_fix_report(fixes: list[str]) -> None:
    """Print auto-fix results."""
    console.print()
    console.print(Panel.fit("[bold]TeeShield Auto-Fix Results[/bold]"))
    console.print()

    for fix in fixes:
        if fix.startswith("[DRY RUN]"):
            console.print(f"  [dim]{fix}[/dim]")
        elif "Failed" in fix or "Cannot" in fix:
            console.print(f"  [red]x {fix}[/red]")
        else:
            console.print(f"  [green]+ {fix}[/green]")

    console.print()
