"""TeeShield CLI -- four core commands."""

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option()
def main():
    """TeeShield -- Scan, improve, and certify MCP servers."""


@main.command()
@click.argument("target")
@click.option("--output", "-o", default=None, help="Output report path (JSON)")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def scan(target: str, output: str | None, fmt: str):
    """Scan an MCP server for security issues and description quality.

    TARGET can be a GitHub repo URL or a local directory path.
    """
    from teeshield.scanner.runner import run_scan

    run_scan(target, output_path=output, output_format=fmt)


@main.command()
@click.argument("server_path")
@click.option("--model", default="claude-sonnet-4-20250514", help="Model for rewriting (if API key set)")
@click.option("--dry-run", is_flag=True, help="Preview changes without writing")
@click.option("--output", "-o", default=None, help="Save rewrites to JSON file")
def rewrite(server_path: str, model: str, dry_run: bool, output: str | None):
    """Rewrite tool descriptions for LLM-optimized selection.

    Transforms API-doc-style descriptions into action-oriented,
    scenario-triggered descriptions that agents can use effectively.

    Uses template-based rewriting by default. Set ANTHROPIC_API_KEY
    for higher-quality LLM-powered rewrites.
    """
    from teeshield.rewriter.runner import run_rewrite

    run_rewrite(server_path, model=model, dry_run=dry_run, output_path=output)


@main.command()
@click.argument("server_path")
@click.option("--read-only/--no-read-only", default=True, help="Enable read-only defaults")
@click.option("--truncate-limit", default=100, help="Max rows/items in tool responses")
@click.option("--dry-run", is_flag=True, help="Preview changes without writing")
def harden(server_path: str, read_only: bool, truncate_limit: int, dry_run: bool):
    """Apply security hardening to an MCP server.

    Fixes: credential wrapping, input validation, result truncation,
    read-only defaults, path traversal protection.
    """
    from teeshield.hardener.runner import run_harden

    run_harden(server_path, read_only=read_only, truncate_limit=truncate_limit, dry_run=dry_run)


@main.command(name="agent-check")
@click.argument("agent_dir", required=False, default=None)
@click.option("--skills/--no-skills", default=True, help="Include skill scanning")
@click.option("--verify", is_flag=True, help="Verify pinned skills (rug pull detection)")
@click.option("--fix", is_flag=True, help="Auto-fix fixable issues")
@click.option("--dry-run", is_flag=True, help="Preview fixes without applying")
@click.option(
    "--format", "fmt",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    help="Output format",
)
def agent_check(
    agent_dir: str | None,
    skills: bool,
    verify: bool,
    fix: bool,
    dry_run: bool,
    fmt: str,
):
    """Scan an AI agent installation for security issues.

    Checks agent config, installed skills for malicious patterns,
    and optionally verifies pinned skills for rug pull detection.

    AGENT_DIR defaults to ~/.openclaw if not specified.
    """
    from pathlib import Path

    from teeshield.agent.scanner import scan_config
    from teeshield.agent.skill_scanner import scan_skills

    agent_path = Path(agent_dir) if agent_dir else None
    result = scan_config(agent_path)

    if skills:
        result.skill_findings.extend(scan_skills(agent_path))

    if verify:
        from teeshield.agent.pinning import verify_all_skills
        pin_findings = verify_all_skills(agent_path)
        result.skill_findings.extend(pin_findings)

    if fix or dry_run:
        from teeshield.agent.fixer import fix_findings
        from teeshield.agent.report import print_fix_report
        fixes = fix_findings(result.findings, agent_path, dry_run=dry_run or not fix)
        if fmt == "text":
            print_fix_report(fixes)
        else:
            import json
            console.print(json.dumps({"fixes": fixes}, indent=2))
        return

    if fmt == "text":
        from teeshield.agent.report import print_report
        print_report(result)
    elif fmt == "json":
        import json
        import dataclasses
        console.print(json.dumps(dataclasses.asdict(result), indent=2))
    elif fmt == "sarif":
        from teeshield.agent.sarif import sarif_to_json, scan_result_to_sarif
        sarif = scan_result_to_sarif(result)
        console.print(sarif_to_json(sarif))

    # Exit code: 2 if tampered, 1 if critical/malicious, 0 otherwise
    from teeshield.agent.models import SkillVerdict, Severity
    if any(sf.verdict == SkillVerdict.TAMPERED for sf in result.skill_findings):
        raise SystemExit(2)
    if any(f.severity == Severity.CRITICAL for f in result.findings):
        raise SystemExit(1)
    if any(sf.verdict == SkillVerdict.MALICIOUS for sf in result.skill_findings):
        raise SystemExit(1)


@main.group(name="agent-pin")
def agent_pin():
    """Manage skill pins for rug pull detection."""


@agent_pin.command(name="add")
@click.argument("skill_path")
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_add(skill_path: str, pin_dir: str | None):
    """Pin a single skill by recording its content hash."""
    from pathlib import Path
    from teeshield.agent.pinning import pin_skill

    pin_path = Path(pin_dir) if pin_dir else None
    result = pin_skill(Path(skill_path), pin_path)
    console.print(f"[green]Pinned:[/green] {result['skill_name']} ({result['hash'][:16]}...)")


@agent_pin.command(name="add-all")
@click.argument("agent_dir", required=False, default=None)
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_add_all(agent_dir: str | None, pin_dir: str | None):
    """Pin all installed skills."""
    from pathlib import Path
    from teeshield.agent.pinning import pin_all_skills

    agent_path = Path(agent_dir) if agent_dir else None
    pin_path = Path(pin_dir) if pin_dir else None
    results = pin_all_skills(agent_path, pin_path)
    for r in results:
        console.print(f"[green]Pinned:[/green] {r['skill_name']} ({r['hash'][:16]}...)")
    console.print(f"\n{len(results)} skill(s) pinned.")


@agent_pin.command(name="list")
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_list(pin_dir: str | None):
    """List all pinned skills."""
    from pathlib import Path
    from teeshield.agent.pinning import list_pins

    pin_path = Path(pin_dir) if pin_dir else None
    pins = list_pins(pin_path)
    if not pins:
        console.print("[dim]No skills pinned yet.[/dim]")
        return
    for name, data in pins.items():
        console.print(f"  {name}: {data['hash'][:16]}... (pinned {data.get('pinned_at', '?')})")


@agent_pin.command(name="verify")
@click.argument("agent_dir", required=False, default=None)
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_verify(agent_dir: str | None, pin_dir: str | None):
    """Verify all pinned skills against their recorded hashes."""
    from pathlib import Path
    from teeshield.agent.pinning import verify_all_skills
    from teeshield.agent.models import SkillVerdict

    agent_path = Path(agent_dir) if agent_dir else None
    pin_path = Path(pin_dir) if pin_dir else None
    findings = verify_all_skills(agent_path, pin_path)

    if not findings:
        console.print("[dim]No pins to verify.[/dim]")
        return

    tampered = False
    for f in findings:
        if f.verdict == SkillVerdict.SAFE:
            console.print(f"  [green]OK[/green] {f.skill_name}")
        elif f.verdict == SkillVerdict.TAMPERED:
            console.print(f"  [bold red]TAMPERED[/bold red] {f.skill_name}")
            for issue in f.issues:
                console.print(f"    {issue}")
            tampered = True
        else:
            console.print(f"  [dim]UNKNOWN[/dim] {f.skill_name}")
            for issue in f.issues:
                console.print(f"    {issue}")

    if tampered:
        raise SystemExit(2)


@agent_pin.command(name="remove")
@click.argument("skill_name")
@click.option("--pin-dir", default=None, help="Pin storage directory")
def pin_remove(skill_name: str, pin_dir: str | None):
    """Remove a skill's pin."""
    from pathlib import Path
    from teeshield.agent.pinning import unpin_skill

    pin_path = Path(pin_dir) if pin_dir else None
    if unpin_skill(skill_name, pin_path):
        console.print(f"[green]Unpinned:[/green] {skill_name}")
    else:
        console.print(f"[yellow]Not found:[/yellow] {skill_name}")


@main.command(name="eval")
@click.argument("original")
@click.argument("improved")
@click.option("--scenarios", "-s", default=None, help="Path to test scenarios YAML")
@click.option("--models", "-m", multiple=True, default=["claude-sonnet-4-20250514"])
def evaluate(original: str, improved: str, scenarios: str | None, models: tuple[str, ...]):
    """Compare tool selection accuracy before and after improvements.

    Runs LLM compatibility tests against ORIGINAL and IMPROVED servers,
    producing a before/after comparison report.
    """
    from teeshield.evaluator.runner import run_eval

    run_eval(original, improved, scenarios_path=scenarios, models=list(models))
