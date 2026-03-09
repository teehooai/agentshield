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
@click.option("--output", "-o", default=None, help="Output report path (JSON/SARIF)")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "sarif"]), default="table")
def scan(target: str, output: str | None, fmt: str):
    """Scan an MCP server for security issues and description quality.

    TARGET can be a GitHub repo URL or a local directory path.
    """
    if fmt == "sarif":
        from teeshield.agent.sarif import sarif_to_json, scan_report_to_sarif
        from teeshield.scanner.runner import run_scan_report

        report = run_scan_report(target)
        sarif = scan_report_to_sarif(report)
        sarif_json = sarif_to_json(sarif)
        if output:
            from pathlib import Path

            Path(output).write_text(sarif_json, encoding="utf-8")
            Console(stderr=True).print(f"[green]SARIF report written to {output}[/green]")
        else:
            console.print(sarif_json)
    else:
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
def harden(server_path: str, read_only: bool, truncate_limit: int):
    """Suggest security hardening for an MCP server (advisory only).

    Scans for: insecure credential handling, missing input validation,
    unbounded query results, and write operations that should default
    to read-only. Prints suggestions but does not modify any files.
    """
    from teeshield.hardener.runner import run_harden

    run_harden(server_path, read_only=read_only, truncate_limit=truncate_limit)


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
@click.option(
    "--ignore", "ignore_codes", multiple=True,
    help="Issue codes or pattern names to ignore (e.g. TS-W001, typosquat)",
)
@click.option(
    "--policy", "policy",
    type=click.Choice(["strict", "balanced", "permissive"]),
    default=None,
    help="Scan policy preset (strict=all, balanced=default, permissive=errors only)",
)
@click.option(
    "--allowlist", "allowlist_path",
    default=None,
    help="Path to approved skills JSON (skills not listed get TS-W011)",
)
def agent_check(
    agent_dir: str | None,
    skills: bool,
    verify: bool,
    fix: bool,
    dry_run: bool,
    fmt: str,
    ignore_codes: tuple[str, ...],
    policy: str | None,
    allowlist_path: str | None,
):
    """Scan an AI agent installation for security issues.

    Checks agent config, installed skills for malicious patterns,
    and optionally verifies pinned skills for rug pull detection.

    AGENT_DIR defaults to ~/.openclaw if not specified.
    """
    from pathlib import Path

    from teeshield.agent.issue_codes import resolve_codes
    from teeshield.agent.scanner import scan_config
    from teeshield.agent.skill_scanner import scan_skills

    # Resolve --ignore codes
    ignored = resolve_codes(list(ignore_codes)) if ignore_codes else set()

    # Apply policy preset (permissive ignores all warnings)
    if policy == "permissive":
        from teeshield.agent.issue_codes import SKILL_WARNING_CODES
        ignored |= set(SKILL_WARNING_CODES.keys())

    agent_path = Path(agent_dir) if agent_dir else None
    result = scan_config(agent_path, ignore_patterns=ignored)

    if skills:
        result.skill_findings.extend(scan_skills(agent_path, ignore_patterns=ignored))

    if verify:
        from teeshield.agent.pinning import verify_all_skills
        pin_findings = verify_all_skills(agent_path)
        result.skill_findings.extend(pin_findings)

    if allowlist_path and "not_in_allowlist" not in ignored:
        from teeshield.agent.allowlist import check_allowlist, load_allowlist
        allowlist = load_allowlist(Path(allowlist_path))
        installed_names = [sf.skill_name for sf in result.skill_findings]
        result.skill_findings.extend(check_allowlist(installed_names, allowlist))

    # Populate audit framework coverage
    result.audit_framework.source_checked = verify or allowlist_path is not None
    result.audit_framework.code_checked = skills
    result.audit_framework.permission_checked = True  # config scanner always checks
    result.audit_framework.risk_checked = True  # verdict/severity always computed

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

    # Exit codes based on policy
    from teeshield.agent.models import SkillVerdict, Severity
    if any(sf.verdict == SkillVerdict.TAMPERED for sf in result.skill_findings):
        raise SystemExit(2)
    if any(f.severity == Severity.CRITICAL for f in result.findings):
        raise SystemExit(1)
    if any(sf.verdict == SkillVerdict.MALICIOUS for sf in result.skill_findings):
        raise SystemExit(1)
    # Strict: exit 1 on any finding (HIGH, MEDIUM, LOW, suspicious)
    if policy == "strict":
        if result.findings or any(
            sf.verdict == SkillVerdict.SUSPICIOUS for sf in result.skill_findings
        ):
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
@click.option("--llm", is_flag=True, help="Use LLM for evaluation (requires ANTHROPIC_API_KEY)")
def evaluate(original: str, improved: str, scenarios: str | None, models: tuple[str, ...], llm: bool):
    """Compare tool selection accuracy before and after improvements.

    Uses heuristic keyword matching by default (free, no API key needed).
    Add --llm to use Claude for higher-quality evaluation.
    """
    from teeshield.evaluator.runner import run_eval

    run_eval(original, improved, scenarios_path=scenarios, models=list(models), use_llm=llm)
