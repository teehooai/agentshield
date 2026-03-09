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
@click.option(
    "--format", "fmt",
    type=click.Choice(["table", "json", "sarif", "spiderrating"]),
    default="table",
)
@click.option("--tools-json", default=None, help="Pre-extracted tools JSON (MCP tools/list format)")
def scan(target: str, output: str | None, fmt: str, tools_json: str | None):
    """Scan an MCP server for security issues and description quality.

    TARGET can be a GitHub repo URL or a local directory path.

    Use --format spiderrating to output in SpiderRating-compatible JSON
    (description 35% + security 35% + metadata 30%, F/D/C/B/A grades).
    """
    if fmt == "sarif":
        from teeshield.agent.sarif import sarif_to_json, scan_report_to_sarif
        from teeshield.scanner.runner import run_scan_report

        report = run_scan_report(target, tools_json=tools_json)
        sarif = scan_report_to_sarif(report)
        sarif_json = sarif_to_json(sarif)
        if output:
            from pathlib import Path

            Path(output).write_text(sarif_json, encoding="utf-8")
            Console(stderr=True).print(f"[green]SARIF report written to {output}[/green]")
        else:
            console.print(sarif_json)
    elif fmt == "spiderrating":
        import json
        from pathlib import Path as SpiderPath

        from teeshield.scanner.runner import run_scan_report

        report = run_scan_report(target, tools_json=tools_json)
        report_dict = json.loads(report.model_dump_json())

        from teeshield.spiderrating import convert, parse_owner_repo

        try:
            owner, repo = parse_owner_repo(target)
        except ValueError:
            owner, repo = "local", SpiderPath(target).name

        result = convert(report_dict, owner, repo)
        json_str = json.dumps(result, indent=2)

        if output:
            SpiderPath(output).write_text(json_str, encoding="utf-8")
            Console(stderr=True).print(f"[green]SpiderRating JSON written to {output}[/green]")
        else:
            console.print(json_str)
    else:
        from teeshield.scanner.runner import run_scan

        run_scan(target, output_path=output, output_format=fmt, tools_json=tools_json)


@main.command()
@click.argument("server_path")
@click.option("--model", default=None, help="Model name (auto-detected per provider if not set)")
@click.option("--dry-run", is_flag=True, help="Preview changes without writing")
@click.option("--output", "-o", default=None, help="Save rewrites to JSON file")
@click.option(
    "--engine", type=click.Choice(["template", "llm", "auto"]), default="auto",
    help="Rewrite engine: template (free), llm (API key needed), auto (detect)",
)
@click.option(
    "--provider", "provider_name",
    type=click.Choice(["claude", "openai", "gemini"]),
    default=None, help="LLM provider (auto-detected from env vars if not set)",
)
@click.option("--tools-json", default=None, help="Pre-extracted tools JSON (MCP tools/list format)")
@click.option("--no-cache", "no_cache", is_flag=True, help="Skip LLM rewrite cache")
def rewrite(
    server_path: str,
    model: str | None,
    dry_run: bool,
    output: str | None,
    engine: str,
    provider_name: str | None,
    tools_json: str | None,
    no_cache: bool,
):
    """Rewrite tool descriptions for LLM-optimized selection.

    Transforms API-doc-style descriptions into action-oriented,
    scenario-triggered descriptions that agents can use effectively.

    Uses template-based rewriting by default. Set ANTHROPIC_API_KEY,
    OPENAI_API_KEY, or GEMINI_API_KEY for higher-quality LLM-powered rewrites.
    """
    from teeshield.rewriter.runner import run_rewrite

    run_rewrite(
        server_path,
        model=model or "claude-sonnet-4-20250514",
        dry_run=dry_run,
        output_path=output,
        engine=engine,
        provider_name=provider_name,
        tools_json=tools_json,
        use_cache=not no_cache,
    )


@main.command()
@click.argument("server_path")
@click.option("--read-only/--no-read-only", default=True, help="Enable read-only defaults")
@click.option("--truncate-limit", default=100, help="Max rows/items in tool responses")
@click.option(
    "--engine", type=click.Choice(["template", "llm", "auto"]), default="auto",
    help="Fix engine: template (free), llm (generates code fixes), auto (detect)",
)
@click.option(
    "--provider", "provider_name",
    type=click.Choice(["claude", "openai", "gemini"]),
    default=None, help="LLM provider (auto-detected from env vars if not set)",
)
def harden(
    server_path: str,
    read_only: bool,
    truncate_limit: int,
    engine: str,
    provider_name: str | None,
):
    """Suggest security hardening for an MCP server (advisory only).

    Scans for: insecure credential handling, missing input validation,
    unbounded query results, and write operations that should default
    to read-only. Prints suggestions but does not modify any files.

    With --engine llm, generates concrete code fix suggestions using
    an LLM with self-check validation.
    """
    from teeshield.hardener.runner import run_harden

    run_harden(
        server_path, read_only=read_only, truncate_limit=truncate_limit,
        engine=engine, provider_name=provider_name,
    )


@main.command(name="agent-check")
@click.argument("agent_dir", required=False, default=None)
@click.option("--skills/--no-skills", default=True, help="Include skill scanning")
@click.option("--verify", is_flag=True, help="Verify pinned skills (rug pull detection)")
@click.option("--fix", is_flag=True, help="Auto-fix fixable issues")
@click.option("--dry-run", is_flag=True, help="Preview fixes without applying")
@click.option(
    "--format", "fmt",
    type=click.Choice(["text", "json", "sarif", "spiderrating"]),
    default="text",
    help="Output format (spiderrating outputs SpiderRating-compatible JSON)",
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

    # Record to dataset (best-effort)
    from teeshield.dataset.collector import record_agent_scan
    record_agent_scan(result, policy=policy)

    if fix or dry_run:
        from teeshield.agent.fixer import fix_findings
        from teeshield.agent.report import print_fix_report
        fixes = fix_findings(result.findings, agent_path, dry_run=dry_run or not fix)
        if fmt == "text":
            print_fix_report(fixes)
        else:
            import json
            click.echo(json.dumps({"fixes": fixes}, indent=2))
        return

    if fmt == "text":
        from teeshield.agent.report import print_report
        print_report(result)
    elif fmt == "json":
        import dataclasses
        import json
        click.echo(json.dumps(dataclasses.asdict(result), indent=2))
    elif fmt == "sarif":
        from teeshield.agent.sarif import sarif_to_json, scan_result_to_sarif
        sarif = scan_result_to_sarif(result)
        click.echo(sarif_to_json(sarif))
    elif fmt == "spiderrating":
        import dataclasses
        import json

        from teeshield.spiderrating import convert_skill

        result_dict = dataclasses.asdict(result)

        # Read SKILL.md content for description scoring
        skill_content = ""
        effective_path = Path(agent_dir) if agent_dir else Path.home() / ".openclaw"
        for skill_dir in [effective_path / "skills", effective_path / "workspace" / "skills"]:
            if skill_dir.exists():
                for p in skill_dir.rglob("SKILL.md"):
                    try:
                        skill_content = p.read_text(encoding="utf-8")
                    except OSError:
                        pass
                    break

        # Try to extract owner/repo from agent_dir or first skill path
        owner, repo = "local", effective_path.name
        if result.skill_findings:
            skill_name = result.skill_findings[0].skill_name
        else:
            skill_name = repo

        sr = convert_skill(result_dict, skill_name, owner, repo, skill_content=skill_content)
        click.echo(json.dumps(sr, indent=2))

    # Exit codes based on policy
    from teeshield.agent.models import Severity, SkillVerdict
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

    from teeshield.agent.models import SkillVerdict
    from teeshield.agent.pinning import verify_all_skills

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


@main.group(name="dataset")
def dataset():
    """Manage the local security dataset."""


@dataset.command(name="stats")
def dataset_stats():
    """Show dataset statistics."""
    from teeshield.dataset.db import get_stats

    stats = get_stats()
    if not stats["db_exists"]:
        console.print(
            "[dim]No dataset yet. Run `teeshield scan`"
            " to start collecting data.[/dim]"
        )
        return

    console.print("\n[bold]TeeShield Security Dataset[/bold]")
    console.print(f"  Location: [dim]{stats['db_path']}[/dim]")
    console.print(f"  Size: {stats['db_size_kb']} KB\n")
    console.print(
        f"  Scans: {stats['total_scans']}"
        f" ({stats['unique_targets']} unique targets)"
    )
    console.print(f"  Security issues: {stats['total_issues']}")
    console.print(f"  Tool descriptions: {stats['total_descriptions']}")
    console.print(f"  Hardener fixes: {stats['total_fixes']}")
    if stats.get("total_agent_scans"):
        console.print(
            f"  Agent scans: {stats['total_agent_scans']}"
            f" ({stats['total_agent_findings']} findings)"
        )
    if stats.get("total_prs"):
        console.print(
            f"  Pull requests: {stats['total_prs']}"
            f" ({stats['pr_tools_changed']} tools changed)"
        )

    if stats.get("pr_status_distribution"):
        console.print("\n  [bold]PR status:[/bold]")
        status_colors = {
            "open": "yellow", "merged": "green",
            "closed": "red", "rejected": "red",
        }
        for st, count in stats["pr_status_distribution"].items():
            c = status_colors.get(st, "dim")
            console.print(f"    [{c}]{st}[/{c}]: {count}")

    if stats.get("rating_distribution"):
        console.print("\n  [bold]Rating distribution:[/bold]")
        for rating, count in stats["rating_distribution"].items():
            console.print(f"    {rating}: {count}")

    if stats.get("top_issue_categories"):
        console.print("\n  [bold]Top issue categories:[/bold]")
        for cat in stats["top_issue_categories"]:
            console.print(f"    {cat['category']}: {cat['count']}")

    console.print()


@dataset.command(name="export")
@click.argument("output_path")
@click.option(
    "--format", "fmt",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Export format",
)
def dataset_export(output_path: str, fmt: str):
    """Export dataset to JSON or CSV."""
    import json
    from pathlib import Path

    from teeshield.dataset.db import DEFAULT_DB_PATH, get_connection

    if not DEFAULT_DB_PATH.exists():
        console.print("[red]No dataset found. Run scans first.[/red]")
        raise SystemExit(1)

    with get_connection() as conn:
        scans = [
            dict(r) for r in conn.execute("SELECT * FROM scans").fetchall()
        ]
        issues = [
            dict(r)
            for r in conn.execute("SELECT * FROM security_issues").fetchall()
        ]
        descriptions = [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM tool_descriptions"
            ).fetchall()
        ]
        fixes = [
            dict(r)
            for r in conn.execute("SELECT * FROM hardener_fixes").fetchall()
        ]
        prs = [
            dict(r)
            for r in conn.execute("SELECT * FROM pull_requests").fetchall()
        ]
        agent_scans_data = [
            dict(r)
            for r in conn.execute("SELECT * FROM agent_scans").fetchall()
        ]
        agent_findings_data = [
            dict(r)
            for r in conn.execute("SELECT * FROM agent_findings").fetchall()
        ]

    if fmt == "json":
        data = {
            "version": 3,
            "scans": scans,
            "security_issues": issues,
            "tool_descriptions": descriptions,
            "hardener_fixes": fixes,
            "pull_requests": prs,
            "agent_scans": agent_scans_data,
            "agent_findings": agent_findings_data,
        }
        Path(output_path).write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8",
        )
    elif fmt == "csv":
        import csv

        if scans:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=scans[0].keys())
                writer.writeheader()
                writer.writerows(scans)

    console.print(f"[green]Dataset exported to {output_path}[/green]")


@dataset.command(name="reset")
@click.confirmation_option(
    prompt="This will delete all collected data. Are you sure?",
)
def dataset_reset():
    """Delete all collected dataset data."""
    from teeshield.dataset.db import DEFAULT_DB_PATH

    if DEFAULT_DB_PATH.exists():
        DEFAULT_DB_PATH.unlink()
        console.print("[green]Dataset reset.[/green]")
    else:
        console.print("[dim]No dataset to reset.[/dim]")


@dataset.command(name="pr-add")
@click.argument("repo")
@click.argument("pr_number", type=int)
@click.option("--title", "-t", required=True, help="PR title")
@click.option(
    "--status", "-s",
    type=click.Choice(["open", "merged", "closed", "rejected"]),
    default="open",
)
@click.option("--strategy", default=None, help="PR strategy (hand-crafted, template)")
@click.option("--tools", "tools_changed", type=int, default=0, help="Tools changed")
@click.option("--engine", default=None, help="Engine used (template/llm)")
@click.option("--date", "submitted_at", default=None, help="Submit date (YYYY-MM-DD)")
@click.option("--notes", default=None, help="Additional notes")
@click.option("--rejection-reason", default=None, help="Why rejected/closed")
def dataset_pr_add(
    repo: str,
    pr_number: int,
    title: str,
    status: str,
    strategy: str | None,
    tools_changed: int,
    engine: str | None,
    submitted_at: str | None,
    notes: str | None,
    rejection_reason: str | None,
):
    """Add or update a PR in the dataset."""
    from teeshield.dataset.collector import record_pr

    merged_at = submitted_at if status == "merged" else None
    closed_at = submitted_at if status in ("closed", "rejected") else None

    pr_id = record_pr(
        repo=repo,
        pr_number=pr_number,
        title=title,
        status=status,
        strategy=strategy,
        tools_changed=tools_changed,
        engine=engine,
        submitted_at=submitted_at,
        merged_at=merged_at,
        closed_at=closed_at,
        rejection_reason=rejection_reason,
        notes=notes,
    )
    if pr_id:
        console.print(
            f"[green]Recorded:[/green] {repo}#{pr_number}"
            f" [{status}]"
        )
    else:
        console.print("[red]Failed to record PR.[/red]")


@dataset.command(name="pr-list")
@click.option(
    "--status", "-s",
    type=click.Choice(["open", "merged", "closed", "rejected"]),
    default=None,
    help="Filter by status",
)
def dataset_pr_list(status: str | None):
    """List tracked PRs."""
    from rich.table import Table

    from teeshield.dataset.collector import get_prs

    prs = get_prs(status=status)
    if not prs:
        console.print("[dim]No PRs tracked yet.[/dim]")
        return

    table = Table(title="Tracked Pull Requests")
    table.add_column("Repo", style="bold")
    table.add_column("#", justify="right")
    table.add_column("Title", width=40)
    table.add_column("Status")
    table.add_column("Tools")
    table.add_column("Strategy")
    table.add_column("Date")

    status_colors = {
        "open": "yellow", "merged": "green",
        "closed": "red", "rejected": "red",
    }
    for pr in prs:
        c = status_colors.get(pr["status"], "dim")
        date = (pr.get("submitted_at") or "")[:10]
        table.add_row(
            pr["repo"],
            str(pr["pr_number"]),
            pr["title"][:40],
            f"[{c}]{pr['status']}[/{c}]",
            str(pr["tools_changed"]),
            pr.get("strategy") or "-",
            date,
        )

    console.print(table)


@main.command(name="eval")
@click.argument("original")
@click.argument("improved")
@click.option("--scenarios", "-s", default=None, help="Path to test scenarios YAML")
@click.option("--models", "-m", multiple=True, default=["claude-sonnet-4-20250514"])
@click.option("--llm", is_flag=True, help="Use LLM for evaluation (requires ANTHROPIC_API_KEY)")
@click.option(
    "--tools-json", default=None,
    help="Pre-extracted tools JSON (overrides source extraction)",
)
def evaluate(
    original: str, improved: str, scenarios: str | None,
    models: tuple[str, ...], llm: bool, tools_json: str | None,
):
    """Compare tool selection accuracy before and after improvements.

    Uses heuristic keyword matching by default (free, no API key needed).
    Add --llm to use Claude for higher-quality evaluation.
    """
    from teeshield.evaluator.runner import run_eval

    run_eval(
        original, improved, scenarios_path=scenarios,
        models=list(models), use_llm=llm, tools_json=tools_json,
    )
