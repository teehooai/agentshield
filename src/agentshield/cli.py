"""AgentShield CLI — four core commands."""

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option()
def main():
    """AgentShield — Scan, improve, and certify MCP servers."""


@main.command()
@click.argument("target")
@click.option("--output", "-o", default=None, help="Output report path (JSON)")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
def scan(target: str, output: str | None, fmt: str):
    """Scan an MCP server for security issues and description quality.

    TARGET can be a GitHub repo URL or a local directory path.
    """
    from agentshield.scanner.runner import run_scan

    run_scan(target, output_path=output, output_format=fmt)


@main.command()
@click.argument("server_path")
@click.option("--model", default="claude-sonnet-4-20250514", help="Model for rewriting")
@click.option("--dry-run", is_flag=True, help="Preview changes without writing")
def rewrite(server_path: str, model: str, dry_run: bool):
    """Rewrite tool descriptions for LLM-optimized selection.

    Transforms API-doc-style descriptions into action-oriented,
    scenario-triggered descriptions that agents can use effectively.
    """
    from agentshield.rewriter.runner import run_rewrite

    run_rewrite(server_path, model=model, dry_run=dry_run)


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
    from agentshield.hardener.runner import run_harden

    run_harden(server_path, read_only=read_only, truncate_limit=truncate_limit, dry_run=dry_run)


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
    from agentshield.evaluator.runner import run_eval

    run_eval(original, improved, scenarios_path=scenarios, models=list(models))
