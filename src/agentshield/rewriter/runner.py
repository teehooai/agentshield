"""Rewriter runner — transforms tool descriptions for LLM-optimized selection."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

console = Console()

REWRITE_SYSTEM_PROMPT = """\
You are an expert at writing MCP tool descriptions that help AI agents select the correct tool.

Given an original tool description, rewrite it following these rules:
1. ACTION-ORIENTED: Start with a verb (e.g., "Query", "Create", "List")
2. SCENARIO TRIGGER: Include "Use when the user wants to..." guidance
3. PARAMETER EXAMPLES: Add concrete examples for key parameters
4. ERROR GUIDANCE: Mention common errors and how to handle them
5. DISAMBIGUATION: If similar tools exist, explain when to use THIS one vs others
6. CONCISE: Keep under 200 words

Return ONLY the improved description text, nothing else.
"""


def run_rewrite(server_path: str, model: str = "claude-sonnet-4-20250514", dry_run: bool = False):
    """Rewrite tool descriptions in an MCP server."""
    path = Path(server_path)
    if not path.exists():
        console.print(f"[red]Path not found: {server_path}[/red]")
        raise SystemExit(1)

    console.print(f"\n[bold]Rewriting tool descriptions:[/bold] {server_path}")
    console.print(f"[dim]Model: {model} | Dry run: {dry_run}[/dim]\n")

    # Extract tools
    from agentshield.scanner.description_quality import _extract_tools

    tools = _extract_tools(path)
    if not tools:
        console.print("[yellow]No tools found in this server.[/yellow]")
        return

    console.print(f"Found {len(tools)} tools to rewrite:\n")

    for tool in tools:
        console.print(f"  [bold]{tool['name']}[/bold]")
        console.print(f"  [dim]Original:[/dim] {tool['description'][:100]}...")

        rewritten = _rewrite_description(tool, tools, model)
        if rewritten:
            console.print(f"  [green]Rewritten:[/green] {rewritten[:100]}...")
            if not dry_run:
                # TODO: Apply rewrite to source file
                console.print("  [yellow]→ File update not yet implemented[/yellow]")
        console.print()

    console.print("[green]Done.[/green] Run `agentshield eval` to measure improvement.\n")


def _rewrite_description(
    tool: dict, all_tools: list[dict], model: str
) -> str | None:
    """Rewrite a single tool description using an LLM."""
    try:
        import anthropic
    except ImportError:
        console.print(
            "[red]anthropic package not installed. Install with: pip install agentshield[ai][/red]"
        )
        return None

    other_tool_names = [t["name"] for t in all_tools if t["name"] != tool["name"]]

    user_prompt = f"""Tool name: {tool['name']}
Original description: {tool['description']}
Other tools in this server: {', '.join(other_tool_names)}

Rewrite the description following the rules."""

    client = anthropic.Anthropic()
    response = client.messages.create(
        model=model,
        max_tokens=500,
        system=REWRITE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    return response.content[0].text.strip()
