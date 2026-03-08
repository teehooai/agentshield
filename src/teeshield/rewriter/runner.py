"""Rewriter runner — transforms tool descriptions for LLM-optimized selection."""

from __future__ import annotations

import json
import re
from pathlib import Path

from rich.console import Console
from rich.table import Table

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

# Template-based rewriting rules (no API needed)
VERB_MAP = {
    "read": "Read",
    "write": "Write",
    "create": "Create",
    "delete": "Delete",
    "remove": "Remove",
    "list": "List",
    "get": "Retrieve",
    "set": "Set",
    "update": "Update",
    "search": "Search",
    "find": "Find",
    "query": "Query",
    "execute": "Execute",
    "run": "Run",
    "show": "Show",
    "diff": "Compare",
    "add": "Add",
    "move": "Move",
    "copy": "Copy",
    "rename": "Rename",
    "edit": "Edit",
    "fetch": "Fetch",
    "checkout": "Switch",
    "commit": "Commit",
    "reset": "Reset",
    "log": "Show",
    "status": "Show",
}

# Scenario triggers based on tool name patterns
SCENARIO_TRIGGERS = {
    "read": "Use when the user needs to examine file contents or retrieve stored data.",
    "write": "Use when the user wants to create or overwrite a file with new content.",
    "create": "Use when the user wants to create a new resource that does not yet exist.",
    "delete": "Use when the user wants to permanently remove a resource.",
    "list": "Use when the user wants to see all available items in a collection or directory.",
    "search": "Use when the user wants to find items matching specific criteria or patterns.",
    "get": "Use when the user needs to retrieve a specific resource by identifier.",
    "edit": "Use when the user wants to modify part of an existing file without rewriting it entirely.",
    "move": "Use when the user wants to relocate or rename a file or resource.",
    "diff": "Use when the user wants to see what changed between two versions.",
    "add": "Use when the user wants to stage changes or append to an existing collection.",
    "commit": "Use when the user wants to save staged changes as a permanent snapshot.",
    "checkout": "Use when the user wants to switch to a different branch or restore files.",
    "log": "Use when the user wants to review history or past activity.",
    "status": "Use when the user wants to check the current state of the working environment.",
    "fetch": "Use when the user wants to retrieve content from a URL or remote source.",
    "query": "Use when the user wants to extract specific data using a structured query.",
    "reset": "Use when the user wants to undo staged changes or restore to a previous state.",
}

# Error guidance based on tool category
ERROR_GUIDANCE = {
    "file": "If the path does not exist, verify the path is within allowed directories. Check file permissions if access is denied.",
    "directory": "If the directory does not exist, create it first or check the path for typos.",
    "git": "If the operation fails, ensure you are inside a valid git repository and the working tree is clean.",
    "network": "If the request fails, check the URL is reachable and properly formatted. Timeouts may occur for large pages.",
    "database": "If the query fails, verify table and column names. Check connection settings if the database is unreachable.",
    "search": "If no results are found, try broader search terms or check that the target path exists.",
}


def _infer_category(name: str, desc: str) -> str:
    """Infer the tool category from its name and description."""
    text = f"{name} {desc}".lower()
    if any(w in text for w in ["file", "read", "write", "path", "content"]):
        return "file"
    if any(w in text for w in ["directory", "dir", "folder", "tree"]):
        return "directory"
    if any(w in text for w in ["git", "commit", "branch", "diff", "staged"]):
        return "git"
    if any(w in text for w in ["fetch", "url", "http", "request", "network"]):
        return "network"
    if any(w in text for w in ["query", "sql", "database", "table"]):
        return "database"
    if any(w in text for w in ["search", "find", "grep", "pattern"]):
        return "search"
    return "file"


def _find_similar_tools(name: str, all_tools: list[dict]) -> list[str]:
    """Find tools with similar names for disambiguation."""
    name_words = set(name.lower().replace("_", " ").split())
    similar = []
    for t in all_tools:
        if t["name"] == name:
            continue
        other_words = set(t["name"].lower().replace("_", " ").split())
        overlap = name_words & other_words
        if overlap:
            similar.append(t["name"])
    return similar


def _rewrite_local(tool: dict, all_tools: list[dict]) -> str:
    """Rewrite a tool description using template-based rules (no API needed)."""
    name = tool["name"]
    desc = tool.get("description", "")
    name_lower = name.lower()

    # 1. Build action-oriented opening
    first_word = name_lower.split("_")[0] if "_" in name_lower else name_lower
    verb = VERB_MAP.get(first_word, desc.split()[0] if desc else "Perform")

    # Clean up original description — strip any leading verb so we don't double-prefix
    clean_desc = desc.strip().rstrip(".")
    # Remove leading adverb + verb phrase (e.g. "Recursively search for..." -> "for files...")
    leading_verb = re.match(
        r'^(?:(?:Recursively|Safely|Securely|Efficiently)\s+)?'
        r'(?:Get|Show|List|Read|Write|Create|Delete|Move|Search|Find|Retrieve|'
        r'Execute|Run|Make|Return|Record|Unstage|Switch|Add|Fetch|Compare|Commit|'
        r'Reset|Edit|Copy|Rename)(?:s|es|ed|ing)?\s+',
        clean_desc, re.IGNORECASE
    )
    if leading_verb:
        clean_desc = clean_desc[leading_verb.end():]

    opening = f"{verb} {clean_desc}." if clean_desc else f"{verb} the {name.replace('_', ' ')} operation."

    # 2. Add scenario trigger
    scenario = ""
    for key, trigger in SCENARIO_TRIGGERS.items():
        if key in name_lower:
            scenario = trigger
            break
    if not scenario:
        scenario = f"Use when the user wants to {name.replace('_', ' ')}."

    # 3. Add disambiguation
    similar = _find_similar_tools(name, all_tools)
    disambig = ""
    if similar:
        disambig = f" Unlike {', '.join(similar[:2])}, this tool specifically handles {name.replace('_', ' ')}."

    # 4. Add error guidance
    category = _infer_category(name, desc)
    error = ERROR_GUIDANCE.get(category, "")

    # 5. Compose final description
    parts = [opening, scenario]
    if disambig:
        parts.append(disambig.strip())
    if error:
        parts.append(error)

    return " ".join(parts)


def run_rewrite(
    server_path: str,
    model: str = "claude-sonnet-4-20250514",
    dry_run: bool = False,
    output_path: str | None = None,
):
    """Rewrite tool descriptions in an MCP server."""
    path = Path(server_path)
    if not path.exists():
        console.print(f"[red]Path not found: {server_path}[/red]")
        raise SystemExit(1)

    # Extract tools
    from teeshield.scanner.description_quality import _extract_tools

    tools = _extract_tools(path)
    if not tools:
        console.print("[yellow]No tools found in this server.[/yellow]")
        return

    # Decide rewrite engine
    use_llm = _has_anthropic_key()
    engine = "Claude API" if use_llm else "template-based"

    console.print(f"\n[bold]Rewriting tool descriptions:[/bold] {server_path}")
    console.print(f"[dim]Engine: {engine} | Dry run: {dry_run}[/dim]")
    console.print(f"Found {len(tools)} tools to rewrite.\n")

    results = []
    for tool in tools:
        original = tool["description"]

        if use_llm:
            rewritten = _rewrite_llm(tool, tools, model)
        else:
            rewritten = _rewrite_local(tool, tools)

        results.append({
            "name": tool["name"],
            "original": original,
            "rewritten": rewritten,
        })

    # Print comparison table
    _print_comparison(results)

    # Output JSON if requested
    if output_path:
        Path(output_path).write_text(json.dumps(results, indent=2))
        console.print(f"\n[green]Rewrites saved to {output_path}[/green]")

    # Apply rewrites to source files
    if not dry_run:
        applied = _apply_rewrites(path, results)
        if applied:
            console.print(f"\n[green]Applied {applied} rewrites to source files.[/green]")
        else:
            console.print("\n[yellow]No rewrites could be applied to source files.[/yellow]")
    else:
        console.print("\n[dim]Dry run -- no files modified. Remove --dry-run to apply.[/dim]")

    if not use_llm:
        console.print("[dim]Tip: Set ANTHROPIC_API_KEY for higher-quality LLM-powered rewrites.[/dim]")

    console.print()


def _print_comparison(results: list[dict]):
    """Print a before/after comparison table."""
    from teeshield.scanner.description_quality import score_descriptions
    from teeshield.models import ToolDescriptionScore

    table = Table(title="Description Rewrite Results", show_lines=True)
    table.add_column("Tool", style="bold", width=20)
    table.add_column("Original", width=40)
    table.add_column("Rewritten", width=50)

    for r in results:
        orig_preview = r["original"][:80] + "..." if len(r["original"]) > 80 else r["original"]
        new_preview = r["rewritten"][:80] + "..." if len(r["rewritten"]) > 80 else r["rewritten"]
        table.add_row(r["name"], f"[dim]{orig_preview}[/dim]", f"[green]{new_preview}[/green]")

    console.print(table)

    # Score comparison
    orig_scores = []
    new_scores = []
    for r in results:
        orig_scores.append(_quick_score(r["original"]))
        new_scores.append(_quick_score(r["rewritten"]))

    avg_orig = sum(orig_scores) / len(orig_scores) if orig_scores else 0
    avg_new = sum(new_scores) / len(new_scores) if new_scores else 0
    delta = avg_new - avg_orig

    console.print(f"\n[bold]Description Quality:[/bold]")
    console.print(f"  Before: {avg_orig:.1f}/10")
    console.print(f"  After:  {avg_new:.1f}/10")
    color = "green" if delta > 0 else "red"
    console.print(f"  Change: [{color}]{'+' if delta > 0 else ''}{delta:.1f}[/{color}]")


def _quick_score(desc: str) -> float:
    """Quick-score a description using the same criteria as the scanner."""
    has_scenario = bool(re.search(r"(?:use (?:this )?when|use for|call this)", desc, re.I))
    has_examples = bool(re.search(r"(?:e\.g\.|example|for instance|such as|like )", desc, re.I))
    has_error = bool(re.search(r"(?:error|fail|common issue|if .* fails|troubleshoot)", desc, re.I))

    length_score = 1.0
    if len(desc) < 20:
        length_score = 0.3
    elif len(desc) < 50:
        length_score = 0.6
    elif len(desc) > 500:
        length_score = 0.7

    score = (
        (1.0 if has_scenario else 0.0) * 3.0
        + (1.0 if has_examples else 0.0) * 2.0
        + (1.0 if has_error else 0.0) * 1.5
        + 1.0 * 2.0  # assume decent disambiguation
        + length_score * 1.5
    ) / 10.0 * 10.0

    return round(min(10.0, score), 1)


def _apply_rewrites(path: Path, results: list[dict]) -> int:
    """Apply rewritten descriptions back to source files.

    Returns the number of rewrites successfully applied.
    """
    applied = 0

    # Build a lookup of tool name -> rewritten description
    rewrites = {r["name"]: r for r in results if r["original"] != r["rewritten"]}
    if not rewrites:
        return 0

    # Scan all source files for tool descriptions to replace
    source_files = (
        list(path.rglob("*.py"))
        + list(path.rglob("*.ts"))
        + list(path.rglob("*.js"))
    )
    source_files = [f for f in source_files if "node_modules" not in str(f)]

    for source_file in source_files:
        try:
            content = source_file.read_text(errors="ignore")
        except OSError:
            continue

        original_content = content
        modified = False

        for tool_name, rewrite_info in rewrites.items():
            old_desc = rewrite_info["original"]
            new_desc = rewrite_info["rewritten"]

            if not old_desc or old_desc not in content:
                continue

            # Replace the description in the file
            content = content.replace(old_desc, new_desc, 1)
            if content != original_content:
                modified = True
                applied += 1
                console.print(f"  [green]+[/green] {tool_name} in {source_file.relative_to(path)}")
                original_content = content

        if modified:
            source_file.write_text(content)

    return applied


def _has_anthropic_key() -> bool:
    """Check if Anthropic API key is available."""
    import os
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _rewrite_llm(
    tool: dict, all_tools: list[dict], model: str
) -> str:
    """Rewrite a single tool description using Claude API."""
    import anthropic

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
