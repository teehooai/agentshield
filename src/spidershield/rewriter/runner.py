"""Rewriter runner -- transforms tool descriptions for LLM-optimized selection."""

from __future__ import annotations

import json
import re
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .quality_gate import _quick_score, quality_gate

console = Console()

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
    "open": "Open",
    "close": "Close",
}

# Scenario triggers -- domain-neutral (always applied).
SCENARIO_TRIGGERS = {
    "search": "Use when the user wants to find items matching specific criteria.",
    "diff": "Use when the user wants to compare two versions.",
}

# Domain-specific scenarios: only fire when the tool name contains
# the keyword AND at least one sibling tool contains a domain signal.
DOMAIN_SCENARIOS: list[tuple[str, list[str], str]] = [
    # Filesystem
    ("read_file", ["write_file", "list_file", "directory"],
     "Use when the user wants to view the contents of a specific file."),
    ("write_file", ["read_file", "list_file", "directory"],
     "Use when the user wants to save or update file contents."),
    ("list_file", ["read_file", "write_file", "directory"],
     "Use when the user wants to see what files are available."),
    # Database
    ("query", ["table", "database", "sql", "schema"],
     "Use when the user wants to retrieve data from the database."),
    ("list_table", ["query", "database", "sql", "schema"],
     "Use when the user wants to discover available tables."),
    # Git
    ("commit", ["branch", "log", "status", "diff"],
     "Use when the user wants to save staged changes to the repository."),
    ("status", ["commit", "branch", "diff", "checkout"],
     "Use when the user wants to check which files are modified or staged."),
    # Network
    ("fetch", ["url", "http", "request", "download"],
     "Use when the user wants to retrieve content from a URL."),
]

# Words that indicate the remaining text is a complete sentence (not a verb complement).
# Excludes determiners like "a", "an", "the", "all" which can be verb complements
# (e.g., "List all tables" -> "all" is part of the object, not a sentence starter).
_SENTENCE_STARTERS = {
    "this", "it", "returns", "performs", "provides",
    "retrieves", "generates", "handles", "manages", "processes", "supports",
    "allows", "enables", "sends", "shows", "displays", "given",
}


def _rewrite_local(tool: dict, all_tools: list[dict]) -> str:
    """Rewrite a tool description using template-based rules (no API needed)."""
    name = tool["name"]
    desc = tool.get("description", "")
    name_lower = name.lower()

    # 1. Build action-oriented opening
    first_word = name_lower.split("_")[0] if "_" in name_lower else name_lower
    verb = VERB_MAP.get(first_word, "")

    # Clean up original description -- strip any leading verb so we don't double-prefix
    clean_desc = desc.strip().rstrip(".")
    if not clean_desc:
        return f"{verb or 'Perform'} the {name.replace('_', ' ')} operation."

    # Detect non-description content (type signatures, code snippets)
    # These contain characters like : | [ ] that don't appear in natural language descriptions
    if re.search(r'\w+:\s*\w+\[', clean_desc) or clean_desc.count("|") >= 2:
        return f"{verb or 'Perform'} the {name.replace('_', ' ')} operation."

    # Check if the description is a complete sentence starting with a pronoun/article/etc.
    # In that case, don't strip the leading verb -- the original phrasing is intentional.
    first_desc_word = clean_desc.split()[0].lower()
    is_complete_sentence = first_desc_word in _SENTENCE_STARTERS

    if is_complete_sentence:
        # Keep the original text as-is (capitalize first letter, add period)
        opening = f"{clean_desc[0].upper()}{clean_desc[1:]}."
    else:
        # Try to strip leading verb phrase to avoid duplication
        leading_verb = re.match(
            r'^(?:(?:Recursively|Safely|Securely|Efficiently)\s+)?'
            r'(?:Get|Show|List|Read|Write|Create|Delete|Move|Search|Find|Retrieve|'
            r'Execute|Run|Make|Return|Record|Unstage|Switch|Add|Fetch|Compare|Commit|'
            r'Reset|Edit|Copy|Rename|Open|Close|Set|Update|Remove|Query)(?:s|es|ed|ing)?\s+',
            clean_desc, re.IGNORECASE,
        )
        if leading_verb:
            remainder = clean_desc[leading_verb.end():]
            # Safety: if the remainder is too short or starts with a preposition
            # that doesn't make sense as a verb complement, keep original
            if len(remainder.split()) < 2:
                opening = f"{desc.strip().rstrip('.')}."
            else:
                clean_desc = remainder
                # Re-check for verb complement fitness
                if verb:
                    opening = f"{verb} {clean_desc}."
                else:
                    opening = f"{clean_desc[0].upper()}{clean_desc[1:]}."
        elif verb:
            # No leading verb to strip -- check for stuttering
            first_words = clean_desc.lower().split()[:5]
            verb_stem = verb.lower().rstrip("es").rstrip("s")
            already_has_verb = any(w.startswith(verb_stem) for w in first_words)
            if already_has_verb:
                opening = f"{clean_desc[0].upper()}{clean_desc[1:]}."
            else:
                opening = f"{verb} {clean_desc}."
        else:
            opening = f"{desc.strip().rstrip('.')}."

    # 2. Add scenario trigger (domain-neutral first, then domain-specific)
    scenario = ""
    for key, trigger in SCENARIO_TRIGGERS.items():
        if key in name_lower:
            scenario = trigger
            break

    # Domain-specific scenarios: only fire when sibling tools confirm the domain
    if not scenario:
        sibling_names = " ".join(t["name"].lower() for t in all_tools)
        for keyword, signals, trigger in DOMAIN_SCENARIOS:
            if keyword in name_lower:
                if any(sig in sibling_names for sig in signals):
                    scenario = trigger
                    break

    # 3. Add parameter hints from tool schema
    param_hint = ""
    params = _extract_params(tool)
    if params:
        required_params = [p for p in params if p.get("required")]
        if required_params:
            param_names = ", ".join(f"`{p['name']}`" for p in required_params[:3])
            param_hint = f"Requires {param_names}."

    # 4. Compose final description
    parts = [opening]
    if scenario:
        parts.append(scenario)
    if param_hint:
        parts.append(param_hint)

    return " ".join(parts)


def _extract_params(tool: dict) -> list[dict] | None:
    """Extract parameter info from tool schema if available."""
    schema = tool.get("inputSchema", tool.get("parameters"))
    if not isinstance(schema, dict) or "properties" not in schema:
        return None
    required = set(schema.get("required", []))
    params = []
    for pname, pinfo in schema["properties"].items():
        params.append({
            "name": pname,
            "type": pinfo.get("type", "string"),
            "required": pname in required,
            "description": pinfo.get("description", ""),
        })
    return params


def _rewrite_llm(
    tool: dict,
    all_tools: list[dict],
    provider,
    model: str | None = None,
    min_score: float = 9.8,
    max_retries: int = 2,
    use_cache: bool = True,
) -> str:
    """Rewrite a single tool description using LLM provider with self-check loop.

    Flow: check cache -> generate -> score -> if below min_score, diagnose -> retry -> cache.
    Maximum `max_retries` attempts total (1 initial + retries).
    """
    from .cache import get_cached, set_cached
    from .prompt import build_rewrite_prompt
    from .quality_gate import _quick_score, diagnose_missing

    tool_name = tool["name"]
    original_desc = tool.get("description", "")
    model_id = model or getattr(provider, "model", "unknown")

    # Check cache first
    if use_cache:
        cached = get_cached(tool_name, original_desc, model_id)
        if cached is not None:
            return cached

    params = _extract_params(tool)
    siblings = [{"name": t["name"], "description": t.get("description", "")} for t in all_tools]

    # v2 (E2): provide template draft as warm start + pre-diagnosed missing signals
    from .quality_gate import diagnose_missing
    template_draft = _rewrite_local(tool, all_tools)
    template_score_val = _quick_score(template_draft)
    missing = diagnose_missing(template_draft)

    system_prompt, user_prompt = build_rewrite_prompt(
        tool_name=tool_name,
        original_description=original_desc,
        parameters=params,
        sibling_tools=siblings,
        template_draft=template_draft,
        missing_signals=missing,
        template_score=template_score_val,
    )

    # Attempt 1: initial generation
    result = provider.complete(system_prompt, user_prompt, max_tokens=500)
    score = _quick_score(result)

    # Self-check loop: diagnose and retry if below threshold
    for attempt in range(max_retries):
        if score >= min_score:
            break

        hints = diagnose_missing(result, min_score)
        if not hints:
            break  # Score is fine or no actionable hints

        # Build retry prompt with specific feedback
        feedback = (
            f"SELF-CHECK FAILED: Your rewrite scored {score:.1f}/10 but needs "
            f"{min_score}/10.\n\n"
            f"Missing criteria that MUST be added:\n"
            + "\n".join(f"- {h}" for h in hints)
            + "\n\nIMPORTANT: You MUST address every missing criterion listed above. "
            "Each one adds significant score weight. For parameters, use `backtick` "
            "notation. For examples, use 'e.g.' prefix. For errors, use 'Raises' or "
            "'fails'. Return ONLY the improved description, nothing else."
        )
        retry_prompt = f"{user_prompt}\n\n---\n\nPrevious attempt:\n{result}\n\n{feedback}"

        result = provider.complete(system_prompt, retry_prompt, max_tokens=500)
        score = _quick_score(result)

    # Cache the result
    if use_cache:
        set_cached(tool_name, original_desc, model_id, result)

    return result


# Keep old function signatures for backward compatibility with tests
def _quality_gate(original: str, rewritten: str) -> str:
    """Return the rewrite only if it genuinely improves the description score.

    Delegates to the new quality_gate module.
    """
    result = quality_gate(original, rewritten)
    return result.description


def run_rewrite(
    server_path: str,
    model: str = "claude-sonnet-4-20250514",
    dry_run: bool = False,
    output_path: str | None = None,
    engine: str = "auto",
    provider_name: str | None = None,
    tools_json: str | None = None,
    use_cache: bool = True,
):
    """Rewrite tool descriptions in an MCP server."""
    path = Path(server_path)
    if not path.exists():
        console.print(f"[red]Path not found: {server_path}[/red]")
        raise SystemExit(1)

    # Extract tools
    if tools_json:
        from spidershield.scanner.description_quality import load_tools_json
        tools = load_tools_json(tools_json)
    else:
        from spidershield.scanner.description_quality import _extract_tools
        tools = _extract_tools(path)
    if not tools:
        console.print("[yellow]No tools found in this server.[/yellow]")
        return

    # Decide rewrite engine
    llm_provider = None
    if engine in ("llm", "auto"):
        from .providers import detect_provider

        llm_provider = detect_provider(provider=provider_name, model=model)

    use_llm = engine == "llm" or (engine == "auto" and llm_provider is not None)
    if engine == "llm" and llm_provider is None:
        console.print(
            "[red]LLM engine requested but no API key found. "
            "Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY.[/red]"
        )
        raise SystemExit(1)

    engine_label = f"LLM ({llm_provider.__class__.__name__})" if use_llm else "template-based"

    console.print(f"\n[bold]Rewriting tool descriptions:[/bold] {server_path}")
    console.print(f"[dim]Engine: {engine_label} | Dry run: {dry_run}[/dim]")
    console.print(f"Found {len(tools)} tools to rewrite.\n")

    results = []
    skipped = 0
    for tool in tools:
        original = tool.get("description", "")

        if use_llm and llm_provider:
            try:
                rewritten = _rewrite_llm(tool, tools, llm_provider, model, use_cache=use_cache)
            except Exception as e:
                console.print(f"[yellow]LLM failed for {tool['name']}: {e}[/yellow]")
                rewritten = _rewrite_local(tool, tools)
        else:
            rewritten = _rewrite_local(tool, tools)

        # Quality gate: only keep rewrite if it passes all checks
        gate_result = quality_gate(original, rewritten, tool_name=tool["name"])
        if not gate_result.passed:
            skipped += 1
        rewritten = gate_result.description

        results.append({
            "name": tool["name"],
            "original": original,
            "rewritten": rewritten,
            "score": gate_result.score,
        })

        # Record rewrite pair to local dataset
        from spidershield.dataset.collector import record_rewrite
        record_rewrite(
            target=server_path,
            tool_name=tool["name"],
            original=original,
            rewritten=rewritten,
            original_score=_quick_score(original),
            rewritten_score=gate_result.score,
            engine="llm" if (use_llm and llm_provider) else "template",
            passed=gate_result.passed,
        )

    if skipped:
        console.print(
            f"[yellow]Quality gate: {skipped}/{len(tools)} rewrites "
            f"rejected (no score improvement).[/yellow]\n"
        )

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
        console.print(
            "[dim]Tip: Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or GEMINI_API_KEY "
            "for higher-quality LLM-powered rewrites.[/dim]"
        )

    console.print()

    # Compute aggregate scores for callers (pipeline/cli.py unpacks this)
    orig_scores = [_quick_score(r.get("original", "")) for r in results]
    new_scores = [_quick_score(r.get("rewritten", "")) for r in results]
    score_before = sum(orig_scores) / len(orig_scores) if orig_scores else 0.0
    score_after = sum(new_scores) / len(new_scores) if new_scores else 0.0
    return results, score_before, score_after


def _print_comparison(results: list[dict]):
    """Print a before/after comparison table."""

    table = Table(title="Description Rewrite Results", show_lines=True)
    table.add_column("Tool", style="bold", width=20)
    table.add_column("Original", width=35)
    table.add_column("Rewritten", width=40)
    table.add_column("Score", width=5, justify="right")

    for r in results:
        orig_preview = r["original"][:70] + "..." if len(r["original"]) > 70 else r["original"]
        new_preview = r["rewritten"][:70] + "..." if len(r["rewritten"]) > 70 else r["rewritten"]
        score = r.get("score", 0)
        score_color = "green" if score >= 9.8 else "yellow" if score >= 8.0 else "red"
        table.add_row(
            r["name"],
            f"[dim]{orig_preview}[/dim]",
            f"[green]{new_preview}[/green]",
            f"[{score_color}]{score:.1f}[/{score_color}]",
        )

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

    above_98 = sum(1 for s in new_scores if s >= 9.8)

    console.print("\n[bold]Description Quality:[/bold]")
    console.print(f"  Before: {avg_orig:.1f}/10")
    console.print(f"  After:  {avg_new:.1f}/10")
    color = "green" if delta > 0 else "red"
    console.print(f"  Change: [{color}]{'+' if delta > 0 else ''}{delta:.1f}[/{color}]")
    console.print(f"  >= 9.8: {above_98}/{len(new_scores)} tools")


def _apply_rewrites(path: Path, results: list[dict]) -> int:
    """Apply rewritten descriptions back to source files.

    Returns the number of rewrites successfully applied.
    """
    applied = 0

    # Build a lookup of tool name -> rewritten description
    rewrites = {r["name"]: r for r in results if r["original"] != r["rewritten"]}
    if not rewrites:
        return 0

    # Scan source files, excluding test/build/non-MCP directories
    skip_dirs = {
        "node_modules", "__pycache__", ".venv", "venv", ".git", "dist",
        "build", ".tox", ".mypy_cache", "__tests__", ".next", ".nuxt",
    }
    skip_file_patterns = re.compile(
        r'(?:^test_|_test\.py$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$'
        r'|\.d\.ts$|\.config\.[jt]s$|\.stories\.[jt]sx?$)',
        re.IGNORECASE,
    )
    source_files = []
    for ext in ("*.py", "*.ts", "*.js"):
        for f in path.rglob(ext):
            if any(part in skip_dirs for part in f.parts):
                continue
            if skip_file_patterns.search(f.name):
                continue
            source_files.append(f)

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
                console.print(
                    f"  [green]+[/green] {tool_name} in {source_file.relative_to(path)}"
                )
                original_content = content

        if modified:
            source_file.write_text(content)

    return applied
