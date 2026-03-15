"""Evaluator runner -- compare tool selection accuracy before/after improvements."""

from __future__ import annotations

import re
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

from spidershield.models import EvalReport, EvalResult

console = Console()

DEFAULT_SCENARIOS_TEMPLATE = """\
# Auto-generated evaluation scenarios
# Edit this file to add domain-specific test cases

scenarios:
  - intent: "List all available tables"
    expected_tool: "list_tables"
  - intent: "Query data from the users table"
    expected_tool: "query"
  - intent: "Get the schema of a table"
    expected_tool: "describe_table"
"""


def run_eval(
    original: str,
    improved: str,
    scenarios_path: str | None = None,
    models: list[str] | None = None,
    use_llm: bool = False,
    tools_json: str | None = None,
):
    """Run before/after evaluation of tool selection accuracy."""
    models = models or ["claude-sonnet-4-20250514"]
    engine = "LLM" if use_llm else "heuristic"

    console.print("\n[bold]Evaluating tool selection accuracy[/bold]")
    console.print(f"  Original: {original}")
    console.print(f"  Improved: {improved}")
    console.print(f"  Engine:   {engine}")
    if tools_json:
        console.print(f"  Tools:    {tools_json}")
    console.print(f"  Models:   {', '.join(models)}\n")

    # Load or generate scenarios
    if scenarios_path:
        scenarios = _load_scenarios(scenarios_path)
    else:
        scenarios = _auto_generate_scenarios(Path(original), tools_json=tools_json)

    if not scenarios:
        console.print("[yellow]No test scenarios found. Create a scenarios.yaml file.[/yellow]")
        console.print(f"\nTemplate:\n{DEFAULT_SCENARIOS_TEMPLATE}")
        return

    console.print(f"Running {len(scenarios)} scenarios × {len(models)} models...\n")

    # Run evaluations
    original_results = _evaluate_server(
        Path(original), scenarios, models, use_llm, tools_json=tools_json,
    )
    improved_results = _evaluate_server(
        Path(improved), scenarios, models, use_llm, tools_json=tools_json,
    )

    original_accuracy = (
        sum(1 for r in original_results if r.correct) / len(original_results)
        if original_results
        else 0.0
    )
    improved_accuracy = (
        sum(1 for r in improved_results if r.correct) / len(improved_results)
        if improved_results
        else 0.0
    )

    report = EvalReport(
        original_server=original,
        improved_server=improved,
        models=models,
        original_accuracy=round(original_accuracy * 100, 1),
        improved_accuracy=round(improved_accuracy * 100, 1),
        improvement_pct=round((improved_accuracy - original_accuracy) * 100, 1),
        results=original_results + improved_results,
    )

    _print_report(report)


def _load_scenarios(path: str) -> list[dict]:
    """Load test scenarios from a YAML file."""
    content = Path(path).read_text()
    data = yaml.safe_load(content)
    return data.get("scenarios", [])


def _auto_generate_scenarios(
    server_path: Path, tools_json: str | None = None,
) -> list[dict]:
    """Auto-generate basic test scenarios from tool definitions."""
    tools = _load_tools(server_path, tools_json=tools_json)
    scenarios = []
    for tool in tools:
        scenarios.append({
            "intent": f"I want to use the {tool['name']} functionality",
            "expected_tool": tool["name"],
        })
    return scenarios


def _load_tools(
    server_path: Path, tools_json: str | None = None,
) -> list[dict]:
    """Load tools from a directory (source extraction) or JSON file."""
    # Explicit --tools-json overrides everything
    if tools_json:
        from spidershield.scanner.description_quality import load_tools_json
        return load_tools_json(tools_json)

    if server_path.suffix == ".json":
        import json
        data = json.loads(server_path.read_text(encoding="utf-8"))
        # Rewrite output format: list of {name, original, rewritten, score}
        if isinstance(data, list):
            return [
                {
                    "name": t["name"],
                    "description": t.get("rewritten") or t.get("original", ""),
                }
                for t in data
            ]
        return []

    from spidershield.scanner.description_quality import _extract_tools
    return _extract_tools(server_path)


def _evaluate_server(
    server_path: Path, scenarios: list[dict], models: list[str],
    use_llm: bool = False, tools_json: str | None = None,
) -> list[EvalResult]:
    """Evaluate tool selection for a server against scenarios."""
    tools = _load_tools(server_path, tools_json=tools_json)
    if not tools:
        return []

    results: list[EvalResult] = []

    # Heuristic mode (default): fast, free, no API key needed
    if not use_llm:
        for scenario in scenarios:
            for model in models:
                best_match = _heuristic_match(scenario["intent"], tools)
                results.append(
                    EvalResult(
                        scenario=scenario["intent"],
                        expected_tool=scenario["expected_tool"],
                        selected_tool=best_match,
                        correct=best_match == scenario["expected_tool"],
                        model=f"{model} (heuristic)",
                    )
                )
        return results

    # LLM mode: requires anthropic SDK + API key
    try:
        import anthropic  # type: ignore[import-untyped]

        client = anthropic.Anthropic()
    except ImportError:
        console.print("[red]--llm requires: pip install spidershield[ai][/red]")
        raise SystemExit(1)

    # LLM-based evaluation
    tool_descriptions = "\n".join(
        f"- {t['name']}: {t['description']}" for t in tools
    )
    tool_name_list = [t["name"] for t in tools]

    for scenario in scenarios:
        for model in models:
            matched_tool = _llm_select_with_retry(
                client, model, tool_descriptions, tool_name_list,
                scenario["intent"],
            )

            results.append(
                EvalResult(
                    scenario=scenario["intent"],
                    expected_tool=scenario["expected_tool"],
                    selected_tool=matched_tool,
                    correct=matched_tool == scenario["expected_tool"],
                    model=model,
                )
            )

    return results


def _llm_select_with_retry(
    client,
    model: str,
    tool_descriptions: str,
    tool_names: list[str],
    intent: str,
    max_retries: int = 1,
) -> str:
    """Ask LLM to select a tool, with retry if response is invalid.

    Self-check: if the LLM response doesn't match any known tool name,
    retry once with a more explicit prompt listing exact valid names.
    """
    system = (
        "You are selecting the best tool for a user's request. "
        "Reply with ONLY the tool name, nothing else."
    )
    user_msg = (
        f"Available tools:\n{tool_descriptions}\n\n"
        f"User request: {intent}\n\n"
        f"Which tool should be used? Reply with only the tool name."
    )

    matched = ""
    for attempt in range(1 + max_retries):
        try:
            response = client.messages.create(
                model=model,
                max_tokens=50,
                system=system,
                messages=[{"role": "user", "content": user_msg}],
            )
            selected = response.content[0].text.strip().lower()
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            return "error"

        matched = _fuzzy_match_tool(selected, tool_names)

        # Self-check: did we get a valid match?
        if matched in tool_names:
            return matched

        # Invalid match -- retry with explicit tool list
        if attempt < max_retries:
            valid_names = ", ".join(tool_names)
            user_msg = (
                f"Available tools:\n{tool_descriptions}\n\n"
                f"User request: {intent}\n\n"
                f"IMPORTANT: You MUST reply with EXACTLY one of these tool names: "
                f"{valid_names}\n"
                f"Your previous answer '{selected}' was not a valid tool name. "
                f"Reply with only the tool name."
            )

    return matched


def _heuristic_match(intent: str, tools: list[dict]) -> str:
    """Keyword-based tool matching with IDF weighting and stopword filtering."""
    import math

    intent_lower = intent.lower()
    intent_words = set(intent_lower.split())

    # Intent verb → tool name verb synonyms
    verb_synonyms = {
        "get": ["get", "retrieve", "fetch", "show", "read"],
        "list": ["list", "show", "get"],
        "show": ["show", "list", "get", "display"],
        "run": ["run", "execute", "perform"],
        "execute": ["execute", "run"],
        "send": ["send", "post", "request", "submit"],
        "check": ["check", "get", "list", "show", "verify"],
        "apply": ["apply", "run", "execute"],
        "search": ["search", "find", "query"],
        "find": ["find", "search", "query"],
        "create": ["create", "add", "new"],
        "delete": ["delete", "remove", "drop"],
        "update": ["update", "edit", "modify", "set"],
    }

    # Extract intent's leading verb
    intent_verb = intent_lower.split()[0] if intent_lower.split() else ""
    intent_verb_family = set(verb_synonyms.get(intent_verb, [intent_verb]))

    # Stopwords: common words that don't help disambiguate tools
    stopwords = {
        "a", "an", "the", "to", "for", "of", "in", "on", "by", "with",
        "from", "this", "that", "it", "is", "are", "was", "were", "be",
        "and", "or", "not", "all", "my", "i", "you", "your", "we",
        "can", "will", "do", "does", "has", "have", "had", "get",
        "about", "into", "up", "out", "at", "as", "if", "so",
    }

    # Build document frequency for IDF weighting
    doc_freq: dict[str, int] = {}
    for tool in tools:
        desc = tool.get("description", "").lower()
        name = tool["name"].lower().replace("_", " ")
        unique_words = set((name + " " + desc).split()) - stopwords
        for w in unique_words:
            if len(w) >= 2:
                doc_freq[w] = doc_freq.get(w, 0) + 1

    n_tools = len(tools) or 1
    best_score = -1.0
    best_tool = tools[0]["name"] if tools else ""

    for tool in tools:
        score = 0.0
        # Split name: snake_case and camelCase
        raw_name = tool["name"].replace("_", " ")
        # Split camelCase: "postgrestRequest" -> "postgrest Request"
        raw_name = re.sub(r"([a-z])([A-Z])", r"\1 \2", raw_name)
        name_words = raw_name.lower().split()
        desc = tool.get("description", "").lower()
        desc_words = desc.split()

        # Exact name match (strongest signal)
        name_joined = tool["name"].lower().replace("_", " ")
        if name_joined in intent_lower:
            score += 10.0

        # Tool name's leading verb alignment with intent verb
        tool_verb = name_words[0] if name_words else ""
        if tool_verb in intent_verb_family:
            score += 4.0

        # Name word matches (high weight, IDF-adjusted)
        for word in name_words:
            if word in stopwords or len(word) < 2:
                continue
            if word in intent_lower:
                idf = math.log(n_tools / (doc_freq.get(word, 1) + 1)) + 1
                score += 5.0 * idf

        # Description word matches (lower weight, IDF-adjusted, skip stopwords)
        seen = set()
        for word in desc_words:
            if word in stopwords or len(word) < 3 or word in seen:
                continue
            seen.add(word)
            if word in intent_words:
                idf = math.log(n_tools / (doc_freq.get(word, 1) + 1)) + 1
                score += 1.0 * idf

        if score > best_score:
            best_score = score
            best_tool = tool["name"]

    return best_tool


def _fuzzy_match_tool(selected: str, tool_names: list[str]) -> str:
    """Fuzzy match a selected tool name against available tool names."""
    selected_clean = selected.strip().lower().replace("-", "_").replace(" ", "_")
    for name in tool_names:
        if name.lower() == selected_clean:
            return name
        if selected_clean in name.lower() or name.lower() in selected_clean:
            return name
    return selected


def _print_report(report: EvalReport):
    """Print a rich comparison table."""
    table = Table(title="Tool Selection Accuracy - Before vs After")
    table.add_column("Metric", style="bold")
    table.add_column("Original", justify="right")
    table.add_column("Improved", justify="right")
    table.add_column("Change", justify="right")

    color = "green" if report.improvement_pct > 0 else "red"
    table.add_row(
        "Accuracy",
        f"{report.original_accuracy}%",
        f"{report.improved_accuracy}%",
        f"[{color}]{'+' if report.improvement_pct > 0 else ''}{report.improvement_pct}%[/{color}]",
    )

    console.print(table)
    console.print()
