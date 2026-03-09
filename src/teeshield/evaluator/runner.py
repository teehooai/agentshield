"""Evaluator runner -- compare tool selection accuracy before/after improvements."""

from __future__ import annotations

import time
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

from teeshield.models import EvalReport, EvalResult

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
):
    """Run before/after evaluation of tool selection accuracy."""
    models = models or ["claude-sonnet-4-20250514"]
    engine = "LLM" if use_llm else "heuristic"

    console.print("\n[bold]Evaluating tool selection accuracy[/bold]")
    console.print(f"  Original: {original}")
    console.print(f"  Improved: {improved}")
    console.print(f"  Engine:   {engine}")
    console.print(f"  Models:   {', '.join(models)}\n")

    # Load or generate scenarios
    if scenarios_path:
        scenarios = _load_scenarios(scenarios_path)
    else:
        scenarios = _auto_generate_scenarios(Path(original))

    if not scenarios:
        console.print("[yellow]No test scenarios found. Create a scenarios.yaml file.[/yellow]")
        console.print(f"\nTemplate:\n{DEFAULT_SCENARIOS_TEMPLATE}")
        return

    console.print(f"Running {len(scenarios)} scenarios × {len(models)} models...\n")

    # Run evaluations
    original_results = _evaluate_server(Path(original), scenarios, models, use_llm)
    improved_results = _evaluate_server(Path(improved), scenarios, models, use_llm)

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


def _auto_generate_scenarios(server_path: Path) -> list[dict]:
    """Auto-generate basic test scenarios from tool definitions."""
    from teeshield.scanner.description_quality import _extract_tools

    tools = _extract_tools(server_path)
    scenarios = []
    for tool in tools:
        scenarios.append({
            "intent": f"I want to use the {tool['name']} functionality",
            "expected_tool": tool["name"],
        })
    return scenarios


def _evaluate_server(
    server_path: Path, scenarios: list[dict], models: list[str], use_llm: bool = False,
) -> list[EvalResult]:
    """Evaluate tool selection for a server against scenarios."""
    from teeshield.scanner.description_quality import _extract_tools

    tools = _extract_tools(server_path)
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
        import anthropic

        client = anthropic.Anthropic()
    except ImportError:
        console.print("[red]--llm requires: pip install teeshield[ai][/red]")
        raise SystemExit(1)

    # LLM-based evaluation
    tool_descriptions = "\n".join(
        f"- {t['name']}: {t['description']}" for t in tools
    )

    for scenario in scenarios:
        for model in models:
            start = time.time()
            try:
                response = client.messages.create(
                    model=model,
                    max_tokens=50,
                    system="You are selecting the best tool for a user's request. Reply with ONLY the tool name, nothing else.",
                    messages=[
                        {
                            "role": "user",
                            "content": f"Available tools:\n{tool_descriptions}\n\nUser request: {scenario['intent']}\n\nWhich tool should be used? Reply with only the tool name.",
                        }
                    ],
                )
                selected = response.content[0].text.strip().lower()
                latency = (time.time() - start) * 1000
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                selected = "error"
                latency = None

            # Fuzzy match the tool name
            matched_tool = _fuzzy_match_tool(selected, [t["name"] for t in tools])

            results.append(
                EvalResult(
                    scenario=scenario["intent"],
                    expected_tool=scenario["expected_tool"],
                    selected_tool=matched_tool,
                    correct=matched_tool == scenario["expected_tool"],
                    model=model,
                    latency_ms=latency,
                )
            )

    return results


def _heuristic_match(intent: str, tools: list[dict]) -> str:
    """Simple keyword-based tool matching as fallback."""
    intent_lower = intent.lower()
    best_score = 0
    best_tool = tools[0]["name"] if tools else ""

    for tool in tools:
        score = 0
        name_words = tool["name"].lower().replace("_", " ").split()
        desc_words = tool.get("description", "").lower().split()
        for word in name_words:
            if word in intent_lower:
                score += 3
        for word in desc_words:
            if word in intent_lower:
                score += 1
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
