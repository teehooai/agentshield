"""Analyze quality of MCP tool descriptions for LLM compatibility."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from agentshield.models import ToolDescriptionScore


def score_descriptions(
    path: Path,
) -> tuple[float, list[ToolDescriptionScore], list[str]]:
    """Score the quality of tool descriptions in an MCP server.

    Returns (overall_score, per_tool_scores, tool_names).
    """
    tools = _extract_tools(path)
    if not tools:
        return 5.0, [], []

    tool_names = [t["name"] for t in tools]
    scores: list[ToolDescriptionScore] = []

    for tool in tools:
        name = tool["name"]
        desc = tool.get("description", "")

        has_scenario = bool(re.search(r"(?:use (?:this )?when|use for|call this)", desc, re.I))
        has_examples = bool(re.search(r"(?:e\.g\.|example|for instance|such as|like )", desc, re.I))
        has_error_guidance = bool(
            re.search(r"(?:error|fail|common issue|if .* fails|troubleshoot)", desc, re.I)
        )

        # Disambiguation: check if description is specific enough
        disambiguation = 1.0
        for other in tools:
            if other["name"] != name:
                other_desc = other.get("description", "")
                overlap = _word_overlap(desc, other_desc)
                if overlap > 0.6:
                    disambiguation = min(disambiguation, 1.0 - overlap)

        # Length penalty: too short or too long
        length_score = 1.0
        if len(desc) < 20:
            length_score = 0.3
        elif len(desc) < 50:
            length_score = 0.6
        elif len(desc) > 500:
            length_score = 0.7

        overall = (
            (1.0 if has_scenario else 0.0) * 3.0
            + (1.0 if has_examples else 0.0) * 2.0
            + (1.0 if has_error_guidance else 0.0) * 1.5
            + disambiguation * 2.0
            + length_score * 1.5
        ) / 10.0 * 10.0

        scores.append(
            ToolDescriptionScore(
                tool_name=name,
                has_scenario_trigger=has_scenario,
                has_param_examples=has_examples,
                has_error_guidance=has_error_guidance,
                disambiguation_score=round(disambiguation, 2),
                overall_score=round(min(10.0, overall), 1),
            )
        )

    avg_score = sum(s.overall_score for s in scores) / len(scores) if scores else 5.0
    return round(avg_score, 1), scores, tool_names


def _extract_tools(path: Path) -> list[dict]:
    """Extract tool definitions from Python or TypeScript MCP server code."""
    tools: list[dict] = []

    # Python: look for @tool or @server.tool decorators
    for py_file in path.rglob("*.py"):
        if "node_modules" in str(py_file) or "__pycache__" in str(py_file):
            continue
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue

        # FastMCP style: @mcp.tool() or @server.tool()
        tool_pattern = re.finditer(
            r'@(?:mcp|server|app)\.tool\(?\)?\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\).*?"""(.*?)"""',
            content,
            re.DOTALL,
        )
        for match in tool_pattern:
            tools.append({"name": match.group(1), "description": match.group(2).strip()})

        # Decorated style: @tool
        tool_pattern2 = re.finditer(
            r'@tool\s*(?:\([^)]*\))?\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\).*?"""(.*?)"""',
            content,
            re.DOTALL,
        )
        for match in tool_pattern2:
            tools.append({"name": match.group(1), "description": match.group(2).strip()})

    # TypeScript: look for server.tool() calls
    for ts_file in list(path.rglob("*.ts")) + list(path.rglob("*.js")):
        if "node_modules" in str(ts_file):
            continue
        try:
            content = ts_file.read_text(errors="ignore")
        except OSError:
            continue

        tool_pattern = re.finditer(
            r'server\.tool\(\s*["\'](\w+)["\'].*?description:\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        )
        for match in tool_pattern:
            tools.append({"name": match.group(1), "description": match.group(2).strip()})

    return tools


def _word_overlap(a: str, b: str) -> float:
    """Calculate word overlap ratio between two strings."""
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    return len(intersection) / min(len(words_a), len(words_b))
