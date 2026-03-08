"""Analyze quality of MCP tool descriptions for LLM compatibility."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from teeshield.models import ToolDescriptionScore


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

    skip_dirs = {"node_modules", "__pycache__", ".venv", "venv", ".git", "dist", "build", ".tox", ".mypy_cache"}

    # Python: look for @tool or @server.tool decorators
    for py_file in path.rglob("*.py"):
        if any(part in skip_dirs for part in py_file.parts):
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

        # MCP SDK style: Tool(name="...", description="..." or """...""")
        tool_pattern3 = re.finditer(
            r'Tool\(\s*name\s*=\s*["\'](\w+)["\']\s*,\s*description\s*=\s*(?:"""(.*?)"""|["\']([^"\']+)["\'])',
            content,
            re.DOTALL,
        )
        for match in tool_pattern3:
            name = match.group(1)
            desc = (match.group(2) or match.group(3) or "").strip()
            if name not in [t["name"] for t in tools]:
                tools.append({"name": name, "description": desc})

        # MCP SDK style with enum: Tool(name=GitTools.STATUS, ...)
        # Extract the enum values first
        enum_values = dict(re.findall(r'(\w+)\s*=\s*["\'](\w+)["\']', content))
        tool_pattern4 = re.finditer(
            r'Tool\(\s*name\s*=\s*(\w+)\.(\w+)\s*,\s*description\s*=\s*["\']([^"\']+)["\']',
            content,
        )
        for match in tool_pattern4:
            enum_member = match.group(2)
            desc = match.group(3).strip()
            # Try to resolve enum value
            name = enum_values.get(enum_member, enum_member.lower())
            if name not in [t["name"] for t in tools]:
                tools.append({"name": name, "description": desc})

    # TypeScript: look for server.tool() or server.registerTool() calls
    for ts_file in list(path.rglob("*.ts")) + list(path.rglob("*.js")):
        if any(part in skip_dirs for part in ts_file.parts):
            continue
        try:
            content = ts_file.read_text(errors="ignore")
        except OSError:
            continue

        # Pattern 1: server.tool("name", { description: "..." })
        tool_pattern = re.finditer(
            r'server\.tool\(\s*["\'](\w+)["\'].*?description:\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        )
        for match in tool_pattern:
            tools.append({"name": match.group(1), "description": match.group(2).strip()})

        # Pattern 2: server.registerTool("name", { description: "..." })
        # Description may be a concatenated string with +
        reg_pattern = re.finditer(
            r'server\.registerTool\(\s*["\'](\w+)["\']\s*,\s*\{[^}]*?description:\s*\n?\s*((?:["\'][^"\']*["\'](?:\s*\+\s*["\'][^"\']*["\'])*)|["\'][^"\']*["\'])',
            content,
            re.DOTALL,
        )
        for match in reg_pattern:
            name = match.group(1)
            raw_desc = match.group(2)
            # Join concatenated strings: "foo" + "bar" -> "foobar"
            desc = "".join(re.findall(r'["\']([^"\']*)["\']', raw_desc))
            if name not in [t["name"] for t in tools]:
                tools.append({"name": name, "description": desc.strip()})

        # Pattern 3: Object literal tool defs (Supabase-style)
        # e.g. { tool_name: { description: '...', parameters: ... } }
        obj_pattern = re.finditer(
            r'(\w+)\s*:\s*\{\s*\n?\s*description\s*:\s*\n?\s*["\']([^"\']+)["\']',
            content,
        )
        for match in obj_pattern:
            name = match.group(1)
            desc = match.group(2).strip()
            # Skip non-tool entries (common property names)
            if name in {"type", "default", "title", "label", "name", "id", "key", "value", "message"}:
                continue
            if name not in [t["name"] for t in tools]:
                tools.append({"name": name, "description": desc})

        # Pattern 3b: Object literal with multi-line description
        obj_pattern_ml = re.finditer(
            r'(\w+)\s*:\s*\{\s*\n?\s*description\s*:\s*\n?\s*["\']([^"\']*)["\']',
            content,
        )
        # Already handled by pattern above

    return tools


def _word_overlap(a: str, b: str) -> float:
    """Calculate word overlap ratio between two strings."""
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    return len(intersection) / min(len(words_a), len(words_b))
