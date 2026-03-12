"""Analyze quality of MCP tool descriptions for LLM compatibility."""

from __future__ import annotations

import re
from pathlib import Path

from spidershield.models import ToolDescriptionScore

_ACTION_VERBS = (
    "read", "write", "create", "delete", "remove", "list", "get", "set",
    "update", "search", "find", "query", "fetch", "send", "run", "execute",
    "check", "validate", "show", "display", "add", "edit", "move", "copy",
    "rename", "monitor", "scan", "analyze", "parse", "convert", "generate",
    "deploy", "install", "configure", "connect", "disconnect", "start", "stop",
    "reset", "restore", "backup", "export", "import", "subscribe", "publish",
    "retrieve", "return", "compute", "calculate", "open", "close", "log",
    "commit", "push", "pull", "merge", "checkout", "diff", "apply", "revert",
    "compare", "switch", "expand", "stage", "unstage", "inspect", "browse",
    "download", "upload", "submit", "approve", "reject", "assign", "unassign",
    "pin", "unpin", "archive", "resolve", "test", "debug", "trace", "profile",
    "pause", "resume", "rebase", "squash", "cherry-pick", "stash", "tag",
    "obtain", "purchase", "request", "grant", "revoke", "invoke", "trigger",
    "schedule", "cancel", "retry", "abort", "suspend", "terminate", "restart",
    "migrate", "seed", "provision", "deprovision", "scale", "replicate",
    "confirm", "verify", "authenticate", "authorize", "register", "deregister",
    "rebuild", "redeploy", "rollback", "promote", "demote", "fork", "clone",
    "sync", "refresh", "flush", "clear", "purge", "truncate", "aggregate",
    "batch", "stream", "emit", "broadcast", "notify", "alert", "warn",
)


def load_tools_json(json_path: str) -> list[dict]:
    """Load tools from a JSON file (MCP tools/list format or rewrite output).

    Supports formats:
    - MCP tools/list: {"tools": [{"name": "...", "description": "...", ...}]}
    - Rewrite output: [{"name": "...", "original": "...", "rewritten": "..."}]
    - Plain list: [{"name": "...", "description": "..."}]
    """
    import json

    data = json.loads(Path(json_path).read_text(encoding="utf-8"))

    # MCP tools/list response: {"tools": [...]}
    if isinstance(data, dict) and "tools" in data:
        return [
            {"name": t["name"], "description": t.get("description", "")}
            for t in data["tools"]
        ]

    # List format
    if isinstance(data, list):
        tools = []
        for t in data:
            if not isinstance(t, dict) or "name" not in t:
                continue
            desc = t.get("description") or t.get("rewritten") or t.get("original", "")
            tools.append({"name": t["name"], "description": desc})
        return tools

    return []


def score_descriptions(
    path: Path,
    tools_json: str | None = None,
) -> tuple[float, list[ToolDescriptionScore], list[str]]:
    """Score the quality of tool descriptions in an MCP server.

    Returns (overall_score, per_tool_scores, tool_names).
    """
    tools = load_tools_json(tools_json) if tools_json else _extract_tools(path)
    if not tools:
        return 5.0, [], []

    tool_names = [t["name"] for t in tools]
    scores: list[ToolDescriptionScore] = []

    # Build stop-word set for disambiguation (words appearing in >50% of tools)
    all_words: dict[str, int] = {}
    for t in tools:
        for w in set(t.get("description", "").lower().split()):
            all_words[w] = all_words.get(w, 0) + 1
    half = max(1, len(tools) // 2)
    stop_words = {w for w, c in all_words.items() if c > half or len(w) <= 2}

    for tool in tools:
        name = tool["name"]
        desc = tool.get("description", "")

        # 1. Action verb: description starts with a verb (imperative mood)
        first_word = desc.split()[0].lower().rstrip("s") if desc.strip() else ""
        has_action_verb = first_word in _ACTION_VERBS or first_word.rstrip("e") in _ACTION_VERBS

        # 2. Scenario trigger: "Use when..." / "Use for..." / "Call this..."
        has_scenario = bool(re.search(r"(?:use (?:this )?when|use for|call this)", desc, re.I))

        # 3. Parameter examples: concrete examples of inputs
        has_examples = bool(re.search(r"(?:e\.g\.|example|for instance|such as|like )", desc, re.I))

        # 4. Error guidance: failure modes and troubleshooting
        error_pat = (
            r"(?:error|fail|common issue|if .* fails"
            r"|troubleshoot|raise|exception|invalid)"
        )
        has_error_guidance = bool(re.search(error_pat, desc, re.I))

        # 5. Parameter documentation: mentions input parameters or accepted values
        has_param_docs = bool(re.search(
            r"(?:param(?:eter)?s?|input|argument|accepts?|takes?|requires?|expects?)\s*[:.]",
            desc, re.I,
        )) or bool(re.search(r"`\w+`", desc)) or bool(  # backtick-quoted param names
            re.search(r"--\w+", desc)  # CLI-style --flag params
        )

        # 6. Disambiguation: specificity vs other tools (using content words only)
        disambiguation = 1.0
        for other in tools:
            if other["name"] != name:
                other_desc = other.get("description", "")
                overlap = _word_overlap(desc, other_desc, stop_words)
                if overlap > 0.5:
                    disambiguation = min(disambiguation, max(0.0, 1.0 - overlap))

        # 7. Length score: penalize very short or excessively long
        length_score = 1.0
        if len(desc) < 20:
            length_score = 0.2
        elif len(desc) < 50:
            length_score = 0.5
        elif len(desc) < 80:
            length_score = 0.7
        elif len(desc) > 500:
            length_score = 0.7

        # 8. Semantic density: penalize keyword-stuffing / low-content text
        semantic_density = _semantic_density(desc)

        # Weighted scoring -- total weights = 10.0
        # Core structure (must-have for good scores):
        #   action_verb: 1.5  -- descriptions MUST start with a verb
        #   scenario:    3.0  -- "use when" is the most impactful guidance
        #   param_docs:  1.5  -- parameters need documentation
        # Quality signals:
        #   examples:    1.5  -- concrete examples help LLMs
        #   error:       1.0  -- failure guidance
        # Context signals:
        #   disambig:    1.0  -- distinctness from sibling tools
        #   length:      0.5  -- adequate length
        raw_score = (
            (1.0 if has_action_verb else 0.0) * 1.5
            + (1.0 if has_scenario else 0.0) * 3.0
            + (1.0 if has_param_docs else 0.0) * 1.5
            + (1.0 if has_examples else 0.0) * 1.5
            + (1.0 if has_error_guidance else 0.0) * 1.0
            + disambiguation * 1.0
            + length_score * 0.5
        )
        # Semantic density acts as a multiplier -- keyword-stuffed garbage
        # gets scaled down proportionally
        overall = raw_score * semantic_density

        scores.append(
            ToolDescriptionScore(
                tool_name=name,
                has_action_verb=has_action_verb,
                has_scenario_trigger=has_scenario,
                has_param_examples=has_examples,
                has_error_guidance=has_error_guidance,
                has_param_docs=has_param_docs,
                disambiguation_score=round(disambiguation, 2),
                overall_score=round(min(10.0, overall), 1),
            )
        )

    avg_score = sum(s.overall_score for s in scores) / len(scores) if scores else 5.0
    return round(avg_score, 1), scores, tool_names


def _extract_fastmcp_kwarg_tools(content: str) -> list[dict]:
    """Extract tools from FastMCP @mcp.tool(description="...") decorator-kwarg style.

    Uses paren-depth scanning instead of greedy regex to safely handle nested
    parentheses (e.g. annotations=ToolAnnotations(...)) without backtracking.
    """
    tools: list[dict] = []
    # Find all @<name>.tool( positions
    dec_pat = re.compile(r'@(?:mcp|server|app|fastmcp)\.tool\(')
    desc_pat = re.compile(r'description\s*=\s*(?:"([^"]*?)"|\'([^\']*?)\'|"""(.*?)""")', re.DOTALL)
    def_pat = re.compile(r'(?:async\s+)?def\s+(\w+)')

    for dec_match in dec_pat.finditer(content):
        start = dec_match.end()  # position after opening '('
        # Scan forward tracking paren depth to find matching ')'
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            ch = content[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            i += 1
        # content[start:i-1] is the decorator body
        dec_body = content[start:i - 1]

        # Look for description= kwarg inside the decorator body
        dm = desc_pat.search(dec_body)
        if dm is None:
            continue
        desc = (dm.group(1) or dm.group(2) or dm.group(3) or "").strip()

        # Look for 'def func_name' in the next ~100 chars after the decorator close
        after_dec = content[i:i + 100]
        fm = def_pat.search(after_dec)
        if fm is None:
            continue
        name = fm.group(1)
        if name:
            tools.append({"name": name, "description": desc})

    return tools


def _extract_tools(path: Path) -> list[dict]:
    """Extract tool definitions from Python, TypeScript, Go, and Rust MCP server code."""
    tools: list[dict] = []

    skip_dirs = {
        "node_modules", "__pycache__", ".venv", "venv", "env", ".env",
        ".git", "dist", "build", ".tox", ".mypy_cache",
        "site-packages", ".nox",
        # Exclude test directories to avoid extracting test fixtures as real tools
        "tests", "test", "__tests__", "spec", "fixtures", "fixture",
        "benchmarks", "benchmark", "testdata", "test_data",
        "e2e", "integration_tests",
    }

    # Monorepo detection: if path has many subdirs with their own package files,
    # try to find MCP-related subdirectories and prioritize those
    mcp_subdirs = _find_mcp_subdirs(path)
    search_root = path

    # Python: look for @tool or @server.tool decorators
    for py_file in path.rglob("*.py"):
        if any(part in skip_dirs for part in py_file.parts):
            continue
        # Skip test files by name
        if py_file.name.startswith("test_") or py_file.name.endswith("_test.py"):
            continue
        try:
            content = py_file.read_text(errors="ignore")
        except OSError:
            continue

        # FastMCP style: @mcp.tool() or @server.tool() with description in docstring
        tool_pattern = re.finditer(
            r'@(?:mcp|server|app)\.tool\(?\)?\s*(?:async\s+)?def\s+(\w+)\s*\([^)]*\).*?"""(.*?)"""',
            content,
            re.DOTALL,
        )
        for match in tool_pattern:
            tools.append({"name": match.group(1), "description": match.group(2).strip()})

        # FastMCP style with description kwarg: @mcp.tool(description="...", annotations=...)
        # postgres-mcp / FastMCP pattern where description is passed as a decorator kwarg.
        # Use depth-tracking scan to handle nested parens (e.g. annotations=Foo(...))
        # safely — avoids catastrophic backtracking with greedy .*? + DOTALL.
        for fastmcp_tool in _extract_fastmcp_kwarg_tools(content):
            if fastmcp_tool["name"] not in [t["name"] for t in tools]:
                tools.append(fastmcp_tool)

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

    # TypeScript: look for tool definitions in .ts/.js files
    for ts_file in list(path.rglob("*.ts")) + list(path.rglob("*.js")):
        if any(part in skip_dirs for part in ts_file.parts):
            continue
        # Skip test files and type definitions
        if (ts_file.name.endswith(".test.ts") or ts_file.name.endswith(".test.js")
                or ts_file.name.endswith(".spec.ts") or ts_file.name.endswith(".spec.js")
                or ts_file.name.endswith(".d.ts")):
            continue
        try:
            content = ts_file.read_text(errors="ignore")
        except OSError:
            continue

        existing_names = {t["name"] for t in tools}

        # Build const variable map for resolving references like TOOL_NAME, TOOL_DESCRIPTION
        const_vars: dict[str, str] = {}
        for m in re.finditer(
            r"const\s+(\w+)\s*(?::\s*\w+)?\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
        ):
            const_vars[m.group(1)] = (m.group(2) or m.group(3) or m.group(4) or "").strip()

        # Pattern 1: server.tool("name", { description: "..." }) or description: `...`
        tool_pattern = re.finditer(
            r"server\.tool\(\s*['\"](\w+)['\"].*?description:\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
            re.DOTALL,
        )
        for match in tool_pattern:
            name = match.group(1)
            desc = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 2: server.registerTool("name", { description: "..." | `...` })
        # Note: tool names can contain hyphens (e.g., "resolve-library-id")
        reg_pattern = re.finditer(
            r"server\.registerTool\(\s*['\"]([a-zA-Z_][\w-]*)['\"]"
            r"\s*,\s*\{[^}]*?description:\s*\n?\s*"
            r"(?:`([^`]+)`|((?:['\"][^'\"]*['\"](?:\s*\+\s*['\"][^'\"]*['\"])*))|['\"]([^'\"]*)['\"])",
            content,
            re.DOTALL,
        )
        for match in reg_pattern:
            name = match.group(1)
            if match.group(2):  # backtick template literal
                desc = re.sub(r"\s*\n\s*", " ", match.group(2)).strip()
            elif match.group(3):  # concatenated strings
                desc = "".join(re.findall(r"['\"]([^'\"]*)['\"]", match.group(3)))
            else:  # simple quoted string
                desc = (match.group(4) or "").strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc.strip()})
                existing_names.add(name)

        # Pattern 3: Object with name + description properties (Neon/PostgreSQL style)
        # Matches: { name: 'tool_name' (as const)?, ..., description: '...' | `...` }
        # Limit span to 400 chars to avoid spanning across unrelated objects (e.g.
        # Server constructor name matching a later tool's description).
        obj_tool_pattern = re.finditer(
            r"name:\s*(?:'([^']*)'|\"([^\"]*)\")\s*(?:as\s+const)?\s*,"
            r"(?:[^}]{0,400}?)description:\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
            re.DOTALL,
        )
        for match in obj_tool_pattern:
            name = (match.group(1) or match.group(2) or "").strip()
            desc = (match.group(3) or match.group(4) or match.group(5) or "").strip()
            # Clean up multi-line template literals
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            # Skip names that look like display labels (contain spaces or special chars)
            # MCP tool names are identifiers: snake_case, kebab-case, or camelCase
            if not name or " " in name or not re.match(r'^[a-zA-Z_][\w.-]*$', name):
                continue
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 4: Const variable resolution (git-mcp-server style)
        # Matches: { name: TOOL_NAME, description: TOOL_DESCRIPTION }
        const_ref_pattern = re.finditer(
            r"name:\s+(\w+)\s*,.*?description:\s+(\w+)\s*,",
            content,
            re.DOTALL,
        )
        for match in const_ref_pattern:
            name_var = match.group(1)
            desc_var = match.group(2)
            name = const_vars.get(name_var, "")
            desc = const_vars.get(desc_var, "")
            if name and desc and name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 5: Object literal tool defs (Supabase-style)
        # e.g. { tool_name: { description: '...', parameters: ... } }
        obj_pattern = re.finditer(
            r"(\w+)\s*:\s*\{\s*\n?\s*description\s*:\s*\n?\s*(?:'([^']*)'|\"([^\"]*)\"|`([^`]*)`)",
            content,
        )
        for match in obj_pattern:
            name = match.group(1)
            desc = (match.group(2) or match.group(3) or match.group(4) or "").strip()
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            skip_names = {
                "type", "default", "title", "label", "name",
                "id", "key", "value", "message", "description",
                "scope", "inputSchema", "outputSchema", "annotations",
            }
            if name in skip_names:
                continue
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 6: McpServer.tool() — @modelcontextprotocol/sdk pattern
        # McpServer instance may be named mcpServer, server, etc.
        # e.g. server.tool("name", { ... }, async (args) => { ... })
        #      server.tool("name", "description", { ... }, handler)
        #      server.tool("name", `multi-line template description`, { ... }, handler)
        ts_tool_str = re.finditer(
            r'\.tool\(\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'\s*,\s*(?:["\']([^"\']+)["\']|`([^`]+)`)',
            content,
            re.DOTALL,
        )
        for match in ts_tool_str:
            name = match.group(1)
            desc = (match.group(2) or match.group(3) or "").strip()
            # Clean up multi-line template literals
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 7: zodFunction / z.object tool definitions
        # e.g. { name: "tool_name", description: "...", parameters: z.object({...}) }
        # Limit span to prevent matching server constructor name against a later description.
        zod_pattern = re.finditer(
            r'name:\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'[^}]{0,300}?description:\s*["\']([^"\']+)["\']'
            r'[^}]{0,300}?(?:parameters|schema|inputSchema)\s*:',
            content,
            re.DOTALL,
        )
        for match in zod_pattern:
            name = match.group(1)
            desc = match.group(2).strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern 8: const name = "tool-name"; const config = { description: "..." };
        #            server.registerTool(name, config, handler)
        # Used in mcp-official/everything server — each tool in its own file with variable-based registration.
        # Safety: only activates when registerTool is called with `name` as a variable (not a string literal).
        if re.search(r'registerTool\(\s*\n?\s*name\s*,', content):
            name_match = re.search(r'const name\s*=\s*["\']([a-zA-Z_][\w-]*)["\']', content)
            desc_match = re.search(r'description:\s*["\']([^"\']+)["\']', content)
            if name_match:
                p8_name = name_match.group(1)
                p8_desc = desc_match.group(1).strip() if desc_match else ""
                if p8_name not in existing_names:
                    tools.append({"name": p8_name, "description": p8_desc})
                    existing_names.add(p8_name)

    # Go: look for tool definitions in .go files
    existing_names = {t["name"] for t in tools}
    for go_file in path.rglob("*.go"):
        if any(part in skip_dirs for part in go_file.parts):
            continue
        # Skip Go test files
        if go_file.name.endswith("_test.go"):
            continue
        try:
            content = go_file.read_text(errors="ignore")
        except OSError:
            continue

        # Go MCP SDK: mcp.NewTool("name", mcp.WithDescription("..."))
        go_newtool = re.finditer(
            r'mcp\.NewTool\(\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'.*?(?:WithDescription|mcp\.WithDescription)\(\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        )
        for match in go_newtool:
            name = match.group(1)
            desc = match.group(2).strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Go: mcp.Tool{Name: "...", Description: t("KEY", "desc")} or Description: "desc"
        # Supports: direct strings, backtick strings, t() translation wrapper
        go_tool_struct = re.finditer(
            r'mcp\.Tool\s*\{[^}]*?Name:\s*(?:"([a-zA-Z_][\w-]*)"|`([a-zA-Z_][\w-]*)`)'
            r'[^}]*?Description:\s*(?:'
            r't\(\s*"[^"]*"\s*,\s*(?:"([^"]+)"|`([^`]+)`)\s*\)'  # t("KEY", "desc") or t("KEY", `desc`)
            r'|"([^"]+)"'  # direct "desc"
            r'|`([^`]+)`'  # direct `desc`
            r')',
            content,
            re.DOTALL,
        )
        for match in go_tool_struct:
            name = (match.group(1) or match.group(2) or "").strip()
            desc = (match.group(3) or match.group(4) or match.group(5) or match.group(6) or "").strip()
            # Clean up multi-line backtick strings
            desc = re.sub(r"\s*\n\s*", " ", desc).strip()
            if name and desc and name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Go: server.AddTool(mcp.Tool{Name: "...", Description: "..."})
        # (fallback for simpler struct patterns without t() wrapper)
        go_addtool = re.finditer(
            r'(?:mcp\.)?Tool\s*\{[^}]*?Name:\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'[^}]*?Description:\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        )
        for match in go_addtool:
            name = match.group(1)
            desc = match.group(2).strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Go: s.AddTool("name", "description", handler)
        go_addtool2 = re.finditer(
            r'\.(?:AddTool|RegisterTool)\(\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'\s*,\s*["\']([^"\']+)["\']',
            content,
        )
        for match in go_addtool2:
            name = match.group(1)
            desc = match.group(2).strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Go: ToolDefinition{Name: "...", Description: "..."}
        go_tooldef = re.finditer(
            r'ToolDefinition\s*\{[^}]*?Name:\s*["\']([a-zA-Z_][\w-]*)["\']'
            r'[^}]*?Description:\s*["\']([^"\']+)["\']',
            content,
            re.DOTALL,
        )
        for match in go_tooldef:
            name = match.group(1)
            desc = match.group(2).strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

    # Rust: look for tool definitions in .rs files
    for rs_file in path.rglob("*.rs"):
        if any(part in skip_dirs for part in rs_file.parts):
            continue
        try:
            content = rs_file.read_text(errors="ignore")
        except OSError:
            continue

        # Rust: #[tool(description = "...")] or #[mcp_tool(...)]
        # followed by fn tool_name(...)
        rust_attr = re.finditer(
            r'#\[(?:tool|mcp_tool)\s*\([^)]*?description\s*=\s*"([^"]+)"[^)]*\)\]'
            r'\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)',
            content,
            re.DOTALL,
        )
        for match in rust_attr:
            desc = match.group(1).strip()
            name = match.group(2)
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Rust: Tool::new("name", "description")
        rust_new = re.finditer(
            r'Tool::new\(\s*"([a-zA-Z_][\w-]*)"\s*,\s*"([^"]+)"',
            content,
        )
        for match in rust_new:
            name = match.group(1)
            desc = match.group(2).strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Rust: ToolBuilder::new("name").description("...")
        rust_builder = re.finditer(
            r'ToolBuilder::new\(\s*"([a-zA-Z_][\w-]*)"\s*\)'
            r'.*?\.description\(\s*"([^"]+)"',
            content,
            re.DOTALL,
        )
        for match in rust_builder:
            name = match.group(1)
            desc = match.group(2).strip()
            if name not in existing_names:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

    # Fallback: if no tools found via code parsing, try README extraction
    if not tools:
        tools = _extract_tools_from_readme(path)

    return tools


def _find_mcp_subdirs(path: Path) -> list[Path]:
    """Detect monorepo structure and find MCP-related subdirectories."""
    # Look for subdirectories that contain MCP server code
    mcp_indicators = [
        "mcp", "server", "tool", "plugin",
    ]
    subdirs: list[Path] = []
    for child in path.iterdir():
        if not child.is_dir() or child.name.startswith("."):
            continue
        name_lower = child.name.lower()
        if any(ind in name_lower for ind in mcp_indicators):
            subdirs.append(child)
    return subdirs


def _extract_tools_from_readme(path: Path) -> list[dict]:
    """Fallback: extract tool names from README when code parsing fails.

    Many MCP servers document their tools in README with patterns like:
    - `tool_name` - Description
    - **tool_name**: Description
    - | tool_name | Description |
    """
    tools: list[dict] = []
    existing_names: set[str] = set()

    for readme_name in ("README.md", "readme.md", "README.rst"):
        readme = path / readme_name
        if not readme.exists():
            continue
        try:
            content = readme.read_text(errors="ignore")
        except OSError:
            continue

        # Look for a tools/commands section
        tools_section = re.search(
            r"(?:^#{1,3}\s+(?:Tools|Commands|Available Tools|API|Functions).*?\n)"
            r"(.*?)(?=\n#{1,3}\s|\Z)",
            content,
            re.MULTILINE | re.DOTALL | re.IGNORECASE,
        )
        if not tools_section:
            continue

        section = tools_section.group(1)

        # Pattern: `tool_name` - description  or  **tool_name** - description
        readme_tools = re.finditer(
            r"^\s*[-*]?\s*(?:`([a-zA-Z_][\w-]*)`|"
            r"\*\*([a-zA-Z_][\w-]*)\*\*)"
            r"\s*[-:–—]\s*(.+)",
            section,
            re.MULTILINE,
        )
        for match in readme_tools:
            name = (match.group(1) or match.group(2) or "").strip()
            desc = match.group(3).strip()
            if name and name not in existing_names and len(name) > 1:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

        # Pattern: markdown table | tool_name | description |
        table_tools = re.finditer(
            r"\|\s*`?([a-zA-Z_][\w-]*)`?\s*\|\s*([^|]+)\|",
            section,
        )
        for match in table_tools:
            name = match.group(1).strip()
            desc = match.group(2).strip()
            # Skip header rows
            if name.lower() in ("tool", "name", "command", "function", "---", ""):
                continue
            if name not in existing_names and len(name) > 1:
                tools.append({"name": name, "description": desc})
                existing_names.add(name)

    return tools


# Words that are scoring triggers -- don't count toward semantic content
_TRIGGER_WORDS = frozenset({
    "use", "when", "this", "for", "call", "the", "to", "a", "an", "is", "it",
    "e.g.", "example", "instance", "such", "as", "like",
    "error", "fail", "fails", "failed", "invalid", "exception", "raise",
    "troubleshoot", "common", "issue",
    "param", "parameter", "parameters", "input", "argument",
    "accepts", "takes", "requires", "expects",
    "if", "or", "and", "of", "in", "on", "by", "with", "from", "that",
    "not", "no", "do", "does", "did", "will", "can", "should", "may",
    "user", "wants",
})


def _semantic_density(desc: str) -> float:
    """Measure the ratio of meaningful content words vs trigger/filler words.

    Returns a multiplier between 0.3 and 1.0:
    - 1.0 = rich semantic content (most words carry meaning)
    - 0.3 = mostly trigger keywords with little real content

    This prevents keyword-stuffing from inflating scores.
    """
    if not desc.strip():
        return 1.0  # Don't penalize empty (already penalized by length)

    words = re.findall(r'[a-zA-Z_]\w*', desc.lower())
    if len(words) < 3:
        return 1.0  # Too short to judge density

    # Count unique content words (not trigger/filler)
    unique_content = {w for w in words if w not in _TRIGGER_WORDS and len(w) > 1}
    # Count total unique words
    unique_total = {w for w in words if len(w) > 1}

    if not unique_total:
        return 0.3

    density = len(unique_content) / len(unique_total)

    # Also penalize high word repetition (e.g. "read read read")
    if len(words) > 0:
        repetition_ratio = len(set(words)) / len(words)
    else:
        repetition_ratio = 1.0

    # Combine: low density OR high repetition = penalty
    combined = min(density, repetition_ratio)

    # Map to 0.3-1.0 range (never fully zero out a score)
    if combined >= 0.4:
        return 1.0
    elif combined >= 0.25:
        return 0.7
    else:
        return 0.3


def _word_overlap(a: str, b: str, stop_words: set[str] | None = None) -> float:
    """Calculate word overlap ratio between two strings, ignoring stop words."""
    words_a = set(a.lower().split()) - (stop_words or set())
    words_b = set(b.lower().split()) - (stop_words or set())
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    return len(intersection) / min(len(words_a), len(words_b))
