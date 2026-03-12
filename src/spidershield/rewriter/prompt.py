"""Structured prompt builder for LLM-powered description rewriting.

v2 improvements (E2, 2026-03-11):
- Added concrete few-shot examples demonstrating all 7 criteria
- Explicit mandatory requirements for SCENARIO TRIGGER (highest weight 3.0)
- Template draft + missing-signal diagnosis passed as starting context
- Score target made explicit (9.8/10) with per-criterion breakdown
"""

from __future__ import annotations

REWRITE_SYSTEM_PROMPT = """\
You are an expert at writing MCP tool descriptions that help AI agents select \
the correct tool. Your rewrites are scored on 7 criteria. You MUST hit 9.8/10.

SCORING RUBRIC (max 10.0 — you need all of these):
  1. ACTION VERB (1.5): Start with an imperative verb — "Query", "Create", "List", "Search"
  2. SCENARIO TRIGGER (3.0): MANDATORY "Use when the user wants to [5+ words]."
     This is the HIGHEST-WEIGHT criterion. Every description MUST have it.
  3. PARAMETER DOCS (1.5): List key params with `backtick` notation
     e.g., "Accepts `repo_owner`, `repo_name` (required), and `branch` (optional)."
  4. EXAMPLES (1.5): Concrete example with "e.g." or "such as"
     e.g., 'e.g., "main" or "feature/login-redesign"'
  5. ERROR GUIDANCE (1.0): One failure mode with "Raises" or "fails if" or "Returns error"
     e.g., "Raises an error if the table does not exist."
  6. DISAMBIGUATION (1.0): If similar tools exist, one sentence on when to prefer THIS tool
  7. LENGTH (0.5): Aim for 80-200 characters

FEW-SHOT EXAMPLES (perfect 10.0 descriptions):

BAD (score 1.5/10): "Get issues."
GOOD (score 10.0/10): "List open or closed issues for a GitHub repository. \
Use when the user wants to browse, filter, or review existing issues by state, \
label, or assignee. Accepts `owner` (required), `repo` (required), `state` \
(optional: \\"open\\" or \\"closed\\"), and `labels` (optional comma-separated string). \
e.g., owner=\\"octocat\\", repo=\\"hello-world\\", state=\\"open\\". \
Raises an error if the repository is private and the token lacks read access."

BAD (score 2.8/10): "Execute a SQL query against the database."
GOOD (score 10.0/10): "Execute a SQL query against the connected database and \
return the result rows. Use when the user wants to read or inspect data using \
a custom SQL statement. Accepts `sql` (required, string), e.g., \
\\'SELECT * FROM users LIMIT 10\\'. Raises an error if the connection is not \
established or the query contains a syntax error."

MANDATORY RULES:
- The "Use when the user wants to ..." sentence MUST appear — no exceptions
- NEVER write tautological triggers: "Use when the user wants to {just restate the tool name}"
- NEVER add generic security advice unrelated to the tool
- Preserve the original tool's semantics — do not broaden scope
- Return ONLY the description text — no markdown, no bullet points, no labels
- Keep under 200 words\
"""


def build_rewrite_prompt(
    tool_name: str,
    original_description: str,
    parameters: list[dict] | None = None,
    sibling_tools: list[dict] | None = None,
    template_draft: str | None = None,
    missing_signals: list[str] | None = None,
    template_score: float | None = None,
) -> tuple[str, str]:
    """Build (system_prompt, user_prompt) for LLM rewriting.

    v2 adds template_draft + missing_signals for score-aware prompting.

    Args:
        tool_name: Name of the tool to rewrite.
        original_description: Current description text.
        parameters: List of dicts with keys: name, type, required, description.
        sibling_tools: List of dicts with keys: name, description.
        template_draft: Optional template-based rewrite to use as starting point.
        missing_signals: List of missing criterion hints from diagnose_missing().
        template_score: _quick_score of the template_draft, if provided.

    Returns:
        (system_prompt, user_prompt) tuple.
    """
    parts = [
        f"Tool name: {tool_name}",
        f"Original description: {original_description}",
    ]

    if parameters:
        param_lines = []
        for p in parameters:
            req = " (required)" if p.get("required") else " (optional)"
            desc = f" -- {p['description']}" if p.get("description") else ""
            param_lines.append(f"  - `{p['name']}`: {p.get('type', 'string')}{req}{desc}")
        parts.append("Parameters:\n" + "\n".join(param_lines))

    if sibling_tools:
        sibling_lines = []
        for s in sibling_tools:
            if s["name"] != tool_name:
                desc_preview = s.get("description", "")[:60]
                sibling_lines.append(f"  - {s['name']}: {desc_preview}")
        if sibling_lines:
            parts.append("Other tools in this server:\n" + "\n".join(sibling_lines[:15]))

    # v2: Include template draft as starting point with score context
    if template_draft and template_draft != original_description:
        score_str = f" (scores {template_score:.1f}/10)" if template_score is not None else ""
        parts.append(
            f"Template draft{score_str}: {template_draft}\n"
            "The template draft above is a starting point. Improve it to hit 9.8/10."
        )
    elif template_draft == original_description:
        parts.append(
            "Note: Template rewriter returned the original unchanged. "
            "You must write a significantly improved version from scratch."
        )

    # v2: Explicitly list missing signals so LLM knows exactly what to add
    if missing_signals:
        parts.append(
            "MISSING criteria that MUST be added to reach 9.8/10:\n"
            + "\n".join(f"  - {s}" for s in missing_signals)
        )

    parts.append(
        "\nWrite a new description that hits ALL 7 criteria. "
        "Target score: 9.8/10. Return ONLY the description text."
    )

    return REWRITE_SYSTEM_PROMPT, "\n\n".join(parts)
