"""Enhanced quality gate for rewritten descriptions."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class GateResult:
    """Result of quality gate evaluation."""

    passed: bool
    description: str  # the description to use (original or rewritten)
    rejection_reason: str | None = None
    score: float = 0.0  # score of the accepted description


# Static tautological patterns (always rejected)
_TAUTOLOGY_PATTERNS = [
    r"Unlike \w+,? this tool specifically",
    r"verify the path is within allowed directories",
    r"Check file permissions if access is denied",
    r"Ensure (?:the |that )?\w+ (?:is|are) valid before",
]

# Words that are common in tool names (used for tautology detection)
_FILLER_WORDS = {"the", "a", "an", "to", "for", "of", "in", "on", "by", "with", "from", "this"}


def quality_gate(
    original: str,
    rewritten: str,
    tool_name: str = "",
    score_fn: Callable[..., object] | None = None,
) -> GateResult:
    """Return the rewrite only if it passes all quality checks.

    Args:
        original: Original description.
        rewritten: Proposed rewritten description.
        tool_name: Tool name (for tautology detection).
        score_fn: Scoring function (original, rewritten) -> (float, float).
                  If None, uses the built-in _quick_score.
    """
    orig_score = _quick_score(original)

    if original == rewritten:
        return GateResult(
            passed=False, description=original,
            rejection_reason="identical", score=orig_score,
        )

    # --- Grammar checks ---

    # Must start with a capital letter
    if rewritten and not rewritten[0].isupper():
        return GateResult(
            passed=False, description=original,
            rejection_reason="starts with lowercase", score=orig_score,
        )

    # Must end with punctuation
    if rewritten and rewritten[-1] not in ".!?)\"'":
        return GateResult(
            passed=False, description=original,
            rejection_reason="does not end with punctuation", score=orig_score,
        )

    # No repeated words at start (e.g. "Retrieve Retrieve")
    words = rewritten.split()
    if len(words) >= 2 and words[0].lower() == words[1].lower():
        return GateResult(
            passed=False, description=original,
            rejection_reason=f"repeated word: '{words[0]}'", score=orig_score,
        )

    # --- Tautology checks ---

    for pat in _TAUTOLOGY_PATTERNS:
        if re.search(pat, rewritten, re.IGNORECASE):
            return GateResult(
                passed=False, description=original,
                rejection_reason=f"tautological pattern: {pat}", score=orig_score,
            )

    # Short "Use when" triggers are tautological
    trigger_match = re.search(
        r"Use when the user wants to (.+?)\.(?:\s|$)",
        rewritten, re.IGNORECASE,
    )
    if trigger_match:
        trigger_body = trigger_match.group(1).split()
        if len(trigger_body) <= 3:
            return GateResult(
                passed=False, description=original,
                rejection_reason=f"tautological trigger: '{trigger_match.group(1)}'",
                score=orig_score,
            )

        # Check if trigger just restates the tool name
        if tool_name:
            name_words = set(tool_name.lower().replace("-", "_").split("_")) - _FILLER_WORDS
            trigger_words = {w.lower() for w in trigger_body} - _FILLER_WORDS
            if name_words and trigger_words and trigger_words <= name_words:
                return GateResult(
                    passed=False, description=original,
                    rejection_reason="trigger restates tool name",
                    score=orig_score,
                )

    # --- Semantic preservation ---

    # Key nouns from original must appear in rewrite
    orig_words = set(re.findall(r'[a-zA-Z]\w{2,}', original.lower()))
    new_words = set(re.findall(r'[a-zA-Z]\w{2,}', rewritten.lower()))
    common_filler = {
        "the", "and", "for", "with", "from", "that", "this", "all", "are",
        "has", "have", "been", "will", "can", "does", "not", "was", "were",
    }
    content_orig = orig_words - common_filler
    content_new = new_words - common_filler
    if content_orig and len(content_orig) >= 3:
        preserved = content_orig & content_new
        preservation_ratio = len(preserved) / len(content_orig)
        if preservation_ratio < 0.3:
            return GateResult(
                passed=False, description=original,
                rejection_reason=f"lost key nouns (preserved {preservation_ratio:.0%})",
                score=orig_score,
            )

    # --- Length bounds ---
    if len(rewritten) > 1500:
        return GateResult(
            passed=False, description=original,
            rejection_reason="too long (>1500 chars)", score=orig_score,
        )

    # --- Score improvement ---
    if score_fn:
        orig_score, new_score = score_fn(original, rewritten)
    else:
        new_score = _quick_score(rewritten)

    if new_score <= orig_score:
        return GateResult(
            passed=False, description=original,
            rejection_reason=f"no score improvement ({orig_score} -> {new_score})",
            score=orig_score,
        )

    return GateResult(passed=True, description=rewritten, score=new_score)


def verify_disambiguation(desc: str, sibling_tools: list[dict]) -> list[str]:
    """Verify that tool names referenced in 'Do not use when' actually exist.

    Returns a list of warnings (empty = all references valid).
    Prevents hallucinated tool names from reaching PRs.
    """
    if not sibling_tools:
        return []

    sibling_names = {t["name"].lower() for t in sibling_tools}

    # Extract "use X instead" references from the description
    refs = re.findall(r"use\s+(\w+)\s+instead", desc, re.IGNORECASE)
    warnings = []
    for ref in refs:
        if ref.lower() not in sibling_names:
            warnings.append(
                f"Referenced tool '{ref}' in 'Do not use when' does not exist "
                f"in sibling tools. Valid tools: {', '.join(sorted(sibling_names)[:5])}"
            )
    return warnings


def diagnose_missing(desc: str, min_score: float = 9.8) -> list[str]:
    """Identify which scoring criteria are missing from a description.

    Returns a list of human-readable improvement hints for the LLM retry.
    """
    from spidershield.scanner.description_quality import _ACTION_VERBS

    hints = []
    if not desc.strip():
        return ["Description is empty."]

    first_word = desc.split()[0].lower().rstrip("s")
    has_verb = first_word in _ACTION_VERBS or first_word.rstrip("e") in _ACTION_VERBS
    if not has_verb:
        hints.append(
            "Missing ACTION VERB: Start with an imperative verb "
            "(e.g., List, Query, Create, Delete, Check)."
        )

    has_scenario = bool(re.search(r"(?:use (?:this )?when|use for|call this)", desc, re.I))
    if not has_scenario:
        hints.append(
            'Missing SCENARIO TRIGGER: Add "Use when..." guidance with 5+ words '
            '(e.g., "Use when you need to review staged changes before committing.").'
        )

    has_param_docs = bool(re.search(
        r"(?:param(?:eter)?s?|input|argument|accepts?|takes?|requires?|expects?)\s*[:.)]\s",
        desc, re.I,
    )) or bool(re.search(r"`\w+`", desc)) or bool(re.search(r"--\w+", desc))
    if not has_param_docs:
        hints.append(
            "Missing PARAMETER DOCS: Mention key parameters using `backtick` notation "
            "or --flag style (e.g., 'Accepts `path` and `encoding` parameters.')."
        )

    has_examples = bool(re.search(r"(?:e\.g\.|example|for instance|such as|like )", desc, re.I))
    if not has_examples:
        hints.append(
            'Missing EXAMPLES: Add concrete examples with "e.g." or "such as" '
            '(e.g., \'e.g., "main" or "feature-branch"\').'
        )

    has_error = bool(
        re.search(
            r"(?:error|fail|common issue|if .* fails|troubleshoot|raise|exception|invalid)",
            desc, re.I,
        )
    )
    if not has_error:
        hints.append(
            "Missing ERROR GUIDANCE: Mention a failure mode "
            '(e.g., "Raises an error if the table does not exist.").'
        )

    has_disambiguation = bool(re.search(
        r"(?:do not use when|avoid (?:this )?when|not (?:intended|designed) for"
        r"|prefer .+? instead|use .+? instead(?:\b|[.,]))",
        desc, re.I,
    ))
    if not has_disambiguation:
        hints.append(
            "Missing DISAMBIGUATION: Add a sentence like "
            '"Do not use when [condition] (use [alternative_tool] instead)." '
            "to distinguish this tool from overlapping sibling tools."
        )

    score = _quick_score(desc)
    if score >= min_score:
        return []  # Already meets threshold

    return hints


def _quick_score(desc: str) -> float:
    """Quick-score a description using the same criteria as the scanner."""
    from spidershield.scanner.description_quality import _ACTION_VERBS, _semantic_density

    first_word = desc.split()[0].lower().rstrip("s") if desc.strip() else ""
    has_verb = first_word in _ACTION_VERBS or first_word.rstrip("e") in _ACTION_VERBS
    has_scenario = bool(re.search(r"(?:use (?:this )?when|use for|call this)", desc, re.I))
    has_examples = bool(re.search(r"(?:e\.g\.|example|for instance|such as|like )", desc, re.I))
    has_error = bool(
        re.search(
            r"(?:error|fail|common issue|if .* fails|troubleshoot|raise|exception|invalid)",
            desc, re.I,
        )
    )
    has_param_docs = bool(re.search(
        r"(?:param(?:eter)?s?|input|argument|accepts?|takes?|requires?|expects?)\s*[:.)]\s",
        desc, re.I,
    )) or bool(re.search(r"`\w+`", desc)) or bool(
        re.search(r"--\w+", desc)
    )

    has_disambiguation = bool(re.search(
        r"(?:do not use when|avoid (?:this )?when|not (?:intended|designed) for"
        r"|prefer .+? instead|use .+? instead(?:\b|[.,]))",
        desc, re.I,
    ))

    length_score = 1.0
    if len(desc) < 20:
        length_score = 0.2
    elif len(desc) < 50:
        length_score = 0.5
    elif len(desc) < 80:
        length_score = 0.7
    elif len(desc) > 500:
        length_score = 0.7

    raw_score = (
        (1.0 if has_verb else 0.0) * 1.5
        + (1.0 if has_scenario else 0.0) * 3.0
        + (1.0 if has_param_docs else 0.0) * 1.5
        + (1.0 if has_examples else 0.0) * 1.5
        + (1.0 if has_error else 0.0) * 1.0
        + (1.0 if has_disambiguation else 0.0) * 1.0
        + length_score * 0.5
    )
    score = raw_score * _semantic_density(desc)

    return round(min(10.0, score), 1)
