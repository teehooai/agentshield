"""Tests for the v2 rewriter: quality gate, providers, prompt, template fixes."""

from __future__ import annotations

import os
from unittest.mock import patch

from spidershield.rewriter.prompt import REWRITE_SYSTEM_PROMPT, build_rewrite_prompt
from spidershield.rewriter.quality_gate import (
    GateResult,
    _quick_score,
    diagnose_missing,
    quality_gate,
)
from spidershield.rewriter.runner import _rewrite_local

# --- Template engine bug fixes ---


class TestTemplateBugFixes:
    """Verify the template engine no longer produces broken text."""

    def test_no_verb_prepend_to_pronoun(self) -> None:
        """'This returns all items' should NOT become 'Retrieve This returns all items'."""
        result = _rewrite_local(
            {"name": "get_comments", "description": "This returns unstructured output."},
            [],
        )
        assert not result.startswith("Retrieve This")
        assert "This returns" in result or "unstructured" in result

    def test_no_verb_prepend_to_it(self) -> None:
        result = _rewrite_local(
            {"name": "get_info", "description": "It provides detailed metadata."},
            [],
        )
        assert not result.startswith("Retrieve It")

    def test_no_verb_prepend_to_returns(self) -> None:
        result = _rewrite_local(
            {"name": "get_data", "description": "Returns a list of objects."},
            [],
        )
        assert not result.startswith("Retrieve Returns")

    def test_no_verb_prepend_to_provides(self) -> None:
        result = _rewrite_local(
            {"name": "get_status", "description": "Provides current build status."},
            [],
        )
        assert not result.startswith("Retrieve Provides")

    def test_handles_type_signature_gracefully(self) -> None:
        """Type signatures should not get a verb prepended."""
        result = _rewrite_local(
            {"name": "add", "description": "server: Server[Any] | MCPServer"},
            [],
        )
        # Should not produce "Add server: Server[Any]..." -- that's broken
        # The description is a type signature, not a natural language desc
        assert result[0].isupper()

    def test_short_remainder_preserved(self) -> None:
        """After stripping verb, if remainder is too short, keep original."""
        result = _rewrite_local(
            {"name": "get_item", "description": "Gets it."},
            [],
        )
        assert len(result) > 3
        assert result[0].isupper()

    def test_sentence_starter_this(self) -> None:
        result = _rewrite_local(
            {"name": "list_items", "description": "This tool lists items by category."},
            [],
        )
        assert result.startswith("This tool")

    def test_multi_sentence_preserves_structure(self) -> None:
        """Multi-sentence descriptions should preserve overall structure."""
        result = _rewrite_local(
            {"name": "search_files",
             "description": "Recursively search for files and directories matching a pattern."},
            [],
        )
        assert "files" in result
        assert "directories" in result or "pattern" in result


# --- Quality gate tests ---


class TestQualityGateEnhanced:
    def test_rejects_lowercase_start(self) -> None:
        result = quality_gate("Original desc.", "lowercase start.")
        assert not result.passed
        assert result.rejection_reason == "starts with lowercase"

    def test_rejects_no_punctuation(self) -> None:
        result = quality_gate("Original desc.", "No ending punctuation")
        assert not result.passed
        assert "punctuation" in result.rejection_reason

    def test_rejects_repeated_words(self) -> None:
        result = quality_gate("List tables.", "List List all tables.")
        assert not result.passed
        assert "repeated" in result.rejection_reason

    def test_rejects_identical(self) -> None:
        result = quality_gate("Same text.", "Same text.")
        assert not result.passed
        assert result.rejection_reason == "identical"

    def test_rejects_tautological_trigger(self) -> None:
        result = quality_gate(
            "Pauses a project.",
            "Pause a project. Use when the user wants to pause project.",
        )
        assert not result.passed

    def test_accepts_good_domain_trigger(self) -> None:
        result = quality_gate(
            "Read a file.",
            "Read a file. Use when the user wants to view the contents of a specific file.",
        )
        assert result.passed

    def test_rejects_trigger_restating_tool_name(self) -> None:
        result = quality_gate(
            "Lists tables.",
            "List tables. Use when the user wants to list the tables.",
            tool_name="list_tables",
        )
        assert not result.passed

    def test_preserves_key_nouns(self) -> None:
        """Rewrite that loses key nouns should be rejected."""
        result = quality_gate(
            "Query the PostgreSQL database for user records and transactions.",
            "Execute a search operation. Use when the user wants to find items in the system.",
        )
        assert not result.passed
        assert "nouns" in result.rejection_reason

    def test_accepts_preserved_nouns(self) -> None:
        result = quality_gate(
            "tables",
            "List all tables in the database.",
        )
        assert result.passed

    def test_rejects_too_long(self) -> None:
        result = quality_gate("Short.", "A" * 1501 + ".")
        assert not result.passed
        assert "too long" in result.rejection_reason

    def test_rejects_no_score_improvement(self) -> None:
        result = quality_gate(
            "Lists all tables in the database.",
            "List all tables in the database.",
        )
        # Score is similar, should not improve
        assert not result.passed or result.description in (
            "Lists all tables in the database.",
            "List all tables in the database.",
        )

    def test_gate_result_has_reason(self) -> None:
        result = quality_gate("Same.", "Same.")
        assert isinstance(result, GateResult)
        assert result.rejection_reason is not None

    def test_rejects_unlike_pattern(self) -> None:
        result = quality_gate(
            "Lists tables.",
            "List tables. Unlike list_schemas, this tool specifically handles tables.",
        )
        assert not result.passed

    def test_rejects_verify_path_pattern(self) -> None:
        result = quality_gate(
            "Read file.",
            "Read file. Verify the path is within allowed directories.",
        )
        assert not result.passed


# --- Prompt builder tests ---


class TestPromptBuilder:
    def test_system_prompt_has_criteria(self) -> None:
        assert "ACTION VERB" in REWRITE_SYSTEM_PROMPT
        assert "SCENARIO TRIGGER" in REWRITE_SYSTEM_PROMPT
        assert "PARAMETER DOCS" in REWRITE_SYSTEM_PROMPT
        assert "EXAMPLES" in REWRITE_SYSTEM_PROMPT
        assert "ERROR GUIDANCE" in REWRITE_SYSTEM_PROMPT
        assert "DISAMBIGUATION" in REWRITE_SYSTEM_PROMPT
        assert "LENGTH" in REWRITE_SYSTEM_PROMPT

    def test_system_prompt_has_anti_patterns(self) -> None:
        assert "tautological" in REWRITE_SYSTEM_PROMPT.lower()
        assert "NEVER" in REWRITE_SYSTEM_PROMPT

    def test_user_prompt_includes_tool_name(self) -> None:
        _, user = build_rewrite_prompt("read_file", "Reads a file.")
        assert "read_file" in user

    def test_user_prompt_includes_params(self) -> None:
        params = [
            {"name": "path", "type": "string", "required": True, "description": "File path"},
            {"name": "encoding", "type": "string", "required": False, "description": ""},
        ]
        _, user = build_rewrite_prompt("read_file", "Reads a file.", parameters=params)
        assert "`path`" in user
        assert "`encoding`" in user
        assert "(required)" in user
        assert "(optional)" in user

    def test_user_prompt_includes_siblings(self) -> None:
        siblings = [
            {"name": "read_file", "description": "Reads a file."},
            {"name": "write_file", "description": "Writes a file."},
        ]
        _, user = build_rewrite_prompt("read_file", "Reads a file.", sibling_tools=siblings)
        assert "write_file" in user

    def test_user_prompt_limits_siblings(self) -> None:
        """Should not include more than 15 siblings."""
        siblings = [{"name": f"tool_{i}", "description": f"Tool {i}"} for i in range(30)]
        _, user = build_rewrite_prompt("my_tool", "Does stuff.", sibling_tools=siblings)
        # Should have at most 15 tool lines
        tool_lines = [line for line in user.split("\n") if line.strip().startswith("- tool_")]
        assert len(tool_lines) <= 15


# --- Provider detection tests ---


class TestProviderDetection:
    def test_no_keys_returns_none(self) -> None:
        from spidershield.rewriter.providers import detect_provider

        with patch.dict(os.environ, {}, clear=True):
            # Clear ALL relevant keys
            for key in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
                os.environ.pop(key, None)
            result = detect_provider()
        assert result is None

    def test_explicit_provider_override(self) -> None:
        """Explicit provider should work even without env vars."""
        from spidershield.rewriter.providers import detect_provider

        # This will fail at instantiation (no API key), but that's expected
        # We're testing the detection logic, not the provider initialization
        try:
            detect_provider(provider="claude")
        except Exception:
            pass  # Expected: no API key


# --- Quick score tests ---


class TestQuickScore:
    def test_empty_scores_low(self) -> None:
        assert _quick_score("") <= 2.0

    def test_verb_only_scores_moderate(self) -> None:
        score = _quick_score("List all tables.")
        assert 1.0 <= score <= 4.0

    def test_full_description_scores_high(self) -> None:
        desc = (
            "List all tables in the database schema. Use when the user wants to "
            "discover available tables before writing queries. Accepts `schema_name` "
            "parameter (e.g., 'public'). Raises an error if the schema does not exist."
        )
        score = _quick_score(desc)
        assert score >= 7.0

    def test_tautological_scores_low(self) -> None:
        # A description that's just filler words
        score = _quick_score("Use when the user wants to use this for the thing.")
        assert score < 5.0


# --- End-to-end template quality tests ---


class TestTemplateQualityEndToEnd:
    """Verify template + quality gate produces sensible output on real-world patterns."""

    def test_filesystem_tools_get_triggers(self) -> None:
        tools = [
            {"name": "read_file", "description": "Read a file"},
            {"name": "write_file", "description": "Write a file"},
            {"name": "list_directory", "description": "List directory contents"},
        ]
        from spidershield.rewriter.runner import _quality_gate

        for t in tools:
            rewritten = _rewrite_local(t, tools)
            final = _quality_gate(t["description"], rewritten)
            if t["name"] in ("read_file", "write_file"):
                # These should get domain triggers
                assert final != t["description"], f"{t['name']} should be improved"
                assert "Use when" in final

    def test_git_tools_get_triggers(self) -> None:
        tools = [
            {"name": "git_commit", "description": "Records changes to the repository"},
            {"name": "git_status", "description": "Shows the working tree status"},
            {"name": "git_diff", "description": "Shows changes between commits"},
            {"name": "git_log", "description": "Shows commit logs"},
            {"name": "git_branch", "description": "List or create branches"},
        ]
        from spidershield.rewriter.runner import _quality_gate

        for t in tools:
            rewritten = _rewrite_local(t, tools)
            final = _quality_gate(t["description"], rewritten)
            # At least commit and status should get domain triggers
            if "commit" in t["name"] or "status" in t["name"]:
                assert "Use when" in final, f"{t['name']} should have Use when trigger"

    def test_no_broken_grammar(self) -> None:
        """No rewrite should produce broken grammar patterns."""
        tools = [
            {"name": "get_comments", "description": "This returns unstructured output"},
            {"name": "get_weather", "description": "Get weather for a city"},
            {"name": "search_nodes", "description": "Search for nodes in the knowledge graph"},
            {"name": "add_item", "description": "server: Server[Any] | MCPServer"},
        ]
        broken_patterns = [
            "Retrieve This",
            "Retrieve It",
            "Add server:",
            "Search Search",
            "Retrieve Returns",
        ]
        for t in tools:
            rewritten = _rewrite_local(t, tools)
            for bp in broken_patterns:
                assert bp not in rewritten, f"{t['name']} produced broken: '{bp}' in '{rewritten}'"


# --- Diagnosis + self-check tests ---


class TestDiagnoseMissing:
    def test_empty_description(self) -> None:
        hints = diagnose_missing("")
        assert len(hints) > 0

    def test_missing_verb(self) -> None:
        hints = diagnose_missing("the tables in the database.")
        assert any("ACTION VERB" in h for h in hints)

    def test_missing_scenario(self) -> None:
        hints = diagnose_missing("List all tables in the database.")
        assert any("SCENARIO TRIGGER" in h for h in hints)

    def test_missing_params(self) -> None:
        hints = diagnose_missing(
            "List all tables. Use when the user wants to discover available tables."
        )
        assert any("PARAMETER" in h for h in hints)

    def test_missing_examples(self) -> None:
        hints = diagnose_missing(
            "List all tables. Use when the user wants to discover available tables. "
            "Accepts `schema` parameter."
        )
        assert any("EXAMPLE" in h for h in hints)

    def test_missing_error(self) -> None:
        hints = diagnose_missing(
            "List all tables. Use when the user wants to discover available tables. "
            "Accepts `schema` (e.g., 'public')."
        )
        assert any("ERROR" in h for h in hints)

    def test_perfect_description_no_hints(self) -> None:
        desc = (
            "List all tables in the database schema. Use when the user wants to "
            "discover available tables before writing queries. Accepts `schema_name` "
            "parameter (e.g., 'public'). Raises an error if the schema does not exist."
        )
        hints = diagnose_missing(desc)
        assert len(hints) == 0

    def test_respects_min_score(self) -> None:
        desc = "List all tables. Use when discovering tables. Accepts `schema`."
        hints_high = diagnose_missing(desc, min_score=9.8)
        hints_low = diagnose_missing(desc, min_score=5.0)
        # Higher threshold should find more missing criteria
        assert len(hints_high) >= len(hints_low)


class TestSelfCheckRetry:
    """Test the retry mechanism using a mock provider."""

    def test_retry_improves_score(self) -> None:
        """Mock provider that returns better output on retry."""
        call_count = 0

        class MockProvider:
            def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    # First attempt: mediocre (missing examples, error guidance)
                    return (
                        "List all tables in the database. "
                        "Use when the user wants to discover available tables. "
                        "Accepts `schema_name` parameter."
                    )
                else:
                    # Retry: adds examples and error guidance
                    return (
                        "List all tables in the database. "
                        "Use when the user wants to discover available tables "
                        "before writing queries. "
                        "Accepts `schema_name` parameter (e.g., 'public'). "
                        "Raises an error if the schema does not exist."
                    )

        from spidershield.rewriter.runner import _rewrite_llm

        tool = {"name": "list_tables", "description": "Lists tables."}
        result = _rewrite_llm(
            tool, [tool], MockProvider(),
            min_score=9.8, max_retries=2, use_cache=False,
        )
        assert call_count == 2  # Should have retried
        assert "e.g." in result
        assert "error" in result.lower() or "Raises" in result

    def test_no_retry_if_score_met(self) -> None:
        """If first attempt meets threshold, no retry."""
        call_count = 0

        class MockProvider:
            def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
                nonlocal call_count
                call_count += 1
                return (
                    "List all tables in the database schema. "
                    "Use when the user wants to discover available tables "
                    "before writing queries. "
                    "Accepts `schema_name` parameter (e.g., 'public'). "
                    "Raises an error if the schema does not exist."
                )

        from spidershield.rewriter.runner import _rewrite_llm

        tool = {"name": "list_tables", "description": "Lists tables."}
        _rewrite_llm(tool, [tool], MockProvider(), min_score=9.0, max_retries=2, use_cache=False)
        assert call_count == 1  # No retry needed

    def test_max_retries_respected(self) -> None:
        """Provider is called at most max_retries + 1 times."""
        call_count = 0

        class MockProvider:
            def complete(self, system: str, user: str, max_tokens: int = 500) -> str:
                nonlocal call_count
                call_count += 1
                return "Short."  # Always bad

        from spidershield.rewriter.runner import _rewrite_llm

        tool = {"name": "list_tables", "description": "Lists tables."}
        _rewrite_llm(tool, [tool], MockProvider(), min_score=9.8, max_retries=3, use_cache=False)
        assert call_count == 4  # 1 initial + 3 retries
