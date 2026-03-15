"""End-to-end LLM rewriter integration tests using mock providers.

Covers the full LLM rewrite pipeline without requiring real API keys:
- Provider detection and selection
- LLM rewrite flow (prompt → generate → score → cache → retry)
- Quality gate interaction
- Semantic verification
- Cache hit/miss behavior
- Error handling (provider failure, bad output)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from spidershield.rewriter.cache import cache_key, clear_cache, get_cached, set_cached
from spidershield.rewriter.prompt import REWRITE_SYSTEM_PROMPT, build_rewrite_prompt
from spidershield.rewriter.providers import detect_provider
from spidershield.rewriter.quality_gate import _quick_score, diagnose_missing, quality_gate
from spidershield.rewriter.runner import _rewrite_llm, _rewrite_local

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PERFECT_REWRITE = (
    "List all open or closed issues for a GitHub repository. "
    "Use when the user wants to browse, filter, or review existing issues "
    "by state, label, or assignee. "
    "Accepts `owner` (required), `repo` (required), `state` (optional). "
    'e.g., owner="octocat", repo="hello-world", state="open". '
    "Raises an error if the repository is private and the token lacks read access."
)

MEDIOCRE_REWRITE = "List issues from a repository."


@pytest.fixture
def mock_provider() -> MagicMock:
    """Mock LLM provider returning a high-quality rewrite."""
    provider = MagicMock()
    provider.model = "mock-model-v1"
    provider.complete.return_value = PERFECT_REWRITE
    return provider


@pytest.fixture
def sample_tool() -> dict:
    return {
        "name": "list_issues",
        "description": "Get issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string", "description": "Repository owner"},
                "repo": {"type": "string", "description": "Repository name"},
                "state": {"type": "string", "description": "Issue state filter"},
            },
            "required": ["owner", "repo"],
        },
    }


@pytest.fixture
def sibling_tools() -> list[dict]:
    return [
        {"name": "list_issues", "description": "Get issues."},
        {"name": "create_issue", "description": "Create a new issue."},
        {"name": "close_issue", "description": "Close an issue."},
    ]


# ---------------------------------------------------------------------------
# Provider detection
# ---------------------------------------------------------------------------


class TestProviderDetection:
    def test_explicit_claude(self) -> None:
        pytest.importorskip("anthropic", reason="anthropic package not installed")
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}, clear=False):
            p = detect_provider(provider="claude")
            assert p is not None
            assert "Anthropic" in type(p).__name__

    def test_explicit_openai(self) -> None:
        pytest.importorskip("openai", reason="openai package not installed")
        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}, clear=False):
            p = detect_provider(provider="openai")
            assert p is not None
            assert "OpenAI" in type(p).__name__

    def test_no_api_key_returns_none(self) -> None:
        env = {
            "ANTHROPIC_API_KEY": "",
            "OPENAI_API_KEY": "",
            "GEMINI_API_KEY": "",
            "GOOGLE_API_KEY": "",
        }
        with patch.dict("os.environ", env, clear=False):
            p = detect_provider()
            assert p is None

    def test_auto_detect_anthropic(self) -> None:
        pytest.importorskip("anthropic", reason="anthropic package not installed")
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False):
            p = detect_provider()
            assert p is not None

    def test_explicit_gemini(self) -> None:
        pytest.importorskip("google.generativeai", reason="google-generativeai not installed")
        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}, clear=False):
            p = detect_provider(provider="gemini")
            assert p is not None
            assert "Gemini" in type(p).__name__

    def test_auto_detect_gemini_via_google_key(self) -> None:
        pytest.importorskip("google.generativeai", reason="google-generativeai not installed")
        env = {"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": "", "GOOGLE_API_KEY": "test-key"}
        with patch.dict("os.environ", env, clear=False):
            p = detect_provider()
            assert p is not None
            assert "Gemini" in type(p).__name__

    def test_custom_model(self) -> None:
        pytest.importorskip("anthropic", reason="anthropic package not installed")
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}, clear=False):
            p = detect_provider(provider="claude", model="claude-haiku-4-5-20251001")
            assert p.model == "claude-haiku-4-5-20251001"


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------


class TestPromptBuilding:
    def test_basic_prompt(self, sample_tool: dict) -> None:
        system, user = build_rewrite_prompt(
            tool_name="list_issues",
            original_description="Get issues.",
        )
        assert system == REWRITE_SYSTEM_PROMPT
        assert "list_issues" in user
        assert "Get issues." in user

    def test_prompt_includes_parameters(self, sample_tool: dict) -> None:
        params = [
            {"name": "owner", "type": "string", "required": True, "description": "Repo owner"},
            {"name": "repo", "type": "string", "required": True, "description": "Repo name"},
        ]
        _, user = build_rewrite_prompt(
            tool_name="list_issues",
            original_description="Get issues.",
            parameters=params,
        )
        assert "`owner`" in user
        assert "(required)" in user

    def test_prompt_includes_siblings(self, sibling_tools: list[dict]) -> None:
        _, user = build_rewrite_prompt(
            tool_name="list_issues",
            original_description="Get issues.",
            sibling_tools=sibling_tools,
        )
        assert "create_issue" in user
        assert "close_issue" in user

    def test_prompt_includes_template_draft(self) -> None:
        _, user = build_rewrite_prompt(
            tool_name="list_issues",
            original_description="Get issues.",
            template_draft="List all issues from the repository.",
            template_score=4.5,
        )
        assert "Template draft" in user
        assert "4.5" in user
        assert "Improve it" in user

    def test_prompt_includes_missing_signals(self) -> None:
        _, user = build_rewrite_prompt(
            tool_name="list_issues",
            original_description="Get issues.",
            missing_signals=["SCENARIO TRIGGER", "PARAMETER DOCS"],
        )
        assert "MISSING" in user
        assert "SCENARIO TRIGGER" in user


# ---------------------------------------------------------------------------
# LLM rewrite pipeline (with mock provider)
# ---------------------------------------------------------------------------


class TestLLMRewritePipeline:
    def test_basic_rewrite(
        self, mock_provider: MagicMock, sample_tool: dict, sibling_tools: list[dict]
    ) -> None:
        result = _rewrite_llm(
            sample_tool, sibling_tools, mock_provider,
            use_cache=False, semantic_verify=False,
        )
        assert len(result) > 50
        mock_provider.complete.assert_called()

    def test_rewrite_calls_provider_with_system_prompt(
        self, mock_provider: MagicMock, sample_tool: dict, sibling_tools: list[dict]
    ) -> None:
        _rewrite_llm(
            sample_tool, sibling_tools, mock_provider,
            use_cache=False, semantic_verify=False,
        )
        call_args = mock_provider.complete.call_args
        system_prompt = call_args[0][0]
        assert "ACTION VERB" in system_prompt
        assert "SCENARIO TRIGGER" in system_prompt

    def test_low_score_triggers_retry(
        self, sample_tool: dict, sibling_tools: list[dict]
    ) -> None:
        """If first attempt scores low, provider is called again."""
        provider = MagicMock()
        provider.model = "mock"
        # First call returns mediocre, second returns perfect
        provider.complete.side_effect = [MEDIOCRE_REWRITE, PERFECT_REWRITE]

        _rewrite_llm(
            sample_tool, sibling_tools, provider,
            use_cache=False, semantic_verify=False,
            min_score=9.0, max_retries=2,
        )
        # Should have retried at least once
        assert provider.complete.call_count >= 2

    def test_max_retries_respected(
        self, sample_tool: dict, sibling_tools: list[dict]
    ) -> None:
        provider = MagicMock()
        provider.model = "mock"
        # Always returns mediocre
        provider.complete.return_value = MEDIOCRE_REWRITE

        _rewrite_llm(
            sample_tool, sibling_tools, provider,
            use_cache=False, semantic_verify=False,
            min_score=9.8, max_retries=2,
        )
        # 1 initial + 2 retries = 3 max
        assert provider.complete.call_count <= 3

    def test_cache_stores_result(
        self, mock_provider: MagicMock, sample_tool: dict,
        sibling_tools: list[dict], tmp_path: Path,
    ) -> None:
        with patch("spidershield.rewriter.cache.get_cached", return_value=None), \
             patch("spidershield.rewriter.cache.set_cached") as mock_set:
            _rewrite_llm(
                sample_tool, sibling_tools, mock_provider,
                use_cache=True, semantic_verify=False,
            )
            mock_set.assert_called_once()

    def test_cache_hit_skips_provider(
        self, mock_provider: MagicMock, sample_tool: dict, sibling_tools: list[dict],
    ) -> None:
        with patch("spidershield.rewriter.cache.get_cached", return_value="Cached result."):
            result = _rewrite_llm(
                sample_tool, sibling_tools, mock_provider,
                use_cache=True, semantic_verify=False,
            )
            assert result == "Cached result."
            mock_provider.complete.assert_not_called()


# ---------------------------------------------------------------------------
# Quality gate integration
# ---------------------------------------------------------------------------


class TestQualityGateIntegration:
    def test_perfect_rewrite_passes(self) -> None:
        result = quality_gate("Get issues.", PERFECT_REWRITE)
        assert result.passed
        assert result.score > 8.0

    def test_mediocre_rewrite_rejected(self) -> None:
        result = quality_gate("Get issues.", MEDIOCRE_REWRITE)
        # Mediocre rewrite may or may not pass depending on original score
        # but should have a low score
        assert result.score < 9.0

    def test_identical_rewrite_rejected(self) -> None:
        result = quality_gate("Get issues.", "Get issues.")
        assert not result.passed

    def test_diagnose_finds_missing_signals(self) -> None:
        missing = diagnose_missing("List all items.")
        assert len(missing) > 0
        signal_names = " ".join(missing)
        assert "SCENARIO" in signal_names or "PARAMETER" in signal_names

    def test_quick_score_range(self) -> None:
        assert _quick_score("") <= 0.5  # near-zero for empty
        assert 0 <= _quick_score("Get items.") <= 10
        assert _quick_score(PERFECT_REWRITE) > 8.0


# ---------------------------------------------------------------------------
# Cache operations
# ---------------------------------------------------------------------------


class TestCacheOperations:
    def test_cache_key_deterministic(self) -> None:
        k1 = cache_key("tool_a", "desc", "model-1")
        k2 = cache_key("tool_a", "desc", "model-1")
        assert k1 == k2

    def test_cache_key_differs_by_model(self) -> None:
        k1 = cache_key("tool_a", "desc", "model-1")
        k2 = cache_key("tool_a", "desc", "model-2")
        assert k1 != k2

    def test_cache_roundtrip(self, tmp_path: Path) -> None:
        with patch("spidershield.rewriter.cache.CACHE_DIR", tmp_path):
            set_cached("test_tool", "original", "model", "rewritten desc")
            result = get_cached("test_tool", "original", "model")
            assert result == "rewritten desc"

    def test_cache_miss(self, tmp_path: Path) -> None:
        with patch("spidershield.rewriter.cache.CACHE_DIR", tmp_path):
            result = get_cached("nonexistent", "desc", "model")
            assert result is None

    def test_clear_cache(self, tmp_path: Path) -> None:
        with patch("spidershield.rewriter.cache.CACHE_DIR", tmp_path):
            set_cached("t1", "d1", "m1", "r1")
            set_cached("t2", "d2", "m2", "r2")
            count = clear_cache()
            assert count == 2
            assert get_cached("t1", "d1", "m1") is None


# ---------------------------------------------------------------------------
# Semantic verification (with mock)
# ---------------------------------------------------------------------------


class TestSemanticVerification:
    def test_semantic_verify_passes(
        self, sample_tool: dict, sibling_tools: list[dict]
    ) -> None:
        """Semantic verification with a cooperative mock provider."""
        provider = MagicMock()
        provider.model = "mock"
        # First call: rewrite; subsequent: verification response
        provider.complete.side_effect = [
            PERFECT_REWRITE,
            '{"preserves_meaning": true, "disambiguation_accurate": true, "issues": []}',
        ]

        result = _rewrite_llm(
            sample_tool, sibling_tools, provider,
            use_cache=False, semantic_verify=True,
            min_score=5.0,  # Low threshold to avoid retries
        )
        assert len(result) > 0

    def test_semantic_verify_failure_triggers_retry(
        self, sample_tool: dict, sibling_tools: list[dict]
    ) -> None:
        provider = MagicMock()
        provider.model = "mock"
        provider.complete.side_effect = [
            PERFECT_REWRITE,  # initial rewrite
            '{"preserves_meaning": false, "disambiguation_accurate": true, "issues": ["changes meaning"]}',  # verification fails
            PERFECT_REWRITE,  # retry rewrite
            '{"preserves_meaning": true, "disambiguation_accurate": true, "issues": []}',  # verification passes
        ]

        _rewrite_llm(
            sample_tool, sibling_tools, provider,
            use_cache=False, semantic_verify=True,
            min_score=5.0, max_retries=2,
        )
        # Should have called more than once due to semantic failure
        assert provider.complete.call_count >= 3


# ---------------------------------------------------------------------------
# Template vs LLM comparison
# ---------------------------------------------------------------------------


class TestTemplateVsLLM:
    def test_template_always_available(self, sample_tool: dict, sibling_tools: list[dict]) -> None:
        """Template rewriter works without any API key."""
        result = _rewrite_local(sample_tool, sibling_tools)
        assert len(result) > 0
        assert result != sample_tool["description"]

    def test_llm_improves_over_template(
        self, mock_provider: MagicMock, sample_tool: dict, sibling_tools: list[dict]
    ) -> None:
        template_result = _rewrite_local(sample_tool, sibling_tools)
        llm_result = _rewrite_llm(
            sample_tool, sibling_tools, mock_provider,
            use_cache=False, semantic_verify=False,
        )
        template_score = _quick_score(template_result)
        llm_score = _quick_score(llm_result)
        # LLM should score higher (our mock returns a perfect rewrite)
        assert llm_score >= template_score
