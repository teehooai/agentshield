"""Core data models for SpiderShield."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Rating(StrEnum):
    """SpiderRating grade levels (F/D/C/B/A)."""

    F = "F"  # Flagged -- critical issues or hard constraint violations
    D = "D"  # Deficient -- significant issues, below minimum quality
    C = "C"  # Caution -- usable but has notable issues
    B = "B"  # Basic -- passed automated scan, minor issues
    A = "A"  # Approved -- high quality across all dimensions


class SecurityIssue(BaseModel):
    """A single security issue found during scanning."""

    severity: str = Field(description="critical / high / medium / low / info")
    category: str = Field(description="e.g. path_traversal, sql_injection, credential_exposure")
    file: str
    line: int | None = None
    description: str
    fix_suggestion: str | None = None
    # L2: file context — helps downstream filters distinguish runtime code from
    # build scripts, CLI tooling, benchmark harnesses, and CTF/intentionally-
    # vulnerable projects.  Defaults to "runtime" (conservative / no filtering).
    file_context: Literal["runtime", "build", "test", "cli", "benchmark", "ctf"] = "runtime"
    # L3: detection confidence — "high" for AST-level (Semgrep) findings,
    # "medium" for regex-only matches, "low" for known-safe-pattern matches.
    # Downstream tools (bug_hunter L3 filter) skip "low" confidence issues.
    confidence: Literal["high", "medium", "low"] = "medium"


class ToolDescriptionScore(BaseModel):
    """Quality score for a single tool's description."""

    tool_name: str
    has_action_verb: bool = Field(default=False, description="Starts with an action verb")
    has_scenario_trigger: bool = Field(default=False, description="Contains 'Use when...' guidance")
    has_param_examples: bool = Field(default=False, description="Contains concrete parameter examples")
    has_error_guidance: bool = Field(default=False, description="Contains error/failure mode guidance")
    has_param_docs: bool = Field(default=False, description="Documents parameters/inputs")
    has_return_docs: bool = Field(default=False, description="Documents return value or output format")
    disambiguation_score: float = Field(ge=0, le=1, description="How distinct from other tools")
    overall_score: float = Field(ge=0, le=10)
    suggested_rewrite: str | None = None


class ScanReport(BaseModel):
    """Complete scan report for an MCP server."""

    target: str
    license: str | None = None
    license_ok: bool = True
    tool_count: int = 0
    tool_names: list[str] = Field(default_factory=list)

    # Security
    security_score: float = Field(ge=0, le=10, default=5.0)
    security_issues: list[SecurityIssue] = Field(default_factory=list)

    # Description quality
    description_score: float = Field(ge=0, le=10, default=5.0)
    tool_scores: list[ToolDescriptionScore] = Field(default_factory=list)

    # Architecture
    architecture_score: float = Field(ge=0, le=10, default=5.0)
    has_tests: bool = False
    has_error_handling: bool = False

    # Overall
    overall_score: float = Field(ge=0, le=10, default=5.0)
    improvement_potential: float = Field(ge=0, le=10, default=5.0)
    rating: Rating = Rating.C
    recommendations: list[str] = Field(default_factory=list)


class EvalResult(BaseModel):
    """Result of a single tool-selection evaluation."""

    scenario: str
    expected_tool: str
    selected_tool: str
    correct: bool
    model: str
    latency_ms: float | None = None


class EvalReport(BaseModel):
    """Before/after comparison report."""

    original_server: str
    improved_server: str
    models: list[str]
    original_accuracy: float
    improved_accuracy: float
    improvement_pct: float
    results: list[EvalResult] = Field(default_factory=list)
