"""Core data models for AgentShield."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Rating(str, Enum):
    """Certification rating levels."""

    F = "F"  # Flagged — known security issues
    C = "C"  # Community — unaudited
    B = "B"  # Basic — passed automated scan
    A = "A"  # Audited — full audit including manual review
    A_PLUS = "A+"  # Enterprise Certified — continuous monitoring


class SecurityIssue(BaseModel):
    """A single security issue found during scanning."""

    severity: str = Field(description="critical / high / medium / low / info")
    category: str = Field(description="e.g. path_traversal, sql_injection, credential_exposure")
    file: str
    line: int | None = None
    description: str
    fix_suggestion: str | None = None


class ToolDescriptionScore(BaseModel):
    """Quality score for a single tool's description."""

    tool_name: str
    has_scenario_trigger: bool = Field(description="Contains 'Use when...' guidance")
    has_param_examples: bool
    has_error_guidance: bool
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
