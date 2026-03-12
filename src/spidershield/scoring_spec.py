"""SpiderRating Scoring Specification — the public "constitution."

This module is the SINGLE SOURCE OF TRUTH for all scoring constants and
formulas shared between spidershield (open-source CLI) and spiderrating
(closed-source platform).

Rules:
  - Pure functions only. No I/O, no network, no imports beyond stdlib.
  - Fully deterministic: same inputs → same outputs.
  - Bump SPEC_VERSION on ANY change to constants or formulas.
  - Both repos import from here; neither copy-pastes values.

What belongs here (public scoring LANGUAGE):
  - Grade thresholds, dimension weights, severity penalties
  - Composite formulas, overall score calculation

What does NOT belong here (closed scoring STRATEGY):
  - Hard constraints (tiered critical, security floor, registry gate)
  - Artifact-type-specific weights (skill 45/35/20)
  - ScoreExplanation / ranking / verified badge logic
"""

from __future__ import annotations

SPEC_VERSION = "2.0.0"

# ---------------------------------------------------------------------------
# Grade Thresholds (descending)
# ---------------------------------------------------------------------------

GRADE_THRESHOLDS: list[tuple[float, str]] = [
    (9.0, "A"),
    (7.0, "B"),
    (5.0, "C"),
    (3.0, "D"),
    (0.0, "F"),
]

# ---------------------------------------------------------------------------
# Description Dimension Weights (sum = 1.0)
# ---------------------------------------------------------------------------

DESC_WEIGHTS: dict[str, float] = {
    "intent_clarity":        0.20,
    "permission_scope":      0.25,
    "side_effects":          0.20,
    "capability_disclosure":  0.20,
    "operational_boundaries": 0.15,
}

# ---------------------------------------------------------------------------
# Metadata Sub-Weights (sum = 1.0)
# ---------------------------------------------------------------------------

META_WEIGHTS: dict[str, float] = {
    "provenance":  0.40,
    "maintenance": 0.35,
    "popularity":  0.25,
}

# ---------------------------------------------------------------------------
# Security Formula Constants
# ---------------------------------------------------------------------------

SECURITY_BASE = 10.0

SEVERITY_PENALTIES: dict[str, float] = {
    "critical": 3.0,
    "high":     2.0,
    "medium":   1.0,
    "low":      0.25,
}

ARCHITECTURE_BONUS_MAX = 2.0

# ---------------------------------------------------------------------------
# Default Layer Weights (MCP servers — the public default)
# ---------------------------------------------------------------------------

DEFAULT_LAYER_WEIGHTS: dict[str, float] = {
    "description": 0.35,
    "security":    0.35,
    "metadata":    0.30,
}

# ---------------------------------------------------------------------------
# Pure Functions
# ---------------------------------------------------------------------------


def _clamp(value: float, lo: float = 0.0, hi: float = 10.0) -> float:
    return max(lo, min(hi, value))


def spec_grade(score: float) -> str:
    """Convert numeric score (0-10) to letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def spec_security_score(
    critical: int,
    high: int,
    medium: int,
    low: int,
    architecture_bonus: float = 0.0,
) -> float:
    """Calculate security score from issue counts + architecture bonus.

    Formula: 10 - (3*critical + 2*high + 1*medium + 0.25*low) + bonus
    Clamped to [0, 10]. Bonus capped at ARCHITECTURE_BONUS_MAX.
    """
    raw = SECURITY_BASE - (
        SEVERITY_PENALTIES["critical"] * critical
        + SEVERITY_PENALTIES["high"] * high
        + SEVERITY_PENALTIES["medium"] * medium
        + SEVERITY_PENALTIES["low"] * low
    )
    bonus = min(architecture_bonus, ARCHITECTURE_BONUS_MAX)
    return _clamp(raw + bonus)


def spec_description_composite(dimensions: dict[str, float]) -> float:
    """Weighted composite of 5 description dimensions."""
    total = sum(dimensions.get(k, 0.0) * w for k, w in DESC_WEIGHTS.items())
    return _clamp(total)


def spec_metadata_composite(
    provenance: float,
    maintenance: float,
    popularity: float,
) -> float:
    """Weighted composite of 3 metadata dimensions."""
    total = (
        provenance * META_WEIGHTS["provenance"]
        + maintenance * META_WEIGHTS["maintenance"]
        + popularity * META_WEIGHTS["popularity"]
    )
    return _clamp(total)


def spec_overall(
    description: float,
    security: float,
    metadata: float,
    weights: dict[str, float] | None = None,
) -> float:
    """Overall score from 3 layers with configurable weights.

    Uses DEFAULT_LAYER_WEIGHTS if none provided.
    """
    w = weights or DEFAULT_LAYER_WEIGHTS
    total = (
        description * w["description"]
        + security * w["security"]
        + metadata * w["metadata"]
    )
    return round(_clamp(total), 2)


def spec_architecture_bonus(architecture_score: float) -> float:
    """Map architecture score (0-10) to bonus (0-ARCHITECTURE_BONUS_MAX)."""
    return min(max(architecture_score / 5.0, 0.0), ARCHITECTURE_BONUS_MAX)
