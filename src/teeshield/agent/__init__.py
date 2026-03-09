"""TeeShield Agent Security Module.

Scans AI agent configurations, skills/tools for malicious patterns,
and provides auto-fix capabilities. Ported from SpiderShield.
"""

from .models import (
    Finding,
    ScanResult,
    Severity,
    SkillFinding,
    SkillVerdict,
)

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "SkillFinding",
    "SkillVerdict",
]
