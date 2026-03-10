"""DLP Engine — orchestrates PII and secret detection with configurable actions.

Actions:
    LOG_ONLY  — detect and log, don't modify output
    REDACT    — replace with [REDACTED:type]
    MASK      — replace with partially masked value (e.g., ****-1234)
    BLOCK     — replace entire output with error message

Usage:
    engine = DLPEngine(action="redact")
    output, findings = engine.scan_and_act("API key: sk-proj-abc123...")
    # output: "API key: [REDACTED:openai_key]"
    # findings: [DLPFinding(type="openai_key", ...)]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .pii import detect_pii
from .prompt_injection import detect_prompt_injection
from .secrets import detect_secrets


class DLPAction(StrEnum):
    """What to do when sensitive data is found."""

    LOG_ONLY = "log_only"
    REDACT = "redact"
    MASK = "mask"
    BLOCK = "block"


@dataclass
class DLPFinding:
    """A single sensitive data detection."""

    finding_type: str  # PIIType or SecretType value
    category: str  # "pii" or "secret"
    severity: str
    value_masked: str  # always masked for audit safety
    start: int
    end: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.finding_type,
            "category": self.category,
            "severity": self.severity,
            "masked": self.value_masked,
        }


@dataclass
class DLPResult:
    """Result of a DLP scan."""

    output: Any  # potentially modified output
    findings: list[DLPFinding] = field(default_factory=list)
    action_taken: DLPAction = DLPAction.LOG_ONLY
    blocked: bool = False

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def finding_types(self) -> list[str]:
        return [f.finding_type for f in self.findings]


class DLPEngine:
    """Orchestrates PII, secret, and prompt injection scanning.

    Args:
        action: Default action when sensitive data is detected.
        scan_pii: Enable PII scanning (default: True).
        scan_secrets: Enable secret scanning (default: True).
        scan_prompt_injection: Enable prompt injection detection (default: True).
        pii_types: Specific PII types to scan for (None = all).
        secret_types: Specific secret types to scan for (None = all).
    """

    def __init__(
        self,
        action: DLPAction | str = DLPAction.LOG_ONLY,
        *,
        scan_pii: bool = True,
        scan_secrets: bool = True,
        scan_prompt_injection: bool = True,
        pii_types: set[str] | None = None,
        secret_types: set[str] | None = None,
    ) -> None:
        self._action = DLPAction(action) if isinstance(action, str) else action
        self._scan_pii = scan_pii
        self._scan_secrets = scan_secrets
        self._scan_prompt_injection = scan_prompt_injection
        self._pii_types = pii_types
        self._secret_types = secret_types

    @property
    def action(self) -> DLPAction:
        return self._action

    def scan_and_act(self, output: Any) -> tuple[Any, list[str]]:
        """Scan output and apply action. Returns (modified_output, finding_type_list).

        This is the interface that RuntimeGuard.after_call() uses.
        """
        result = self.scan(output)
        return result.output, result.finding_types

    def scan(self, output: Any) -> DLPResult:
        """Full scan with detailed results."""
        # Extract text to scan
        text = self._extract_text(output)
        if not text:
            return DLPResult(output=output)

        findings = self._detect_all(text)

        if not findings:
            return DLPResult(output=output)

        # Apply action
        if self._action == DLPAction.BLOCK:
            blocked_msg = (
                f"[BLOCKED] Output contained {len(findings)} sensitive data "
                f"finding(s): {', '.join(f.finding_type for f in findings)}"
            )
            return DLPResult(
                output=blocked_msg,
                findings=findings,
                action_taken=DLPAction.BLOCK,
                blocked=True,
            )

        if self._action == DLPAction.REDACT:
            modified = self._apply_redact(text, findings)
            output = self._replace_text(output, modified)
            return DLPResult(
                output=output,
                findings=findings,
                action_taken=DLPAction.REDACT,
            )

        if self._action == DLPAction.MASK:
            modified = self._apply_mask(text, findings)
            output = self._replace_text(output, modified)
            return DLPResult(
                output=output,
                findings=findings,
                action_taken=DLPAction.MASK,
            )

        # LOG_ONLY — don't modify
        return DLPResult(
            output=output,
            findings=findings,
            action_taken=DLPAction.LOG_ONLY,
        )

    def _detect_all(self, text: str) -> list[DLPFinding]:
        """Run all enabled detectors."""
        findings: list[DLPFinding] = []

        if self._scan_pii:
            for match in detect_pii(text):
                if self._pii_types and match.pii_type not in self._pii_types:
                    continue
                findings.append(DLPFinding(
                    finding_type=match.pii_type,
                    category="pii",
                    severity=match.severity,
                    value_masked=match.masked,
                    start=match.start,
                    end=match.end,
                ))

        if self._scan_secrets:
            for match in detect_secrets(text):
                if self._secret_types and match.secret_type not in self._secret_types:
                    continue
                findings.append(DLPFinding(
                    finding_type=match.secret_type,
                    category="secret",
                    severity=match.severity,
                    value_masked=match.masked,
                    start=match.start,
                    end=match.end,
                ))

        if self._scan_prompt_injection:
            for match in detect_prompt_injection(text):
                findings.append(DLPFinding(
                    finding_type=match.pattern_name,
                    category="prompt_injection",
                    severity=match.severity,
                    value_masked=match.matched_text[:50] + "...",
                    start=match.start,
                    end=match.end,
                ))

        # Deduplicate overlapping findings (keep highest severity)
        findings = self._deduplicate_findings(findings)

        # Sort by position for correct replacement order
        findings.sort(key=lambda f: f.start)
        return findings

    @staticmethod
    def _deduplicate_findings(findings: list[DLPFinding]) -> list[DLPFinding]:
        """Remove overlapping findings, keeping the highest severity."""
        if not findings:
            return findings

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        # Sort by severity (highest first), then by span length (longest first)
        ranked = sorted(
            findings,
            key=lambda f: (severity_rank.get(f.severity, 0), f.end - f.start),
            reverse=True,
        )

        kept: list[DLPFinding] = []
        for f in ranked:
            # Check if this finding overlaps with any already-kept finding
            if not any(f.start < k.end and k.start < f.end for k in kept):
                kept.append(f)

        return kept

    def _apply_redact(self, text: str, findings: list[DLPFinding]) -> str:
        """Replace sensitive data with [REDACTED:type] tags."""
        # Process in reverse order to preserve positions
        result = text
        for f in reversed(findings):
            tag = f"[REDACTED:{f.finding_type}]"
            result = result[:f.start] + tag + result[f.end:]
        return result

    def _apply_mask(self, text: str, findings: list[DLPFinding]) -> str:
        """Replace sensitive data with masked versions."""
        result = text
        for f in reversed(findings):
            result = result[:f.start] + f.value_masked + result[f.end:]
        return result

    def _extract_text(self, output: Any) -> str:
        """Extract scannable text from various output types."""
        if isinstance(output, str):
            return output
        if isinstance(output, dict):
            # Scan all string values
            parts = []
            for v in output.values():
                if isinstance(v, str):
                    parts.append(v)
                elif isinstance(v, list):
                    parts.extend(str(item) for item in v if isinstance(item, str))
            return "\n".join(parts)
        if isinstance(output, list):
            return "\n".join(str(item) for item in output if isinstance(item, str))
        return str(output) if output is not None else ""

    def _replace_text(self, output: Any, modified_text: str) -> Any:
        """Replace text in the original output structure."""
        if isinstance(output, str):
            return modified_text
        # For non-string outputs, return the modified text as-is
        # (the caller can decide how to handle structured output)
        return modified_text
