"""Audit log query and statistics engine.

Reads JSONL files from the audit directory and provides
filtering, search, and aggregation.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


@dataclass
class AuditStats:
    """Aggregated audit statistics."""

    total_calls: int = 0
    allowed: int = 0
    denied: int = 0
    escalated: int = 0
    pii_detections: int = 0
    top_denied_tools: list[tuple[str, int]] = None  # type: ignore[assignment]
    top_triggered_rules: list[tuple[str, int]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.top_denied_tools is None:
            self.top_denied_tools = []
        if self.top_triggered_rules is None:
            self.top_triggered_rules = []

    @property
    def denied_pct(self) -> float:
        return (self.denied / self.total_calls * 100) if self.total_calls else 0

    @property
    def escalated_pct(self) -> float:
        return (self.escalated / self.total_calls * 100) if self.total_calls else 0


class AuditQuery:
    """Query engine over JSONL audit logs."""

    def __init__(self, audit_dir: str | Path) -> None:
        self._audit_dir = Path(audit_dir)

    def iter_entries(
        self,
        *,
        last_hours: float | None = None,
        session_id: str | None = None,
        tool_name: str | None = None,
        decision: str | None = None,
        phase: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Iterate audit entries with optional filters."""
        cutoff = None
        if last_hours is not None:
            cutoff = datetime.now(UTC) - timedelta(hours=last_hours)

        for entry in self._read_all():
            if phase and entry.get("phase") != phase:
                continue
            if session_id and entry.get("session_id") != session_id:
                continue
            if tool_name and tool_name not in entry.get("tool_name", ""):
                continue
            if decision and entry.get("decision") != decision:
                continue
            if cutoff:
                ts = entry.get("timestamp", "")
                try:
                    entry_time = datetime.fromisoformat(ts)
                    if entry_time < cutoff:
                        continue
                except (ValueError, TypeError):
                    continue
            yield entry

    def query(self, **kwargs: Any) -> list[dict[str, Any]]:
        """Return filtered entries as a list."""
        return list(self.iter_entries(**kwargs))

    def stats(self, last_hours: float | None = None) -> AuditStats:
        """Compute aggregate statistics over before_call entries."""
        denied_tools: Counter[str] = Counter()
        triggered_rules: Counter[str] = Counter()
        total = 0
        allowed = 0
        denied = 0
        escalated = 0
        pii = 0

        for entry in self.iter_entries(last_hours=last_hours, phase="before_call"):
            total += 1
            d = entry.get("decision", "")
            if d == "allow":
                allowed += 1
            elif d == "deny":
                denied += 1
                tool = entry.get("tool_name", "unknown")
                denied_tools[tool] += 1
            elif d == "escalate":
                escalated += 1

            rule = entry.get("policy_matched")
            if rule:
                triggered_rules[rule] += 1

        # Count PII detections from after_call entries
        for entry in self.iter_entries(last_hours=last_hours, phase="after_call"):
            if entry.get("pii_detected"):
                pii += 1

        return AuditStats(
            total_calls=total,
            allowed=allowed,
            denied=denied,
            escalated=escalated,
            pii_detections=pii,
            top_denied_tools=denied_tools.most_common(10),
            top_triggered_rules=triggered_rules.most_common(10),
        )

    def _read_all(self) -> Iterator[dict[str, Any]]:
        """Read all JSONL files in audit dir, sorted by name (date)."""
        if not self._audit_dir.exists():
            return

        for f in sorted(self._audit_dir.glob("*.jsonl")):
            with open(f, encoding="utf-8") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
