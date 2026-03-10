"""JSONL audit logger for SpiderShield Runtime Guard.

Every tool call decision is logged as a single JSON line.
Default location: ~/.spidershield/audit/YYYY-MM-DD.jsonl
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_DEFAULT_AUDIT_DIR = Path.home() / ".spidershield" / "audit"


class AuditLogger:
    """Append-only JSONL audit logger.

    Each entry is one JSON line with:
        timestamp, session_id, agent_id, tool_name, call_index,
        phase (before_call/after_call), decision, reason,
        policy_matched, suggestion, pii_detected, latency_ms
    """

    def __init__(self, audit_dir: str | Path | None = None) -> None:
        self._audit_dir = Path(audit_dir) if audit_dir else _DEFAULT_AUDIT_DIR
        self._audit_dir.mkdir(parents=True, exist_ok=True)
        self._current_file: Path | None = None
        self._current_date: str = ""
        self._pending_timers: dict[str, float] = {}

    @property
    def audit_dir(self) -> Path:
        return self._audit_dir

    def log(self, entry: dict[str, Any]) -> None:
        """Write a single audit entry as a JSON line."""
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            **entry,
        }
        f = self._get_file()
        with open(f, "a", encoding="utf-8") as fp:
            fp.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")

    def log_before_call(
        self,
        *,
        session_id: str,
        agent_id: str,
        tool_name: str,
        call_index: int,
        decision: str,
        reason: str,
        policy_matched: str | None = None,
        suggestion: str = "",
        arguments_summary: str = "",
    ) -> None:
        """Log a before_call decision."""
        timer_key = f"{session_id}:{call_index}"
        self._pending_timers[timer_key] = time.monotonic()

        self.log({
            "phase": "before_call",
            "session_id": session_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "call_index": call_index,
            "decision": decision,
            "reason": reason,
            "policy_matched": policy_matched,
            "suggestion": suggestion,
            "arguments_summary": arguments_summary,
        })

    def log_after_call(
        self,
        *,
        session_id: str,
        agent_id: str,
        tool_name: str,
        call_index: int,
        pii_detected: list[str] | None = None,
    ) -> None:
        """Log an after_call result with latency."""
        timer_key = f"{session_id}:{call_index}"
        start = self._pending_timers.pop(timer_key, None)
        latency_ms = round((time.monotonic() - start) * 1000, 1) if start else None

        self.log({
            "phase": "after_call",
            "session_id": session_id,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "call_index": call_index,
            "pii_detected": pii_detected or [],
            "latency_ms": latency_ms,
        })

    def _get_file(self) -> Path:
        """Get today's log file, rotating daily."""
        today = datetime.now(UTC).strftime("%Y-%m-%d")
        if today != self._current_date:
            self._current_date = today
            self._current_file = self._audit_dir / f"{today}.jsonl"
        return self._current_file  # type: ignore[return-value]
