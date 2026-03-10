"""RuntimeGuard — core interception engine for SpiderShield.

Architecture:
    Agent Decision
         ↓
    RuntimeGuard.before_call(ctx)
         ↓
    PolicyEngine → Allow / Deny / Escalate
         ↓
    Tool Execution (if allowed)
         ↓
    RuntimeGuard.after_call(ctx, result)
         ↓
    DLP scan + Audit Logger
"""

from __future__ import annotations

from typing import Any

from .context import CallContext
from .decision import InterceptResult
from .policy import PolicyEngine


class RuntimeGuard:
    """Core guard that evaluates tool calls against policies.

    This is the single entry point for all adapters.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine | None = None,
        audit_logger: Any | None = None,
        dlp_engine: Any | None = None,
    ) -> None:
        self._policy = policy_engine or PolicyEngine()
        self._audit_log: list[dict[str, Any]] = []
        self._dlp_engine = dlp_engine
        self._audit_logger = audit_logger

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy

    def before_call(self, ctx: CallContext) -> InterceptResult:
        """Evaluate a tool call before execution.

        Returns an InterceptResult with the guard's decision.
        All adapters call this method — it is the single security checkpoint.
        """
        decision, reason, policy_name, suggestion = self._policy.evaluate(ctx)

        result = InterceptResult(
            decision=decision,
            reason=reason,
            suggestion=suggestion,
            policy_matched=policy_name,
        )

        self._record_before(ctx, result)
        return result

    def after_call(self, ctx: CallContext, tool_result: Any) -> Any:
        """Inspect tool call result after execution.

        Checks output for sensitive data leakage (DLP).
        Returns the (possibly modified) result.
        """
        pii_detected: list[str] = []

        # DLP hook (Week 5) — scan output for PII/secrets
        if self._dlp_engine is not None:
            tool_result, pii_detected = self._dlp_engine.scan_and_act(tool_result)

        self._record_after(ctx, pii_detected)
        return tool_result

    def _record_before(self, ctx: CallContext, result: InterceptResult) -> None:
        """Record pre-call decision for audit trail."""
        entry = {
            "phase": "before_call",
            "session_id": ctx.session_id,
            "agent_id": ctx.agent_id,
            "tool_name": ctx.tool_name,
            "call_index": ctx.call_index,
            "decision": result.decision.value,
            "reason": result.reason,
            "suggestion": result.suggestion,
            "policy_matched": result.policy_matched,
        }
        self._audit_log.append(entry)

        if self._audit_logger is not None:
            self._audit_logger.log(entry)

    def _record_after(
        self, ctx: CallContext, pii_detected: list[str]
    ) -> None:
        """Record post-call result for audit trail."""
        entry = {
            "phase": "after_call",
            "session_id": ctx.session_id,
            "agent_id": ctx.agent_id,
            "tool_name": ctx.tool_name,
            "call_index": ctx.call_index,
            "pii_detected": pii_detected,
        }
        self._audit_log.append(entry)

        if self._audit_logger is not None:
            self._audit_logger.log(entry)
