"""Tests for the Tool Firewall interceptor and policy engine."""

from spidershield.guard.context import CallContext
from spidershield.guard.core import RuntimeGuard as ToolInterceptor
from spidershield.guard.decision import Decision
from spidershield.guard.policy import PolicyEngine, PolicyRule


def _make_ctx(
    tool_name: str = "read_file",
    arguments: dict | None = None,
    token_spent: int = 0,
    call_chain: list | None = None,
) -> CallContext:
    return CallContext(
        session_id="test-session",
        agent_id="test-agent",
        tool_name=tool_name,
        arguments=arguments or {},
        call_chain=call_chain or [],
        token_spent=token_spent,
    )


class TestToolInterceptor:
    def test_default_passthrough(self):
        interceptor = ToolInterceptor()
        ctx = _make_ctx()
        result = interceptor.before_call(ctx)
        assert result.decision == Decision.ALLOW

    def test_after_call_logs(self):
        interceptor = ToolInterceptor()
        ctx = _make_ctx()
        interceptor.after_call(ctx, {"ok": True})
        assert len(interceptor._audit_log) == 1
        assert interceptor._audit_log[0]["tool_name"] == "read_file"


class TestPolicyEngine:
    def test_no_rules_allows(self):
        engine = PolicyEngine()
        ctx = _make_ctx()
        decision, reason, name, suggestion = engine.evaluate(ctx)
        assert decision == Decision.ALLOW

    def test_tool_match_deny(self):
        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="blocked sensitive file",
            tool_match="read_file",
            args_patterns={"path": r"\.(env|key|pem)"},
        )
        engine = PolicyEngine([rule])

        # Should block .env access
        ctx = _make_ctx(arguments={"path": "/app/.env"})
        decision, reason, name, _ = engine.evaluate(ctx)
        assert decision == Decision.DENY
        assert name == "block-env"

        # Should allow normal file
        ctx = _make_ctx(arguments={"path": "/app/main.py"})
        decision, _, _, _ = engine.evaluate(ctx)
        assert decision == Decision.ALLOW

    def test_escalate_external_email(self):
        rule = PolicyRule(
            name="external-email",
            action=Decision.ESCALATE,
            reason="external email needs approval",
            tool_match="send_email",
            args_patterns={"to": r"^(?!.*@company\.com)"},
        )
        engine = PolicyEngine([rule])

        # External email → escalate
        ctx = _make_ctx(
            tool_name="send_email",
            arguments={"to": "attacker@evil.com"},
        )
        decision, _, _, _ = engine.evaluate(ctx)
        assert decision == Decision.ESCALATE

        # Internal email → allow
        ctx = _make_ctx(
            tool_name="send_email",
            arguments={"to": "colleague@company.com"},
        )
        decision, _, _, _ = engine.evaluate(ctx)
        assert decision == Decision.ALLOW

    def test_from_yaml(self):
        yaml_data = {
            "policies": [
                {
                    "name": "block-delete",
                    "match": {"tool": "delete_file", "args_pattern": {}},
                    "action": "deny",
                    "reason": "file deletion not allowed",
                },
            ]
        }
        engine = PolicyEngine.from_yaml(yaml_data)
        ctx = _make_ctx(tool_name="delete_file")
        decision, _, name, _ = engine.evaluate(ctx)
        assert decision == Decision.DENY
        assert name == "block-delete"

    def test_first_match_wins(self):
        rules = [
            PolicyRule(
                name="allow-read-src",
                action=Decision.ALLOW,
                reason="src is safe",
                tool_match="read_file",
                args_patterns={"path": r"^/app/src/"},
            ),
            PolicyRule(
                name="deny-all-reads",
                action=Decision.DENY,
                reason="block all file reads",
                tool_match="read_file",
                any_tool=False,
                args_patterns={},
            ),
        ]
        engine = PolicyEngine(rules)

        # /app/src/ → first rule matches → ALLOW
        ctx = _make_ctx(arguments={"path": "/app/src/main.py"})
        decision, _, name, _ = engine.evaluate(ctx)
        assert decision == Decision.ALLOW
        assert name == "allow-read-src"
