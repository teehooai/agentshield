"""Tests for SpiderShield adapters (Week 6).

Tests AdapterBase, StandaloneGuard, MCP proxy refactor, and dry-run mode.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from spidershield.adapters.base import AdapterBase, AdapterStats
from spidershield.adapters.mcp_proxy import MCPProxyGuard
from spidershield.adapters.standalone import StandaloneGuard
from spidershield.guard.core import RuntimeGuard
from spidershield.guard.decision import Decision
from spidershield.guard.policy import PolicyEngine, PolicyRule

# ---------------------------------------------------------------------------
# AdapterBase tests
# ---------------------------------------------------------------------------


class TestAdapterBase:
    def test_cannot_instantiate_directly(self) -> None:
        """AdapterBase is abstract and cannot be instantiated."""
        with pytest.raises(TypeError):
            AdapterBase(RuntimeGuard())

    def test_adapter_stats_default(self) -> None:
        stats = AdapterStats()
        assert stats.total_calls == 0
        assert stats.allowed == 0
        assert stats.denied == 0
        assert stats.escalated == 0
        d = stats.to_dict()
        assert d == {"total_calls": 0, "allowed": 0, "denied": 0, "escalated": 0}

    def test_evaluate_tool_call_allow(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)
        result = adapter.evaluate_tool_call("read_file", {"path": "/app/main.py"})
        assert result.decision == Decision.ALLOW
        assert adapter.stats.total_calls == 1
        assert adapter.stats.allowed == 1

    def test_evaluate_tool_call_deny(self) -> None:
        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="blocked",
            suggestion="use /workspace/",
            tool_match="read_file",
            args_patterns={"path": r"\.env"},
        )
        guard = RuntimeGuard(policy_engine=PolicyEngine([rule]))
        adapter = StandaloneGuard(guard)
        result = adapter.evaluate_tool_call("read_file", {"path": "/app/.env"})
        assert result.decision == Decision.DENY
        assert adapter.stats.denied == 1

    def test_dry_run_converts_deny_to_allow(self) -> None:
        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="blocked",
            tool_match="read_file",
            args_patterns={"path": r"\.env"},
        )
        guard = RuntimeGuard(policy_engine=PolicyEngine([rule]))
        adapter = StandaloneGuard(guard, dry_run=True)
        result = adapter.evaluate_tool_call("read_file", {"path": "/app/.env"})
        # Dry-run should convert DENY → ALLOW
        assert result.decision == Decision.ALLOW
        assert "[dry-run]" in result.reason
        # But stats should still count the original denial
        assert adapter.stats.denied == 1

    def test_session_id_auto_generated(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)
        assert len(adapter.session_id) == 12

    def test_session_id_custom(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard, session_id="my-session")
        assert adapter.session_id == "my-session"

    def test_framework_name(self) -> None:
        guard = RuntimeGuard()
        standalone = StandaloneGuard(guard)
        assert standalone.framework_name == "standalone"
        mcp = MCPProxyGuard(guard)
        assert mcp.framework_name == "mcp"


# ---------------------------------------------------------------------------
# StandaloneGuard tests
# ---------------------------------------------------------------------------


class TestStandaloneGuard:
    def test_parse_tool_call_valid(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)
        result = adapter._parse_tool_call(
            '{"tool": "read_file", "arguments": {"path": "/tmp/x"}}\n'
        )
        assert result is not None
        assert result[0] == "read_file"
        assert result[1] == {"path": "/tmp/x"}

    def test_parse_tool_call_tool_name_key(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)
        result = adapter._parse_tool_call(
            '{"tool_name": "exec", "args": {"cmd": "ls"}}\n'
        )
        assert result is not None
        assert result[0] == "exec"

    def test_parse_tool_call_not_json(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)
        assert adapter._parse_tool_call("Hello world\n") is None

    def test_parse_tool_call_no_tool_field(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)
        assert adapter._parse_tool_call('{"data": "test"}\n') is None

    def test_parse_tool_call_invalid_json(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)
        assert adapter._parse_tool_call("{invalid json}\n") is None

    def test_run_requires_server_cmd(self) -> None:
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)
        with pytest.raises(ValueError, match="server_cmd is required"):
            adapter.run()

    def test_scan_and_relay_passthrough(self) -> None:
        """Non-tool-call lines should pass through unchanged."""
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)

        source = io.StringIO("line 1\nline 2\n")
        dest = io.StringIO()
        adapter._scan_and_relay(source, dest)

        assert dest.getvalue() == "line 1\nline 2\n"

    def test_scan_and_relay_blocks_denied_tool(self) -> None:
        """Denied tool calls should produce denial JSON."""
        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="blocked",
            suggestion="avoid .env",
            tool_match="read_file",
            args_patterns={"path": r"\.env"},
        )
        guard = RuntimeGuard(policy_engine=PolicyEngine([rule]))
        adapter = StandaloneGuard(guard)

        tool_call = json.dumps({"tool": "read_file", "arguments": {"path": ".env"}})
        source = io.StringIO(tool_call + "\n")
        dest = io.StringIO()
        adapter._scan_and_relay(source, dest)

        output = dest.getvalue()
        # Should contain denial JSON, NOT the original tool call
        parsed = json.loads(output.strip())
        assert parsed["error"] == "denied"
        assert parsed["reason"] == "blocked"

    def test_scan_and_relay_allows_normal_tool(self) -> None:
        """Allowed tool calls should pass through."""
        guard = RuntimeGuard()
        adapter = StandaloneGuard(guard)

        tool_call = json.dumps({"tool": "read_file", "arguments": {"path": "/app/main.py"}})
        source = io.StringIO(tool_call + "\n")
        dest = io.StringIO()
        adapter._scan_and_relay(source, dest)

        output = dest.getvalue()
        assert tool_call in output


# ---------------------------------------------------------------------------
# MCP Proxy refactor tests
# ---------------------------------------------------------------------------


class TestMCPProxyRefactor:
    def test_inherits_adapter_base(self) -> None:
        assert issubclass(MCPProxyGuard, AdapterBase)

    def test_run_requires_server_cmd(self) -> None:
        guard = RuntimeGuard()
        proxy = MCPProxyGuard(guard)
        with pytest.raises(ValueError, match="server_cmd is required"):
            proxy.run()

    def test_stats_tracking(self) -> None:
        guard = RuntimeGuard()
        proxy = MCPProxyGuard(guard)
        proxy.evaluate_tool_call("read_file", {"path": "/app/main.py"})
        assert proxy.stats.total_calls == 1
        assert proxy.stats.allowed == 1

    def test_dry_run_mode(self) -> None:
        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="blocked",
            tool_match="read_file",
            args_patterns={"path": r"\.env"},
        )
        guard = RuntimeGuard(policy_engine=PolicyEngine([rule]))
        proxy = MCPProxyGuard(guard, dry_run=True)
        result = proxy.evaluate_tool_call("read_file", {"path": "/app/.env"})
        assert result.decision == Decision.ALLOW
        assert "[dry-run]" in result.reason


# ---------------------------------------------------------------------------
# End-to-end: SpiderGuard full pipeline
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_full_pipeline_check_and_after(self) -> None:
        """Test the complete SpiderGuard flow: check → after_check with DLP."""
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced", dlp="redact")

        # Step 1: Check if tool call is allowed
        result = guard.check("read_file", {"path": "/app/config.txt"})
        assert result.decision == Decision.ALLOW

        # Step 2: After execution, scan output for secrets
        output = guard.after_check(
            "read_file",
            "OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012\nDB_HOST=localhost",
        )
        assert "[REDACTED:openai_key]" in output
        assert "localhost" in output  # non-secret should remain

    def test_full_pipeline_deny(self) -> None:
        """Test denial flow."""
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="strict")

        result = guard.check("shell_exec", {"command": "ls -la"})
        assert result.decision == Decision.DENY
        assert result.reason
        assert result.suggestion

        # Verify actionable denial format
        d = result.to_dict()
        assert d["decision"] == "deny"
        assert "reason" in d
        assert "suggestion" in d

    def test_full_pipeline_with_audit(self, tmp_path: Path) -> None:
        """Test audit logging through full pipeline."""
        from spidershield import SpiderGuard

        guard = SpiderGuard(
            policy="balanced",
            audit=True,
            audit_dir=str(tmp_path),
        )

        guard.check("read_file", {"path": "/app/.env"})
        guard.check("read_file", {"path": "/app/main.py"})

        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1
        lines = files[0].read_text().strip().split("\n")
        assert len(lines) == 2

        entries = [json.loads(line) for line in lines]
        decisions = [e["decision"] for e in entries]
        assert "deny" in decisions
        assert "allow" in decisions

    def test_adapter_imports(self) -> None:
        """Verify all adapter types are importable."""
        from spidershield.adapters import (
            AdapterBase,
            StandaloneGuard,
            run_standalone_guard,
        )

        assert AdapterBase is not None
        assert StandaloneGuard is not None
        assert callable(run_standalone_guard)

    def test_dlp_imports(self) -> None:
        """Verify DLP module is importable."""
        from spidershield.dlp import (
            DLPEngine,
            detect_pii,
            detect_secrets,
        )

        assert DLPEngine is not None
        assert callable(detect_pii)
        assert callable(detect_secrets)


# ---------------------------------------------------------------------------
# CLI guard command
# ---------------------------------------------------------------------------


class TestGuardCLI:
    def test_guard_help(self) -> None:
        from click.testing import CliRunner

        from spidershield.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["guard", "--help"])
        assert result.exit_code == 0
        assert "Wrap any subprocess" in result.output
        assert "--policy" in result.output
        assert "--dry-run" in result.output

    def test_proxy_help_has_dry_run(self) -> None:
        from click.testing import CliRunner

        from spidershield.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["proxy", "--help"])
        assert result.exit_code == 0
        assert "--dry-run" in result.output
