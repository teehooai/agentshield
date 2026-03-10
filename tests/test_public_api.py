"""Tests for SpiderShield public API (Week 4).

Validates that:
- SpiderGuard high-level API works correctly
- guard_mcp_server() is importable
- All public types are accessible from top-level import
- Policy validate CLI command works
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

# ---------------------------------------------------------------------------
# Import validation
# ---------------------------------------------------------------------------


class TestImports:
    def test_top_level_imports(self) -> None:
        from spidershield import (
            CallContext,
            Decision,
            InterceptResult,
            PolicyEngine,
            PolicyRule,
            RuntimeGuard,
            SpiderGuard,
            guard_mcp_server,
        )

        # All should be non-None
        assert SpiderGuard is not None
        assert guard_mcp_server is not None
        assert Decision is not None
        assert InterceptResult is not None
        assert CallContext is not None
        assert RuntimeGuard is not None
        assert PolicyEngine is not None
        assert PolicyRule is not None

    def test_guard_subpackage_imports(self) -> None:
        from spidershield.guard import (
            RuntimeGuard,
        )

        assert RuntimeGuard is not None

    def test_adapter_imports(self) -> None:
        from spidershield.adapters import MCPProxyGuard, run_mcp_proxy

        assert MCPProxyGuard is not None
        assert run_mcp_proxy is not None

    def test_audit_imports(self) -> None:
        from spidershield.audit import AuditLogger, AuditQuery

        assert AuditLogger is not None
        assert AuditQuery is not None

    def test_version(self) -> None:
        import spidershield

        assert hasattr(spidershield, "__version__")
        assert isinstance(spidershield.__version__, str)


# ---------------------------------------------------------------------------
# SpiderGuard API
# ---------------------------------------------------------------------------


class TestSpiderGuard:
    def test_default_allow(self) -> None:
        from spidershield import Decision, SpiderGuard

        guard = SpiderGuard(policy="balanced")
        result = guard.check("read_file", {"path": "/app/main.py"})
        assert result.decision == Decision.ALLOW

    def test_deny_sensitive_file(self) -> None:
        from spidershield import Decision, SpiderGuard

        guard = SpiderGuard(policy="balanced")
        result = guard.check("read_file", {"path": "/app/.env"})
        assert result.decision == Decision.DENY
        assert result.reason  # non-empty reason
        assert result.suggestion  # non-empty suggestion

    def test_strict_blocks_shell(self) -> None:
        from spidershield import Decision, SpiderGuard

        guard = SpiderGuard(policy="strict")
        result = guard.check("shell_exec", {"command": "ls"})
        assert result.decision == Decision.DENY

    def test_permissive_allows_most(self) -> None:
        from spidershield import Decision, SpiderGuard

        guard = SpiderGuard(policy="permissive")
        result = guard.check("read_file", {"path": "/app/main.py"})
        assert result.decision == Decision.ALLOW

    def test_denied_property(self) -> None:
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced")

        result = guard.check("read_file", {"path": "/app/.env"})
        assert result.denied is True

        result = guard.check("read_file", {"path": "/app/main.py"})
        assert result.denied is False

    def test_to_dict(self) -> None:
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced")
        result = guard.check("read_file", {"path": "/app/.env"})
        d = result.to_dict()
        assert "decision" in d
        assert "reason" in d
        assert d["decision"] == "deny"

    def test_call_index_increments(self) -> None:
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced")
        guard.check("read_file", {"path": "/app/a.py"})
        guard.check("read_file", {"path": "/app/b.py"})
        assert guard._call_index == 2

    def test_with_session_and_agent(self) -> None:
        from spidershield import Decision, SpiderGuard

        guard = SpiderGuard(policy="balanced")
        result = guard.check(
            "read_file",
            {"path": "/app/main.py"},
            session_id="s1",
            agent_id="agent-001",
        )
        assert result.decision == Decision.ALLOW

    def test_guard_property(self) -> None:
        from spidershield import RuntimeGuard, SpiderGuard

        guard = SpiderGuard(policy="balanced")
        assert isinstance(guard.guard, RuntimeGuard)

    def test_policy_engine_property(self) -> None:
        from spidershield import PolicyEngine, SpiderGuard

        guard = SpiderGuard(policy="balanced")
        assert isinstance(guard.policy_engine, PolicyEngine)
        assert len(guard.policy_engine.rules) > 0

    def test_with_audit(self, tmp_path: Path) -> None:
        from spidershield import Decision, SpiderGuard

        guard = SpiderGuard(policy="balanced", audit=True, audit_dir=str(tmp_path))
        result = guard.check("read_file", {"path": "/app/.env"})
        assert result.decision == Decision.DENY

        # Verify audit file created
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1

    def test_after_check(self) -> None:
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced")
        result = guard.after_check("read_file", {"data": "hello"})
        assert result == {"data": "hello"}  # passthrough (no DLP yet)

    def test_invalid_policy_raises(self) -> None:
        from spidershield import SpiderGuard

        with pytest.raises(ValueError, match="not a preset"):
            SpiderGuard(policy="nonexistent")


# ---------------------------------------------------------------------------
# guard_mcp_server() — can only test that it's callable
# ---------------------------------------------------------------------------


class TestGuardMCPServer:
    def test_importable(self) -> None:
        from spidershield import guard_mcp_server

        assert callable(guard_mcp_server)


# ---------------------------------------------------------------------------
# Policy validate CLI
# ---------------------------------------------------------------------------


class TestPolicyValidateCLI:
    def test_validate_valid_policy(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text("policies:\n"
            "  - name: block-env\n"
            "    match:\n"
            "      tool: read_file\n"
            "      args_pattern:\n"
            "        path: '.*\\.env'\n"
            "    action: deny\n"
            "    reason: Blocked\n"
            "    suggestion: Use workspace files\n"
        )
        from spidershield.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["policy", "validate", str(policy_file)])
        assert result.exit_code == 0
        assert "Valid" in result.output
        assert "1 rule(s)" in result.output

    def test_validate_invalid_yaml(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text("{{{{invalid yaml")

        from spidershield.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["policy", "validate", str(policy_file)])
        assert result.exit_code != 0

    def test_validate_missing_policies_key(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "missing.yaml"
        policy_file.write_text("rules:\n  - name: test\n")

        from spidershield.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["policy", "validate", str(policy_file)])
        assert result.exit_code != 0
        assert "Missing 'policies'" in result.output

    def test_validate_missing_required_fields(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "incomplete.yaml"
        policy_file.write_text("""policies:
  - reason: "test"
""")
        from spidershield.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["policy", "validate", str(policy_file)])
        assert result.exit_code != 0
        assert "missing 'name'" in result.output

    def test_validate_invalid_action(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "bad-action.yaml"
        policy_file.write_text("""policies:
  - name: test
    match:
      tool: read_file
    action: destroy
    reason: "test"
""")
        from spidershield.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["policy", "validate", str(policy_file)])
        assert result.exit_code != 0
        assert "invalid action" in result.output

    def test_validate_multi_rule(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "multi.yaml"
        policy_file.write_text("policies:\n"
            "  - name: block-env\n"
            "    match:\n"
            "      tool: read_file\n"
            "      args_pattern:\n"
            "        path: '.*\\.env'\n"
            "    action: deny\n"
            "    reason: Blocked\n"
            "  - name: review-email\n"
            "    match:\n"
            "      tool: send_email\n"
            "    action: escalate\n"
            "    reason: Needs review\n"
            "  - name: cost-limit\n"
            "    match:\n"
            "      any_tool: true\n"
            "    condition:\n"
            "      token_spent_gt: 50000\n"
            "    action: deny\n"
            "    reason: Budget exceeded\n"
        )
        from spidershield.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["policy", "validate", str(policy_file)])
        assert result.exit_code == 0
        assert "3 rule(s)" in result.output
