"""Tests for the SpiderShield Audit Engine (logger + storage + CLI)."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from spidershield.audit.logger import AuditLogger
from spidershield.audit.storage import AuditQuery, AuditStats
from spidershield.cli import main

# ---------------------------------------------------------------------------
# AuditLogger tests
# ---------------------------------------------------------------------------


class TestAuditLogger:
    def test_creates_audit_dir(self, tmp_path: Path) -> None:
        audit_dir = tmp_path / "audit"
        AuditLogger(audit_dir)
        assert audit_dir.exists()

    def test_log_writes_jsonl(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        logger.log({"phase": "before_call", "tool_name": "read_file", "decision": "allow"})

        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1

        lines = files[0].read_text().strip().split("\n")
        assert len(lines) == 1

        entry = json.loads(lines[0])
        assert entry["phase"] == "before_call"
        assert entry["tool_name"] == "read_file"
        assert "timestamp" in entry

    def test_log_before_call(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        logger.log_before_call(
            session_id="s1",
            agent_id="a1",
            tool_name="exec_cmd",
            call_index=0,
            decision="deny",
            reason="shell blocked",
            policy_matched="block-shell",
            suggestion="Use a safer alternative",
        )

        files = list(tmp_path.glob("*.jsonl"))
        entry = json.loads(files[0].read_text().strip())
        assert entry["phase"] == "before_call"
        assert entry["decision"] == "deny"
        assert entry["policy_matched"] == "block-shell"
        assert entry["suggestion"] == "Use a safer alternative"

    def test_log_after_call_with_latency(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)

        # Start timer via before_call
        logger.log_before_call(
            session_id="s1",
            agent_id="a1",
            tool_name="read_file",
            call_index=0,
            decision="allow",
            reason="ok",
        )

        # End timer via after_call
        logger.log_after_call(
            session_id="s1",
            agent_id="a1",
            tool_name="read_file",
            call_index=0,
            pii_detected=["email"],
        )

        files = list(tmp_path.glob("*.jsonl"))
        lines = files[0].read_text().strip().split("\n")
        assert len(lines) == 2

        after = json.loads(lines[1])
        assert after["phase"] == "after_call"
        assert after["pii_detected"] == ["email"]
        assert after["latency_ms"] is not None
        assert after["latency_ms"] >= 0

    def test_log_after_call_no_timer(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        logger.log_after_call(
            session_id="s1",
            agent_id="a1",
            tool_name="read_file",
            call_index=99,
        )

        files = list(tmp_path.glob("*.jsonl"))
        entry = json.loads(files[0].read_text().strip())
        assert entry["latency_ms"] is None

    def test_daily_rotation_filename(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path)
        logger.log({"test": True})

        today = datetime.now(UTC).strftime("%Y-%m-%d")
        expected_file = tmp_path / f"{today}.jsonl"
        assert expected_file.exists()


# ---------------------------------------------------------------------------
# AuditQuery / AuditStats tests
# ---------------------------------------------------------------------------


class TestAuditQuery:
    @pytest.fixture()
    def populated_audit_dir(self, tmp_path: Path) -> Path:
        """Create a tmp audit dir with sample entries."""
        logger = AuditLogger(tmp_path)

        # 3 before_call entries
        logger.log({
            "phase": "before_call",
            "session_id": "s1",
            "agent_id": "a1",
            "tool_name": "read_file",
            "call_index": 0,
            "decision": "allow",
            "reason": "ok",
            "policy_matched": None,
        })
        logger.log({
            "phase": "before_call",
            "session_id": "s1",
            "agent_id": "a1",
            "tool_name": "exec_cmd",
            "call_index": 1,
            "decision": "deny",
            "reason": "shell blocked",
            "policy_matched": "block-shell",
        })
        logger.log({
            "phase": "before_call",
            "session_id": "s2",
            "agent_id": "a2",
            "tool_name": "send_email",
            "call_index": 0,
            "decision": "escalate",
            "reason": "needs review",
            "policy_matched": "review-email",
        })

        # 1 after_call with PII
        logger.log({
            "phase": "after_call",
            "session_id": "s1",
            "agent_id": "a1",
            "tool_name": "read_file",
            "call_index": 0,
            "pii_detected": ["ssn"],
        })

        return tmp_path

    def test_query_all(self, populated_audit_dir: Path) -> None:
        q = AuditQuery(populated_audit_dir)
        entries = q.query()
        assert len(entries) == 4

    def test_query_filter_phase(self, populated_audit_dir: Path) -> None:
        q = AuditQuery(populated_audit_dir)
        entries = q.query(phase="before_call")
        assert len(entries) == 3

    def test_query_filter_decision(self, populated_audit_dir: Path) -> None:
        q = AuditQuery(populated_audit_dir)
        entries = q.query(decision="deny")
        assert len(entries) == 1
        assert entries[0]["tool_name"] == "exec_cmd"

    def test_query_filter_session(self, populated_audit_dir: Path) -> None:
        q = AuditQuery(populated_audit_dir)
        entries = q.query(session_id="s2")
        assert len(entries) == 1
        assert entries[0]["tool_name"] == "send_email"

    def test_query_filter_tool(self, populated_audit_dir: Path) -> None:
        q = AuditQuery(populated_audit_dir)
        entries = q.query(tool_name="email")
        assert len(entries) == 1

    def test_query_empty_dir(self, tmp_path: Path) -> None:
        q = AuditQuery(tmp_path / "nonexistent")
        entries = q.query()
        assert entries == []

    def test_stats(self, populated_audit_dir: Path) -> None:
        q = AuditQuery(populated_audit_dir)
        stats = q.stats()

        assert stats.total_calls == 3
        assert stats.allowed == 1
        assert stats.denied == 1
        assert stats.escalated == 1
        assert stats.pii_detections == 1
        assert stats.denied_pct == pytest.approx(33.3, abs=0.1)
        assert stats.escalated_pct == pytest.approx(33.3, abs=0.1)

    def test_stats_top_denied_tools(self, populated_audit_dir: Path) -> None:
        q = AuditQuery(populated_audit_dir)
        stats = q.stats()
        assert ("exec_cmd", 1) in stats.top_denied_tools

    def test_stats_top_triggered_rules(self, populated_audit_dir: Path) -> None:
        q = AuditQuery(populated_audit_dir)
        stats = q.stats()
        rule_names = [r[0] for r in stats.top_triggered_rules]
        assert "block-shell" in rule_names
        assert "review-email" in rule_names

    def test_stats_empty(self, tmp_path: Path) -> None:
        q = AuditQuery(tmp_path)
        stats = q.stats()
        assert stats.total_calls == 0
        assert stats.denied_pct == 0


# ---------------------------------------------------------------------------
# AuditStats dataclass tests
# ---------------------------------------------------------------------------


class TestAuditStats:
    def test_defaults(self) -> None:
        stats = AuditStats()
        assert stats.total_calls == 0
        assert stats.top_denied_tools == []
        assert stats.top_triggered_rules == []

    def test_denied_pct_zero_division(self) -> None:
        stats = AuditStats(total_calls=0, denied=0)
        assert stats.denied_pct == 0

    def test_denied_pct_calculation(self) -> None:
        stats = AuditStats(total_calls=10, denied=3)
        assert stats.denied_pct == 30.0


# ---------------------------------------------------------------------------
# CLI audit commands tests
# ---------------------------------------------------------------------------


class TestAuditCLI:
    @pytest.fixture()
    def audit_dir_with_data(self, tmp_path: Path) -> Path:
        """Create audit dir with sample data for CLI tests."""
        logger = AuditLogger(tmp_path)
        logger.log({
            "phase": "before_call",
            "session_id": "cli-test",
            "agent_id": "a1",
            "tool_name": "read_file",
            "call_index": 0,
            "decision": "allow",
            "reason": "ok",
        })
        logger.log({
            "phase": "before_call",
            "session_id": "cli-test",
            "agent_id": "a1",
            "tool_name": "exec_cmd",
            "call_index": 1,
            "decision": "deny",
            "reason": "blocked by policy",
            "policy_matched": "block-shell",
        })
        return tmp_path

    def test_audit_show_no_data(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "--audit-dir", str(tmp_path), "show"])
        assert result.exit_code == 0
        assert "No audit entries found" in result.output

    def test_audit_show_with_data(self, audit_dir_with_data: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "--audit-dir", str(audit_dir_with_data), "show",
        ])
        assert result.exit_code == 0
        assert "Audit Log" in result.output
        assert "2 entries" in result.output

    def test_audit_show_filter_decision(self, audit_dir_with_data: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "--audit-dir", str(audit_dir_with_data),
            "show", "--decision", "deny",
        ])
        assert result.exit_code == 0
        assert "1 entries" in result.output
        assert "DENY" in result.output

    def test_audit_show_json(self, audit_dir_with_data: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "--audit-dir", str(audit_dir_with_data),
            "show", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_audit_stats_no_data(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "--audit-dir", str(tmp_path), "stats"])
        assert result.exit_code == 0
        assert "No audit data found" in result.output

    def test_audit_stats_with_data(self, audit_dir_with_data: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "--audit-dir", str(audit_dir_with_data), "stats",
        ])
        assert result.exit_code == 0
        assert "Total calls" in result.output

    def test_audit_stats_json(self, audit_dir_with_data: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "--audit-dir", str(audit_dir_with_data),
            "stats", "--json",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_calls"] == 2
        assert data["denied"] == 1


# ---------------------------------------------------------------------------
# Integration: RuntimeGuard → AuditLogger
# ---------------------------------------------------------------------------


class TestGuardAuditIntegration:
    def test_guard_writes_to_audit_logger(self, tmp_path: Path) -> None:
        from spidershield.guard.context import CallContext
        from spidershield.guard.core import RuntimeGuard
        from spidershield.guard.decision import Decision
        from spidershield.guard.policy import PolicyEngine, PolicyRule

        logger = AuditLogger(tmp_path)
        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="sensitive file",
            tool_match="read_file",
            args_patterns={"path": r"\.env"},
        )
        engine = PolicyEngine([rule])
        guard = RuntimeGuard(policy_engine=engine, audit_logger=logger)

        ctx = CallContext(
            session_id="int-test",
            agent_id="a1",
            tool_name="read_file",
            arguments={"path": "/app/.env"},
        )
        result = guard.before_call(ctx)
        assert result.decision == Decision.DENY

        # Verify audit file was written
        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1
        entry = json.loads(files[0].read_text().strip())
        assert entry["phase"] == "before_call"
        assert entry["decision"] == "deny"
        assert entry["tool_name"] == "read_file"
        assert entry["policy_matched"] == "block-env"

    def test_guard_allow_writes_audit(self, tmp_path: Path) -> None:
        from spidershield.guard.context import CallContext
        from spidershield.guard.core import RuntimeGuard

        logger = AuditLogger(tmp_path)
        guard = RuntimeGuard(audit_logger=logger)

        ctx = CallContext(
            session_id="int-test",
            agent_id="a1",
            tool_name="read_file",
            arguments={"path": "/app/main.py"},
        )
        guard.before_call(ctx)

        files = list(tmp_path.glob("*.jsonl"))
        assert len(files) == 1
        entry = json.loads(files[0].read_text().strip())
        assert entry["decision"] == "allow"
