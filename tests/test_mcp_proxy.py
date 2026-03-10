"""Tests for the MCP Proxy adapter and JSON-RPC utilities."""

import io
import json

from spidershield.guard import Decision, PolicyEngine, PolicyRule, RuntimeGuard
from spidershield.utils.jsonrpc import (
    extract_tool_info,
    is_tool_call,
    make_denied_response,
    parse_message,
    serialize_message,
)


class TestJsonRpc:
    def test_parse_valid_message(self):
        msg = parse_message('{"jsonrpc": "2.0", "method": "test"}')
        assert msg is not None
        assert msg["method"] == "test"

    def test_parse_empty_line(self):
        assert parse_message("") is None
        assert parse_message("  \n") is None

    def test_parse_invalid_json(self):
        assert parse_message("not json") is None

    def test_is_tool_call_true(self):
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp"}},
        }
        assert is_tool_call(msg) is True

    def test_is_tool_call_false(self):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        assert is_tool_call(msg) is False

    def test_extract_tool_info(self):
        msg = {
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/test.txt"},
            }
        }
        name, args = extract_tool_info(msg)
        assert name == "read_file"
        assert args == {"path": "/tmp/test.txt"}

    def test_extract_tool_info_missing(self):
        name, args = extract_tool_info({})
        assert name == ""
        assert args == {}

    def test_make_denied_response(self):
        resp = make_denied_response(
            request_id=42,
            reason="sandbox violation",
            suggestion="use /workspace/",
            policy_matched="sandbox-rule",
        )
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 42
        assert resp["error"]["code"] == -32001
        assert "sandbox violation" in resp["error"]["message"]
        assert resp["error"]["data"]["denied"] is True
        assert resp["error"]["data"]["reason"] == "sandbox violation"
        assert resp["error"]["data"]["suggestion"] == "use /workspace/"

    def test_serialize_message(self):
        msg = {"jsonrpc": "2.0", "id": 1}
        s = serialize_message(msg)
        assert s.endswith("\n")
        assert json.loads(s) == msg


class TestMCPProxyGuard:
    """Test MCPProxyGuard message routing logic."""

    def test_passthrough_non_tool_call(self):
        """Non-tools/call messages should be forwarded as-is."""
        from spidershield.adapters.mcp_proxy import MCPProxyGuard

        guard = RuntimeGuard()
        MCPProxyGuard(guard)  # verify instantiation works

        # Simulate: client sends tools/list, should passthrough
        client_in = io.StringIO('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n')
        server_in = io.StringIO()  # noqa: F841

        # Manually test the relay logic
        for line in client_in:
            msg = parse_message(line)
            if msg and is_tool_call(msg):
                pass  # Would be intercepted
            else:
                server_in.write(line)

        server_in.seek(0)
        assert "tools/list" in server_in.read()

    def test_deny_returns_error_to_client(self):
        """Denied tool calls should return error to client, not forward."""
        from spidershield.adapters.mcp_proxy import MCPProxyGuard

        rule = PolicyRule(
            name="block-env",
            action=Decision.DENY,
            reason="sensitive file",
            suggestion="use /workspace/",
            tool_match="read_file",
            args_patterns={"path": r"\.env$"},
        )
        engine = PolicyEngine([rule])
        guard = RuntimeGuard(policy_engine=engine)
        proxy = MCPProxyGuard(guard)

        # Simulate tools/call for .env file
        tool_call = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/app/.env"},
            },
        }
        client_in = io.StringIO(json.dumps(tool_call) + "\n")
        server_in = io.StringIO()
        client_out = io.StringIO()

        # Run relay
        proxy._relay_client_to_server(client_in, server_in, client_out)

        # Server should NOT receive the denied call
        server_in.seek(0)
        assert server_in.read() == ""

        # Client should receive error response
        client_out.seek(0)
        response = json.loads(client_out.read())
        assert response["error"]["code"] == -32001
        assert response["error"]["data"]["denied"] is True
        assert "sensitive file" in response["error"]["data"]["reason"]
        assert response["error"]["data"]["suggestion"] == "use /workspace/"

    def test_allow_forwards_to_server(self):
        """Allowed tool calls should be forwarded to server."""
        from spidershield.adapters.mcp_proxy import MCPProxyGuard

        # No rules = allow all
        guard = RuntimeGuard()
        proxy = MCPProxyGuard(guard)

        tool_call = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/app/main.py"},
            },
        }
        client_in = io.StringIO(json.dumps(tool_call) + "\n")
        server_in = io.StringIO()
        client_out = io.StringIO()

        proxy._relay_client_to_server(client_in, server_in, client_out)

        # Server should receive the call
        server_in.seek(0)
        forwarded = server_in.read()
        assert "read_file" in forwarded

        # Client should NOT receive an error
        client_out.seek(0)
        assert client_out.read() == ""


class TestActionableDenial:
    """Test the actionable denial format end-to-end."""

    def test_denial_has_reason_and_suggestion(self):
        """Every denial must include reason and suggestion for agent to adapt."""
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced")

        # .env file should be denied with reason + suggestion
        result = guard.check("read_file", {"path": "/app/.env"})
        assert result.denied is True
        assert len(result.reason) > 0
        assert len(result.suggestion) > 0

    def test_denial_serializes_to_agent_format(self):
        """Denial must serialize to the agent-consumable dict format."""
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced")
        result = guard.check("read_file", {"path": "/app/.env"})

        d = result.to_dict()
        assert d["decision"] == "deny"
        assert "reason" in d
        assert "suggestion" in d

    def test_allow_has_no_suggestion(self):
        """Allowed calls should have minimal response."""
        from spidershield import SpiderGuard

        guard = SpiderGuard(policy="balanced")
        result = guard.check("read_file", {"path": "/app/main.py"})

        assert result.denied is False
        d = result.to_dict()
        assert d["decision"] == "allow"
        assert "suggestion" not in d
