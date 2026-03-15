"""Tests for SpiderShield MCP Server mode (server.py).

Covers:
- Tool listing (schema, names, descriptions)
- scan_mcp_server tool call (success + error cases)
- check_agent_security tool call (success + options)
- Unknown tool handling
- Entry point (run function)
- End-to-end stdio JSON-RPC handshake (real subprocess)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from spidershield.server import (
    _handle_agent_check,
    _handle_scan,
    app,
    call_tool,
    list_tools,
)

# ---------------------------------------------------------------------------
# Tool listing
# ---------------------------------------------------------------------------


class TestListTools:
    """Verify the MCP tool registry is correct."""

    @pytest.mark.asyncio
    async def test_lists_two_tools(self) -> None:
        tools = await list_tools()
        assert len(tools) == 2

    @pytest.mark.asyncio
    async def test_tool_names(self) -> None:
        tools = await list_tools()
        names = {t.name for t in tools}
        assert names == {"scan_mcp_server", "check_agent_security"}

    @pytest.mark.asyncio
    async def test_scan_tool_schema(self) -> None:
        tools = await list_tools()
        scan_tool = next(t for t in tools if t.name == "scan_mcp_server")
        schema = scan_tool.inputSchema
        assert schema["type"] == "object"
        assert "target" in schema["properties"]
        assert "target" in schema["required"]

    @pytest.mark.asyncio
    async def test_agent_check_schema(self) -> None:
        tools = await list_tools()
        agent_tool = next(t for t in tools if t.name == "check_agent_security")
        schema = agent_tool.inputSchema
        assert schema["type"] == "object"
        assert "agent_dir" in schema["properties"]
        assert "scan_skills" in schema["properties"]
        assert "verify_pins" in schema["properties"]
        assert "policy" in schema["properties"]
        # No required fields for agent check
        assert schema["required"] == []

    @pytest.mark.asyncio
    async def test_scan_tool_description_quality(self) -> None:
        """Tool descriptions should follow our own quality standards."""
        tools = await list_tools()
        scan_tool = next(t for t in tools if t.name == "scan_mcp_server")
        desc = scan_tool.description
        # Should have action verb, scenario trigger, and specifics
        assert "Scan" in desc
        assert "Use when" in desc
        assert len(desc) > 100  # not too short

    @pytest.mark.asyncio
    async def test_agent_tool_description_quality(self) -> None:
        tools = await list_tools()
        agent_tool = next(t for t in tools if t.name == "check_agent_security")
        desc = agent_tool.description
        assert "Scan" in desc
        assert "Use when" in desc
        assert len(desc) > 100


# ---------------------------------------------------------------------------
# scan_mcp_server tool
# ---------------------------------------------------------------------------


class TestScanTool:
    """Test _handle_scan and call_tool dispatch for scan_mcp_server."""

    def test_missing_target_returns_error(self) -> None:
        result = _handle_scan({})
        assert len(result) == 1
        assert "Error" in result[0].text
        assert "target" in result[0].text

    def test_empty_target_returns_error(self) -> None:
        result = _handle_scan({"target": ""})
        assert "Error" in result[0].text

    @patch("spidershield.server.run_scan_report")
    def test_successful_scan(self, mock_scan: MagicMock) -> None:
        mock_report = MagicMock()
        mock_report.model_dump_json.return_value = '{"score": 8.5}'
        mock_scan.return_value = mock_report

        result = _handle_scan({"target": "/tmp/test-repo"})
        assert len(result) == 1
        assert '"score"' in result[0].text
        mock_scan.assert_called_once_with("/tmp/test-repo")

    @patch("spidershield.server.run_scan_report")
    def test_scan_exception_returns_error(self, mock_scan: MagicMock) -> None:
        mock_scan.side_effect = RuntimeError("Clone failed")

        result = _handle_scan({"target": "https://github.com/nonexistent/repo"})
        assert "Scan failed" in result[0].text
        assert "Clone failed" in result[0].text

    @pytest.mark.asyncio
    @patch("spidershield.server.run_scan_report")
    async def test_call_tool_dispatches_scan(self, mock_scan: MagicMock) -> None:
        mock_report = MagicMock()
        mock_report.model_dump_json.return_value = '{"ok": true}'
        mock_scan.return_value = mock_report

        result = await call_tool("scan_mcp_server", {"target": "/tmp/test"})
        assert '"ok"' in result[0].text


# ---------------------------------------------------------------------------
# check_agent_security tool
# ---------------------------------------------------------------------------


class TestAgentCheckTool:
    """Test _handle_agent_check with various options."""

    def test_default_options(self, tmp_path: Path) -> None:
        """Agent check with defaults should not crash."""
        # Create a minimal agent config directory
        (tmp_path / "config.yaml").write_text("gateway:\n  bind: 0.0.0.0:8080\n")

        result = _handle_agent_check({"agent_dir": str(tmp_path)})
        assert len(result) == 1
        # Should be valid JSON
        data = json.loads(result[0].text)
        assert "findings" in data

    def test_scan_skills_disabled(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("gateway:\n  bind: localhost:8080\n")

        result = _handle_agent_check({
            "agent_dir": str(tmp_path),
            "scan_skills": False,
        })
        data = json.loads(result[0].text)
        assert "findings" in data

    def test_permissive_policy_ignores_warnings(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("gateway:\n  bind: 0.0.0.0:8080\n")

        result = _handle_agent_check({
            "agent_dir": str(tmp_path),
            "policy": "permissive",
            "scan_skills": False,
        })
        data = json.loads(result[0].text)
        assert "findings" in data

    def test_nonexistent_dir_handled_gracefully(self) -> None:
        """Should not crash on nonexistent directory."""
        result = _handle_agent_check({
            "agent_dir": "/nonexistent/path/12345",
            "scan_skills": False,
        })
        assert len(result) == 1
        # Should either return findings or error gracefully
        text = result[0].text
        assert "findings" in text or "Agent check failed" in text

    @pytest.mark.asyncio
    async def test_call_tool_dispatches_agent_check(self, tmp_path: Path) -> None:
        (tmp_path / "config.yaml").write_text("gateway:\n  bind: localhost:8080\n")

        result = await call_tool("check_agent_security", {
            "agent_dir": str(tmp_path),
            "scan_skills": False,
        })
        assert len(result) == 1
        data = json.loads(result[0].text)
        assert "findings" in data


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------


class TestUnknownTool:
    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self) -> None:
        result = await call_tool("nonexistent_tool", {})
        assert "Unknown tool" in result[0].text
        assert "nonexistent_tool" in result[0].text


# ---------------------------------------------------------------------------
# Server app structure
# ---------------------------------------------------------------------------


class TestServerApp:
    def test_app_name(self) -> None:
        assert app.name == "spidershield"

    def test_run_entrypoint_exists(self) -> None:
        from spidershield.server import run
        assert callable(run)

    def test_main_is_async(self) -> None:
        import inspect

        from spidershield.server import main
        assert inspect.iscoroutinefunction(main)


# ---------------------------------------------------------------------------
# End-to-end stdio JSON-RPC (real subprocess)
# ---------------------------------------------------------------------------


class TestServerE2E:
    """Launch spidershield-server as a subprocess and talk MCP protocol."""

    @pytest.mark.asyncio
    async def test_initialize_handshake(self) -> None:
        """Server responds to MCP initialize request over stdio."""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "spidershield.server"],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                result = await session.initialize()
                assert result is not None
                # Server should identify itself
                assert result.serverInfo.name == "spidershield"

    @pytest.mark.asyncio
    async def test_list_tools_e2e(self) -> None:
        """List tools via real MCP protocol."""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "spidershield.server"],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                tool_names = {t.name for t in tools_result.tools}
                assert "scan_mcp_server" in tool_names
                assert "check_agent_security" in tool_names

    @pytest.mark.asyncio
    async def test_call_scan_missing_target_e2e(self) -> None:
        """Call scan_mcp_server with missing target via real protocol."""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "spidershield.server"],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("scan_mcp_server", {"target": ""})
                assert len(result.content) >= 1
                assert "Error" in result.content[0].text

    @pytest.mark.asyncio
    async def test_call_agent_check_e2e(self, tmp_path: Path) -> None:
        """Call check_agent_security via real protocol."""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        (tmp_path / "config.yaml").write_text("gateway:\n  bind: localhost:8080\n")

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "spidershield.server"],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("check_agent_security", {
                    "agent_dir": str(tmp_path),
                    "scan_skills": False,
                })
                data = json.loads(result.content[0].text)
                assert "findings" in data

    @pytest.mark.asyncio
    async def test_unknown_tool_e2e(self) -> None:
        """Unknown tool returns error via real protocol."""
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        server_params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "spidershield.server"],
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("nonexistent_tool", {})
                assert "Unknown tool" in result.content[0].text
