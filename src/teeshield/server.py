"""TeeShield MCP Server -- exposes scan + agent-check as MCP tools."""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from teeshield.scanner.runner import run_scan_report

logger = logging.getLogger("teeshield.server")

app = Server("teeshield")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="scan_mcp_server",
            description=(
                "Scan an MCP server for security vulnerabilities, description quality, "
                "and architecture issues. Checks for path traversal, command injection, "
                "SQL injection, SSRF, hardcoded credentials, and unsafe deserialization. "
                "Scores tool descriptions for scenario triggers, parameter docs, and "
                "disambiguation. Returns a security rating (F/C/B/A/A+) with actionable "
                "recommendations. Use when evaluating whether an MCP server is safe to "
                "install or deploy."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "GitHub repo URL or local directory path "
                            "of the MCP server to scan"
                        ),
                    }
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="check_agent_security",
            description=(
                "Scan an AI agent installation for security issues. Checks agent "
                "configuration (gateway binding, authentication, sandbox, API keys "
                "in plaintext, DM policy, tool permissions, SSRF protection, file "
                "permissions, log redaction) and installed skills for malicious "
                "patterns (reverse shells, credential theft, prompt injection, "
                "toxic data flows). Returns findings with severity levels and "
                "fix hints. Use when auditing an agent's security posture or "
                "before deploying an agent to production."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "agent_dir": {
                        "type": "string",
                        "description": (
                            "Path to agent config directory. "
                            "Defaults to ~/.openclaw if not specified."
                        ),
                    },
                    "scan_skills": {
                        "type": "boolean",
                        "description": (
                            "Include skill scanning for malicious "
                            "patterns (default: true)"
                        ),
                    },
                    "verify_pins": {
                        "type": "boolean",
                        "description": (
                            "Verify pinned skills for rug pull "
                            "detection (default: false)"
                        ),
                    },
                    "policy": {
                        "type": "string",
                        "enum": ["strict", "balanced", "permissive"],
                        "description": "Scan policy preset (default: balanced)",
                    },
                },
                "required": [],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "scan_mcp_server":
        return _handle_scan(arguments)

    if name == "check_agent_security":
        return _handle_agent_check(arguments)

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


def _handle_scan(arguments: dict) -> list[TextContent]:
    target = arguments.get("target", "")
    if not target:
        return [TextContent(type="text", text="Error: 'target' argument is required")]
    try:
        report = run_scan_report(target)
        result = report.model_dump_json(indent=2)
        return [TextContent(type="text", text=result)]
    except Exception as e:
        logger.exception("Scan failed")
        return [TextContent(type="text", text=f"Scan failed: {e}")]


def _handle_agent_check(arguments: dict) -> list[TextContent]:
    try:
        from teeshield.agent.issue_codes import SKILL_WARNING_CODES
        from teeshield.agent.scanner import scan_config
        from teeshield.agent.skill_scanner import scan_skills

        agent_dir_str = arguments.get("agent_dir")
        agent_path = Path(agent_dir_str) if agent_dir_str else None
        scan_skills_flag = arguments.get("scan_skills", True)
        verify_pins = arguments.get("verify_pins", False)
        policy = arguments.get("policy")

        ignored: set[str] = set()
        if policy == "permissive":
            ignored = set(SKILL_WARNING_CODES.keys())

        result = scan_config(agent_path, ignore_patterns=ignored)

        if scan_skills_flag:
            result.skill_findings.extend(
                scan_skills(agent_path, ignore_patterns=ignored)
            )

        if verify_pins:
            from teeshield.agent.pinning import verify_all_skills
            result.skill_findings.extend(verify_all_skills(agent_path))

        result.audit_framework.source_checked = verify_pins
        result.audit_framework.code_checked = scan_skills_flag
        result.audit_framework.permission_checked = True
        result.audit_framework.risk_checked = True

        output = json.dumps(dataclasses.asdict(result), indent=2)
        return [TextContent(type="text", text=output)]
    except Exception as e:
        logger.exception("Agent check failed")
        return [TextContent(type="text", text=f"Agent check failed: {e}")]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def run():
    """Synchronous entry point for the console script."""
    import asyncio

    asyncio.run(main())


if __name__ == "__main__":
    run()
