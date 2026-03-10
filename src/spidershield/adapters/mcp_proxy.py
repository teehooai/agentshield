"""MCP Proxy Adapter — stdio proxy between MCP Client and Server.

Sits between Claude Desktop / Cursor and the real MCP server.
Intercepts tools/call requests and enforces security policies.

Architecture:
    MCP Client (Claude Desktop)
         ↓ stdin
    SpiderShield MCP Proxy
         ├─ tools/call → RuntimeGuard.before_call()
         │   ├─ ALLOW → forward to server
         │   ├─ DENY → return error with reason + suggestion
         │   └─ ESCALATE → terminal prompt → allow/deny
         ├─ other messages → passthrough
         ↓ stdout
    MCP Server (real server subprocess)
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import IO, Any

from ..guard.core import RuntimeGuard
from ..guard.decision import Decision
from ..guard.policy import PolicyEngine
from ..utils.jsonrpc import (
    extract_tool_info,
    is_tool_call,
    make_denied_response,
    parse_message,
    serialize_message,
)
from .base import AdapterBase


class MCPProxyGuard(AdapterBase):
    """MCP stdio proxy with security guard.

    Reads JSON-RPC messages from client_in, evaluates tools/call
    against the RuntimeGuard, and forwards allowed calls to the
    real MCP server subprocess.
    """

    @property
    def framework_name(self) -> str:
        return "mcp"

    def run(
        self,
        server_cmd: list[str] | None = None,
        client_in: IO[str] | None = None,
        client_out: IO[str] | None = None,
        **kwargs: Any,
    ) -> int:
        """Start proxy: launch server subprocess and relay messages.

        Args:
            server_cmd: Command to start the real MCP server.
            client_in: Client input stream (default: sys.stdin).
            client_out: Client output stream (default: sys.stdout).

        Returns:
            Server process return code.
        """
        if not server_cmd:
            raise ValueError("server_cmd is required")

        client_in = client_in or sys.stdin
        client_out = client_out or sys.stdout

        # Launch real MCP server as subprocess
        proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

        try:
            # Thread: relay server stdout → client stdout
            relay_thread = threading.Thread(
                target=self._relay_server_to_client,
                args=(proc.stdout, client_out),
                daemon=True,
            )
            relay_thread.start()

            # Main thread: relay client stdin → (guard) → server stdin
            self._relay_client_to_server(client_in, proc.stdin, client_out)

        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        return proc.returncode or 0

    def _relay_client_to_server(
        self,
        client_in: IO[str],
        server_in: IO[str],
        client_out: IO[str],
    ) -> None:
        """Read from client, evaluate tool calls, forward to server."""
        for line in client_in:
            msg = parse_message(line)
            if msg is None:
                # Non-JSON line — passthrough
                server_in.write(line)
                server_in.flush()
                continue

            if is_tool_call(msg):
                # Intercept tools/call
                tool_name, arguments = extract_tool_info(msg)
                result = self.evaluate_tool_call(tool_name, arguments)

                if result.decision == Decision.DENY:
                    # Return error to client, don't forward to server
                    error_msg = make_denied_response(
                        request_id=msg.get("id"),
                        reason=result.reason,
                        suggestion=result.suggestion,
                        policy_matched=result.policy_matched,
                    )
                    client_out.write(serialize_message(error_msg))
                    client_out.flush()
                    self._log(f"DENY: {tool_name} — {result.reason}")
                    continue

                if result.decision == Decision.ESCALATE:
                    # Terminal prompt for human approval
                    if not self._prompt_human(tool_name, arguments, result.reason):
                        error_msg = make_denied_response(
                            request_id=msg.get("id"),
                            reason="Denied by human review",
                            suggestion=result.suggestion,
                        )
                        client_out.write(serialize_message(error_msg))
                        client_out.flush()
                        self._log(f"ESCALATE→DENY: {tool_name}")
                        continue
                    self._log(f"ESCALATE→ALLOW: {tool_name}")

                self._log(f"ALLOW: {tool_name}")

            # Forward to server (passthrough or allowed tool call)
            server_in.write(line)
            server_in.flush()

    def _relay_server_to_client(
        self,
        server_out: IO[str],
        client_out: IO[str],
    ) -> None:
        """Relay server responses to client (with DLP scanning)."""
        for line in server_out:
            # DLP scan on server responses
            scanned = self.evaluate_tool_result("server_response", line)
            if isinstance(scanned, str):
                client_out.write(scanned)
            else:
                client_out.write(line)
            client_out.flush()

    def _prompt_human(
        self, tool_name: str, arguments: dict[str, Any], reason: str
    ) -> bool:
        """Terminal prompt for ESCALATE decisions."""
        print(
            "\n[SpiderShield] Tool call requires approval:",
            file=sys.stderr,
        )
        print(f"  Tool: {tool_name}", file=sys.stderr)
        print(f"  Args: {json.dumps(arguments, indent=2)}", file=sys.stderr)
        print(f"  Reason: {reason}", file=sys.stderr)
        try:
            answer = input("  Allow? [y/N] ").strip().lower()
            return answer in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False


def run_mcp_proxy(
    server_cmd: list[str],
    policy: str = "balanced",
    verbose: bool = False,
    audit_dir: str | None = None,
    no_audit: bool = False,
    dry_run: bool = False,
) -> int:
    """Convenience function to run an MCP proxy with security guard.

    Args:
        server_cmd: Command to start the real MCP server.
        policy: Policy preset name or YAML file path.
        verbose: Enable verbose logging to stderr.
        audit_dir: Custom audit log directory (default: ~/.spidershield/audit/).
        no_audit: Disable audit logging.
        dry_run: Log decisions but don't enforce denials.

    Returns:
        Server process return code.
    """
    from ..audit.logger import AuditLogger

    engine = PolicyEngine.from_name_or_path(policy)
    logger = None if no_audit else AuditLogger(audit_dir)
    guard = RuntimeGuard(policy_engine=engine, audit_logger=logger)
    proxy = MCPProxyGuard(guard, verbose=verbose, dry_run=dry_run)
    return proxy.run(server_cmd=server_cmd)
