"""Standalone Guard Adapter — wraps any subprocess with security guard.

Unlike the MCP proxy (which intercepts JSON-RPC), the standalone adapter
watches stdin/stdout for tool-call-like patterns and evaluates them.

Primary use case: wrapping agent scripts that output tool calls as JSON.

Expected format (one JSON object per line on stdout):
    {"tool": "read_file", "arguments": {"path": "/etc/passwd"}}

The adapter:
1. Launches the subprocess
2. Relays stdin to the subprocess
3. Reads stdout lines, checking each for tool call JSON
4. Evaluates tool calls against the guard
5. Forwards allowed output, blocks denied output

Usage:
    spidershield guard --policy balanced -- python my_agent.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import IO, Any

from ..guard.core import RuntimeGuard
from ..guard.decision import Decision
from .base import AdapterBase


class StandaloneGuard(AdapterBase):
    """Standalone subprocess adapter with security guard.

    Wraps any subprocess, scanning stdout for tool call patterns.
    """

    @property
    def framework_name(self) -> str:
        return "standalone"

    def run(
        self,
        server_cmd: list[str] | None = None,
        client_in: IO[str] | None = None,
        client_out: IO[str] | None = None,
        **kwargs: Any,
    ) -> int:
        """Start the guarded subprocess.

        Args:
            server_cmd: Command to run.
            client_in: Input stream (default: sys.stdin).
            client_out: Output stream (default: sys.stdout).

        Returns:
            Subprocess return code.
        """
        if not server_cmd:
            raise ValueError("server_cmd is required")

        client_in = client_in or sys.stdin
        client_out = client_out or sys.stdout

        proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,
        )

        try:
            # Thread: relay stdin to subprocess
            stdin_thread = threading.Thread(
                target=self._relay_stdin,
                args=(client_in, proc.stdin),
                daemon=True,
            )
            stdin_thread.start()

            # Main thread: scan and relay subprocess stdout
            self._scan_and_relay(proc.stdout, client_out)  # type: ignore[arg-type]

        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        return proc.returncode or 0

    def _relay_stdin(self, source: IO[str], dest: IO[str]) -> None:
        """Relay stdin to subprocess."""
        try:
            for line in source:
                dest.write(line)
                dest.flush()
        except (BrokenPipeError, OSError):
            pass

    def _scan_and_relay(self, source: IO[str], dest: IO[str]) -> None:
        """Read subprocess stdout, scan for tool calls, relay output."""
        for line in source:
            tool_call = self._parse_tool_call(line)

            if tool_call is not None:
                tool_name, arguments = tool_call
                result = self.evaluate_tool_call(tool_name, arguments)

                if result.decision == Decision.DENY:
                    # Replace line with denial message
                    denial = {
                        "error": "denied",
                        "tool": tool_name,
                        "reason": result.reason,
                        "suggestion": result.suggestion,
                    }
                    dest.write(json.dumps(denial) + "\n")
                    dest.flush()
                    self._log(f"DENY: {tool_name} — {result.reason}")
                    continue

                if result.decision == Decision.ESCALATE:
                    self._log(f"ESCALATE: {tool_name} — {result.reason}")
                    # For standalone, escalate = allow with warning
                    warning = {
                        "warning": "escalated",
                        "tool": tool_name,
                        "reason": result.reason,
                    }
                    dest.write(json.dumps(warning) + "\n")

                self._log(f"ALLOW: {tool_name}")

            # Forward the line (tool call or passthrough)
            dest.write(line)
            dest.flush()

    def _parse_tool_call(self, line: str) -> tuple[str, dict[str, Any]] | None:
        """Try to parse a line as a tool call JSON.

        Expected format:
            {"tool": "name", "arguments": {...}}
        """
        line = line.strip()
        if not line.startswith("{"):
            return None
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None

        if not isinstance(data, dict):
            return None

        tool_name = data.get("tool") or data.get("tool_name")
        if not tool_name or not isinstance(tool_name, str):
            return None

        arguments = data.get("arguments") or data.get("args") or {}
        if not isinstance(arguments, dict):
            arguments = {}

        return tool_name, arguments


def run_standalone_guard(
    server_cmd: list[str],
    policy: str = "balanced",
    verbose: bool = False,
    audit_dir: str | None = None,
    no_audit: bool = False,
    dry_run: bool = False,
) -> int:
    """Convenience function to run a standalone guard.

    Args:
        server_cmd: Command to run.
        policy: Policy preset or YAML path.
        verbose: Enable verbose logging.
        audit_dir: Custom audit log directory.
        no_audit: Disable audit logging.
        dry_run: Log but don't enforce denials.

    Returns:
        Subprocess return code.
    """
    from ..audit.logger import AuditLogger
    from ..guard.policy import PolicyEngine

    engine = PolicyEngine.from_name_or_path(policy)
    logger = None if no_audit else AuditLogger(audit_dir)
    guard = RuntimeGuard(policy_engine=engine, audit_logger=logger)
    adapter = StandaloneGuard(guard, verbose=verbose, dry_run=dry_run)
    return adapter.run(server_cmd=server_cmd)
