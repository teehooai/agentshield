"""Agent config scanner -- security checks against agent configuration.

Covers gaps NOT checked by built-in agent security audits:
- Skill content, malicious patterns, credential exposure, description quality

Also duplicates the most critical config checks for standalone use.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

from .issue_codes import get_issue_code
from .models import Finding, ScanResult, Severity


def _get_nested(data: dict, *keys: str, default: Any = None) -> Any:
    """Safely get nested dict value."""
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def scan_config(
    agent_dir: Path | None = None,
    ignore_patterns: set[str] | None = None,
) -> ScanResult:
    """Scan agent config for security issues.

    Args:
        agent_dir: Path to agent config directory. Auto-detected if None.
        ignore_patterns: Set of check_id or pattern names to skip.

    Returns:
        ScanResult with findings.
    """
    if agent_dir is None:
        agent_dir = Path.home() / ".openclaw"

    ignored = ignore_patterns or set()
    config_path = agent_dir / "openclaw.json"
    result = ScanResult(config_path=str(config_path))

    if not agent_dir.exists():
        result.findings.append(Finding(
            check_id="install.not_found",
            title="Agent not installed",
            severity=Severity.LOW,
            description=f"Directory {agent_dir} not found",
        ))
        return result

    if not config_path.exists():
        result.findings.append(Finding(
            check_id="config.not_found",
            title="Config file not found",
            severity=Severity.HIGH,
            description=f"{config_path} does not exist",
        ))
        return result

    # Parse config (JSON5 format)
    config = _load_config(config_path)
    if config is None:
        result.findings.append(Finding(
            check_id="config.parse_error",
            title="Cannot parse config",
            severity=Severity.HIGH,
            description="Failed to parse config (JSON5)",
        ))
        return result

    # Run all 10 checks
    checkers = [
        _check_gateway_bind,
        _check_auth,
        _check_api_keys_in_config,
        _check_sandbox,
        _check_dm_policy,
        _check_tool_profile,
        _check_elevated_tools,
        _check_ssrf_policy,
        _check_file_permissions,
        _check_logging_redaction,
    ]

    for checker in checkers:
        finding = checker(config, agent_dir)
        if finding is not None and finding.check_id not in ignored:
            # Attach issue code to description
            code = get_issue_code(finding.check_id)
            if code:
                finding.description = f"[{code}] {finding.description}"
            result.findings.append(finding)

    return result


def _load_config(config_path: Path) -> dict | None:
    """Load config (JSON5 format)."""
    try:
        import json5  # type: ignore[import-untyped]
        return json5.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        # Fallback: try standard json (works if no JSON5 features used)
        import json
        try:
            return json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            return None


# --- 10 Security Checks ---


def _check_gateway_bind(config: dict, _dir: Path) -> Finding | None:
    """Check 1: Gateway binding address."""
    bind = _get_nested(config, "gateway", "bind", default="loopback")

    if bind in ("loopback", "tailnet"):
        return None

    severity = Severity.CRITICAL
    desc = f'Gateway bound to "{bind}"'

    if bind == "lan":
        severity = Severity.HIGH
        desc += " — accessible from local network"
    elif bind == "custom":
        severity = Severity.CRITICAL
        desc += " — custom binding, verify it's not 0.0.0.0"
    else:
        desc += " — may be accessible from the internet"

    return Finding(
        check_id="gateway.bind",
        title="Gateway not bound to loopback",
        severity=severity,
        description=desc,
        fix_hint='Set "gateway": { "bind": "loopback" }',
        auto_fixable=True,
        current_value=bind,
    )


def _check_auth(config: dict, _dir: Path) -> Finding | None:
    """Check 2: Authentication configuration."""
    auth = _get_nested(config, "gateway", "auth")

    if auth is None:
        return Finding(
            check_id="gateway.no_auth",
            title="Authentication not configured",
            severity=Severity.CRITICAL,
            description="No authentication — anyone can control your Agent",
            fix_hint='Add "gateway": { "auth": { "mode": "token", "token": "<random>" } }',
            auto_fixable=True,
        )

    mode = _get_nested(auth, "mode", default="")
    if mode == "token":
        token = _get_nested(auth, "token", default="")
        if len(token) < 16:
            return Finding(
                check_id="gateway.weak_token",
                title="Authentication token too short",
                severity=Severity.HIGH,
                description=f"Token length {len(token)} — should be at least 32 characters",
                fix_hint="Generate a longer random token",
                auto_fixable=True,
            )
    elif mode == "password":
        password = _get_nested(auth, "password", default="")
        if len(password) < 12:
            return Finding(
                check_id="gateway.weak_password",
                title="Authentication password too short",
                severity=Severity.HIGH,
                description=f"Password length {len(password)} — should be at least 12 characters",
                fix_hint="Use a stronger password",
            )

    return None


def _check_api_keys_in_config(config: dict, _dir: Path) -> Finding | None:
    """Check 3: API keys stored in plaintext config."""
    config_str = str(config)

    key_patterns = [
        (r"sk-ant-[a-zA-Z0-9_-]{20,}", "Anthropic API key"),
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
        (r"gsk_[a-zA-Z0-9]{20,}", "Groq API key"),
        (r"xai-[a-zA-Z0-9]{20,}", "xAI API key"),
    ]

    found_keys = []
    for pattern, name in key_patterns:
        if re.search(pattern, config_str):
            found_keys.append(name)

    if found_keys:
        return Finding(
            check_id="config.plaintext_keys",
            title="API keys in plaintext config",
            severity=Severity.HIGH,
            description=f"Found: {', '.join(found_keys)}. Keys should be in .env or env vars",
            fix_hint="Move keys to .env or use environment variables",
            auto_fixable=True,
            current_value=f"{len(found_keys)} key(s)",
        )

    return None


def _check_sandbox(config: dict, _dir: Path) -> Finding | None:
    """Check 4: Sandbox mode."""
    sandbox = _get_nested(config, "agents", "defaults", "sandbox")

    if sandbox is None:
        return Finding(
            check_id="sandbox.not_configured",
            title="Sandbox not configured",
            severity=Severity.HIGH,
            description="No sandbox — Agent can execute arbitrary shell commands",
            fix_hint='Set "agents": { "defaults": { "sandbox": { "mode": "all" } } }',
            auto_fixable=True,
        )

    mode = _get_nested(sandbox, "mode", default="off")
    if mode == "off":
        return Finding(
            check_id="sandbox.disabled",
            title="Sandbox disabled",
            severity=Severity.HIGH,
            description='Sandbox mode is "off" — Agent can execute arbitrary commands',
            fix_hint='Set "sandbox": { "mode": "all" }',
            auto_fixable=True,
            current_value="off",
        )

    workspace = _get_nested(sandbox, "workspaceAccess", default="none")
    if workspace == "rw":
        return Finding(
            check_id="sandbox.workspace_rw",
            title="Sandbox allows workspace write access",
            severity=Severity.MEDIUM,
            description="Agent can modify workspace files from sandbox",
            fix_hint='Set "workspaceAccess": "ro" or "none"',
            current_value="rw",
        )

    return None


def _check_dm_policy(config: dict, _dir: Path) -> Finding | None:
    """Check 5: DM policy."""
    channels = _get_nested(config, "channels", default={})

    for channel_name, channel_cfg in channels.items():
        if not isinstance(channel_cfg, dict):
            continue

        policy = _get_nested(channel_cfg, "dmPolicy", default="pairing")
        allow_from = _get_nested(channel_cfg, "allowFrom", default=[])

        if policy == "open":
            if isinstance(allow_from, list) and "*" in allow_from:
                return Finding(
                    check_id="channels.open_dm",
                    title=f'DM policy "open" on {channel_name}',
                    severity=Severity.HIGH,
                    description="Anyone can send messages to your Agent",
                    fix_hint=f'Set "{channel_name}": {{ "dmPolicy": "pairing" }}',
                    auto_fixable=True,
                    current_value=f'{channel_name}: open + "*"',
                )
            return Finding(
                check_id="channels.open_dm",
                title=f'DM policy "open" on {channel_name}',
                severity=Severity.MEDIUM,
                description="DM policy is open (check allowFrom list)",
                fix_hint='Consider "pairing" or "allowlist" policy',
                current_value=f"{channel_name}: open",
            )

    return None


def _check_tool_profile(config: dict, _dir: Path) -> Finding | None:
    """Check 6: Tool profile and deny list."""
    tools = _get_nested(config, "tools", default={})
    profile = _get_nested(tools, "profile", default="messaging")
    deny = _get_nested(tools, "deny", default=[])

    if profile == "full" and not deny:
        return Finding(
            check_id="tools.full_no_deny",
            title='Tool profile "full" with no deny list',
            severity=Severity.HIGH,
            description=(
                "Agent has access to ALL tools including"
                " automation, runtime, and filesystem"
            ),
            fix_hint='Add "deny": ["group:automation", "group:runtime"] or use "messaging" profile',
            auto_fixable=True,
            current_value="full, deny=[]",
        )

    if profile == "full":
        return Finding(
            check_id="tools.full_profile",
            title='Tool profile "full"',
            severity=Severity.MEDIUM,
            description=f"Full tool access with deny list: {deny}",
            fix_hint='Consider "messaging" profile for most use cases',
            current_value=f"full, deny={deny}",
        )

    return None


def _check_elevated_tools(config: dict, _dir: Path) -> Finding | None:
    """Check 7: Elevated tool mode."""
    elevated = _get_nested(config, "tools", "elevated", "enabled", default=False)

    if elevated:
        return Finding(
            check_id="tools.elevated",
            title="Elevated tools enabled",
            severity=Severity.HIGH,
            description="Agent can use elevated (sudo-level) tools",
            fix_hint='Set "tools": { "elevated": { "enabled": false } }',
            auto_fixable=True,
            current_value="enabled",
        )

    return None


def _check_ssrf_policy(config: dict, _dir: Path) -> Finding | None:
    """Check 8: SSRF protection for browser tool."""
    allow_private = _get_nested(
        config, "browser", "ssrfPolicy", "dangerouslyAllowPrivateNetwork", default=False
    )

    if allow_private:
        return Finding(
            check_id="browser.ssrf",
            title="SSRF protection disabled",
            severity=Severity.HIGH,
            description="Browser tool can access private network (localhost, internal IPs)",
            fix_hint='Set "browser": { "ssrfPolicy": { "dangerouslyAllowPrivateNetwork": false } }',
            auto_fixable=True,
            current_value="dangerouslyAllowPrivateNetwork=true",
        )

    return None


def _check_file_permissions(config: dict, agent_dir: Path) -> Finding | None:
    """Check 9: File permissions on config directory."""
    if os.name == "nt":
        return None

    try:
        dir_stat = agent_dir.stat()
        mode = dir_stat.st_mode

        if mode & stat.S_IROTH or mode & stat.S_IWOTH:
            return Finding(
                check_id="fs.permissions",
                title="Insecure directory permissions",
                severity=Severity.CRITICAL,
                description=f"Config directory is world-accessible (mode {oct(mode)[-3:]})",
                fix_hint="Run: chmod 700 <config-dir>",
                auto_fixable=True,
                current_value=oct(mode)[-3:],
            )
    except OSError:
        pass

    return None


def _check_logging_redaction(config: dict, _dir: Path) -> Finding | None:
    """Check 10: Log redaction."""
    redact = _get_nested(config, "logging", "redactSensitive", default=True)

    if redact is False or redact == "off":
        return Finding(
            check_id="logging.redact_off",
            title="Log redaction disabled",
            severity=Severity.MEDIUM,
            description="Sensitive values (API keys, tokens) may appear in logs",
            fix_hint='Set "logging": { "redactSensitive": true }',
            auto_fixable=True,
            current_value="off",
        )

    return None
