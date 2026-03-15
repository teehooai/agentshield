"""Auto-fixer for insecure agent configurations.

Only fixes issues that are safe to auto-remediate:
- Gateway binding -> loopback
- Auth -> generate random token
- Sandbox -> enable
- Logging -> enable redaction
- API keys -> move to .env
- File permissions -> chmod 700/600
"""

from __future__ import annotations

import os
import secrets
import shutil
from pathlib import Path

from .models import Finding


def fix_findings(
    findings: list[Finding],
    agent_dir: Path | None = None,
    dry_run: bool = False,
) -> list[str]:
    """Apply auto-fixes for fixable findings.

    Args:
        findings: List of findings from scanner.
        agent_dir: Path to agent config directory.
        dry_run: If True, only report what would be fixed.

    Returns:
        List of fix descriptions applied.
    """
    if agent_dir is None:
        agent_dir = Path.home() / ".openclaw"

    config_path = agent_dir / "openclaw.json"
    if not config_path.exists():
        return ["Cannot fix: config file not found"]

    fixable = [f for f in findings if f.auto_fixable]
    if not fixable:
        return ["No auto-fixable issues found"]

    # Load config
    try:
        import json5  # type: ignore[import-untyped]
        config = json5.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        import json
        try:
            config = json.loads(config_path.read_text(encoding="utf-8"))
        except Exception:
            return ["Cannot fix: failed to parse config"]

    fixes_applied: list[str] = []
    config_changed = False

    for finding in fixable:
        fix = _apply_fix(finding, config, agent_dir, dry_run)
        if fix:
            fixes_applied.append(fix)
            if finding.check_id != "fs.permissions":
                config_changed = True

    # Write config back
    if config_changed and not dry_run:
        _save_config(config, config_path)

    return fixes_applied


def _apply_fix(
    finding: Finding,
    config: dict,
    agent_dir: Path,
    dry_run: bool,
) -> str | None:
    """Apply a single fix. Returns description of fix, or None."""
    check = finding.check_id

    if check == "gateway.bind":
        return _fix_gateway_bind(config, dry_run)
    elif check == "gateway.no_auth":
        return _fix_add_auth(config, dry_run)
    elif check == "gateway.weak_token":
        return _fix_weak_token(config, dry_run)
    elif check == "config.plaintext_keys":
        return _fix_move_keys_to_env(config, agent_dir, dry_run)
    elif check in ("sandbox.not_configured", "sandbox.disabled"):
        return _fix_enable_sandbox(config, dry_run)
    elif check == "channels.open_dm":
        return _fix_dm_policy(config, dry_run)
    elif check == "tools.full_no_deny":
        return _fix_tool_deny_list(config, dry_run)
    elif check == "tools.elevated":
        return _fix_elevated(config, dry_run)
    elif check == "browser.ssrf":
        return _fix_ssrf(config, dry_run)
    elif check == "fs.permissions":
        return _fix_permissions(agent_dir, dry_run)
    elif check == "logging.redact_off":
        return _fix_logging(config, dry_run)

    return None


def _ensure_nested(config: dict, *keys: str) -> dict:
    """Ensure nested dict structure exists, return the innermost dict."""
    current = config
    for key in keys:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    return current


def _fix_gateway_bind(config: dict, dry_run: bool) -> str:
    if dry_run:
        return '[DRY RUN] Would set gateway.bind = "loopback"'
    gateway = _ensure_nested(config, "gateway")
    gateway["bind"] = "loopback"
    return 'Set gateway.bind = "loopback"'


def _fix_add_auth(config: dict, dry_run: bool) -> str:
    token = secrets.token_urlsafe(32)
    if dry_run:
        return "[DRY RUN] Would generate auth token and enable token auth"
    gateway = _ensure_nested(config, "gateway")
    gateway["auth"] = {"mode": "token", "token": token}
    return f"Generated auth token and enabled token auth (token: {token[:8]}...)"


def _fix_weak_token(config: dict, dry_run: bool) -> str:
    token = secrets.token_urlsafe(32)
    if dry_run:
        return "[DRY RUN] Would replace weak auth token"
    auth = _ensure_nested(config, "gateway", "auth")
    auth["token"] = token
    return f"Replaced weak token with strong token ({token[:8]}...)"


def _fix_move_keys_to_env(config: dict, agent_dir: Path, dry_run: bool) -> str | None:
    import re

    config_str = str(config)
    key_patterns = [
        (r"sk-ant-[a-zA-Z0-9_-]{20,}", "ANTHROPIC_API_KEY"),
        (r"sk-[a-zA-Z0-9]{20,}", "OPENAI_API_KEY"),
        (r"gsk_[a-zA-Z0-9]{20,}", "GROQ_API_KEY"),
    ]

    env_lines = []
    for pattern, env_name in key_patterns:
        match = re.search(pattern, config_str)
        if match:
            env_lines.append(f"{env_name}={match.group()}")

    if not env_lines:
        return None

    if dry_run:
        return f"[DRY RUN] Would move {len(env_lines)} key(s) to .env"

    env_path = agent_dir / ".env"
    existing = env_path.read_text(encoding="utf-8") if env_path.exists() else ""

    for line in env_lines:
        env_name = line.split("=")[0]
        if env_name not in existing:
            existing += f"\n{line}"

    env_path.write_text(existing.strip() + "\n", encoding="utf-8")

    # Remove keys from config (replace with env var reference)
    provider = config.get("provider", {})
    if isinstance(provider, dict) and "apiKey" in provider:
        del provider["apiKey"]

    return f"Moved {len(env_lines)} API key(s) to .env"


def _fix_enable_sandbox(config: dict, dry_run: bool) -> str:
    if dry_run:
        return '[DRY RUN] Would enable sandbox mode = "all"'
    agents = _ensure_nested(config, "agents", "defaults")
    agents["sandbox"] = {"mode": "all", "scope": "agent", "workspaceAccess": "ro"}
    return 'Enabled sandbox: mode="all", workspaceAccess="ro"'


def _fix_dm_policy(config: dict, dry_run: bool) -> str:
    if dry_run:
        return '[DRY RUN] Would set DM policy to "pairing"'
    channels = config.get("channels", {})
    for name, cfg in channels.items():
        if isinstance(cfg, dict) and cfg.get("dmPolicy") == "open":
            cfg["dmPolicy"] = "pairing"
    return 'Set DM policy to "pairing"'


def _fix_tool_deny_list(config: dict, dry_run: bool) -> str:
    if dry_run:
        return "[DRY RUN] Would add deny list for dangerous tool groups"
    tools = _ensure_nested(config, "tools")
    tools["deny"] = ["group:automation", "group:runtime"]
    return "Added deny list: [group:automation, group:runtime]"


def _fix_elevated(config: dict, dry_run: bool) -> str:
    if dry_run:
        return "[DRY RUN] Would disable elevated tools"
    elevated = _ensure_nested(config, "tools", "elevated")
    elevated["enabled"] = False
    return "Disabled elevated tools"


def _fix_ssrf(config: dict, dry_run: bool) -> str:
    if dry_run:
        return "[DRY RUN] Would disable dangerouslyAllowPrivateNetwork"
    ssrf = _ensure_nested(config, "browser", "ssrfPolicy")
    ssrf["dangerouslyAllowPrivateNetwork"] = False
    return "Disabled dangerouslyAllowPrivateNetwork"


def _fix_permissions(agent_dir: Path, dry_run: bool) -> str:
    if os.name == "nt":
        return None
    if dry_run:
        return "[DRY RUN] Would chmod 700 config dir, 600 config file"
    try:
        os.chmod(agent_dir, 0o700)
        config_path = agent_dir / "openclaw.json"
        if config_path.exists():
            os.chmod(config_path, 0o600)
        return "Set permissions: config_dir=700, config_file=600"
    except OSError as e:
        return f"Failed to fix permissions: {e}"


def _fix_logging(config: dict, dry_run: bool) -> str:
    if dry_run:
        return "[DRY RUN] Would enable log redaction"
    logging = _ensure_nested(config, "logging")
    logging["redactSensitive"] = True
    return "Enabled log redaction"


def _save_config(config: dict, config_path: Path) -> None:
    """Save config with backup."""
    import json

    backup_path = config_path.with_suffix(".json.bak")
    if config_path.exists():
        shutil.copy2(config_path, backup_path)

    config_path.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
