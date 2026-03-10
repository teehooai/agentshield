"""Policy definitions for the SpiderShield Runtime Guard.

Policies define what agents can and cannot do. They are evaluated
in order — first match wins.

Example policy (YAML):
    policies:
      - name: block-env-reads
        match:
          tool: read_file
          args_pattern:
            path: ".*\\.(env|key|pem|credentials).*"
        action: deny
        reason: "Blocked access to sensitive file"
        suggestion: "Use files in /workspace/ instead"

      - name: external-email-review
        match:
          tool: send_email
          args_pattern:
            to: "^(?!.*@company\\.com).*$"
        action: escalate
        reason: "External email requires approval"

      - name: cost-limit
        match:
          any_tool: true
        condition:
          token_spent_gt: 50000
        action: deny
        reason: "Session token budget exceeded"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .context import CallContext
from .decision import Decision

_PRESET_NAMES = ("strict", "balanced", "permissive")


@dataclass
class PolicyRule:
    """A single guard policy rule."""

    name: str
    action: Decision
    reason: str
    suggestion: str = ""
    tool_match: str | None = None
    args_patterns: dict[str, str] = field(default_factory=dict)
    any_tool: bool = False
    max_token_spent: int | None = None
    max_chain_depth: int | None = None

    def matches(self, ctx: CallContext) -> bool:
        """Check if this policy rule matches the given call context."""
        if not self.any_tool and self.tool_match:
            if not re.search(self.tool_match, ctx.tool_name):
                return False
        elif not self.any_tool:
            return False

        for arg_name, pattern in self.args_patterns.items():
            arg_value = str(ctx.arguments.get(arg_name, ""))
            if not re.search(pattern, arg_value):
                return False

        if self.max_token_spent is not None and ctx.token_spent <= self.max_token_spent:
            return False

        if self.max_chain_depth is not None and len(ctx.call_chain) <= self.max_chain_depth:
            return False

        return True


class PolicyEngine:
    """Evaluates tool calls against an ordered list of policy rules."""

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self._rules = rules or []

    @property
    def rules(self) -> list[PolicyRule]:
        return list(self._rules)

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)

    def evaluate(self, ctx: CallContext) -> tuple[Decision, str, str | None, str]:
        """Evaluate context against all rules. First match wins.

        Returns (decision, reason, policy_name, suggestion).
        """
        for rule in self._rules:
            if rule.matches(ctx):
                return rule.action, rule.reason, rule.name, rule.suggestion

        return Decision.ALLOW, "no matching policy (default allow)", None, ""

    @classmethod
    def from_yaml(cls, data: dict[str, Any]) -> PolicyEngine:
        """Load policies from parsed YAML config."""
        rules = []
        for item in data.get("policies", []):
            match = item.get("match", {})
            condition = item.get("condition", {})
            rule = PolicyRule(
                name=item["name"],
                action=Decision(item["action"]),
                reason=item.get("reason", ""),
                suggestion=item.get("suggestion", ""),
                tool_match=match.get("tool"),
                args_patterns=match.get("args_pattern", {}),
                any_tool=match.get("any_tool", False),
                max_token_spent=condition.get("token_spent_gt"),
                max_chain_depth=condition.get("chain_depth_gt"),
            )
            rules.append(rule)
        return cls(rules)

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> PolicyEngine:
        """Load policies from a YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.from_yaml(data)

    @classmethod
    def from_preset(cls, name: str) -> PolicyEngine:
        """Load a built-in policy preset (strict / balanced / permissive)."""
        if name not in _PRESET_NAMES:
            raise ValueError(
                f"Unknown preset '{name}'. Available: {', '.join(_PRESET_NAMES)}"
            )
        preset_dir = Path(__file__).parent / "presets"
        preset_file = preset_dir / f"{name}.yaml"
        return cls.from_yaml_file(preset_file)

    @classmethod
    def from_name_or_path(cls, policy: str) -> PolicyEngine:
        """Load from preset name or file path (CLI convenience)."""
        if policy in _PRESET_NAMES:
            return cls.from_preset(policy)
        path = Path(policy)
        if path.exists():
            return cls.from_yaml_file(path)
        raise ValueError(
            f"'{policy}' is not a preset name ({', '.join(_PRESET_NAMES)}) "
            f"or an existing file path."
        )
