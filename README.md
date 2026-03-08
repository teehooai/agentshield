# AgentShield

Scan, rate, and harden MCP servers for AI agent safety.

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Scan an MCP server
agentshield scan ./path/to/server.py

# Rewrite tool descriptions (requires ANTHROPIC_API_KEY)
agentshield rewrite ./path/to/server.py --dry-run

# Harden a server (detect + fix security issues)
agentshield harden ./path/to/server.py

# Evaluate tool selection accuracy before/after
agentshield eval ./original.py ./improved.py
```

## Rating Scale

| Rating | Score | Meaning |
|--------|-------|---------|
| A+     | 9.0+  | Production-ready, fully certified |
| A      | 8.0+  | Safe with minor suggestions |
| B      | 6.0+  | Usable, needs improvements |
| C      | 4.0+  | Significant issues found |
| F      | <4.0  | Unsafe, do not deploy |

## License

MIT
