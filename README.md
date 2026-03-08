# TeeShield — Security Scanner for MCP tools

Scan, rate, and harden MCP servers for AI agent safety.

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Scan an MCP server
teeshield scan ./path/to/server.py

# Rewrite tool descriptions (requires ANTHROPIC_API_KEY)
teeshield rewrite ./path/to/server.py --dry-run

# Harden a server (detect + fix security issues)
teeshield harden ./path/to/server.py

# Evaluate tool selection accuracy before/after
teeshield eval ./original.py ./improved.py
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
