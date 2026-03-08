# TeeShield -- Security Scanner for MCP tools

![TeeShield Verified](https://img.shields.io/badge/MCP-TeeShield_Verified-green)
[![PyPI](https://img.shields.io/pypi/v/teeshield)](https://pypi.org/project/teeshield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**`npm audit` for MCP tools.** Scan tool definitions and detect unsafe descriptions before AI agents misuse them.

## Why TeeShield?

We scanned **79 MCP tools across 7 public servers** and found:

- Average description quality: **3.1 / 10**
- 0% of tools have "Use when..." scenario triggers
- 0% have parameter examples
- Fewer than 5% have error handling guidance

AI agents pick which tool to call based on the description text. A vague description like *"access filesystem"* gives the agent no boundaries -- it doesn't know which directories are safe, whether it should read or write, or what happens on failure.

TeeShield scans tool descriptions, scores them, and rewrites them automatically.

## Install

```bash
pip install teeshield
```

Requires Python 3.11+.

## Quickstart

```bash
teeshield scan ./your-mcp-server
```

Example output:

```
            TeeShield Scan Report
   modelcontextprotocol/servers/filesystem
+---------------------------------------------+
| Metric                | Value     |   Score |
|-----------------------+-----------+---------|
| License               | MIT       |      OK |
| Tools                 | 14        |      OK |
| Security              | 0 issues  | 10.0/10 |
| Descriptions          |           |  3.2/10 |
| Architecture          |           | 10.0/10 |
| Tests                 | Yes       |      OK |
|                       |           |         |
| Overall               | Rating: B |  7.6/10 |
| Improvement Potential |           |  2.4/10 |
+---------------------------------------------+
```

## Rewrite tool descriptions

TeeShield can automatically rewrite tool descriptions to be action-oriented, with scenario triggers, parameter examples, and error guidance.

```bash
# Preview changes (no files modified)
teeshield rewrite ./your-mcp-server --dry-run

# Apply changes to source files
teeshield rewrite ./your-mcp-server
```

Before (score 2.9):
```
"Shows the working tree status"
```

After (score 9.6):
```
"Query the current state of the Git working directory and staging area.
 Use when the user wants to check which files are modified, staged, or
 untracked before committing."
```

The rewriter works offline using templates (zero cost). Set `ANTHROPIC_API_KEY` for higher-quality LLM-powered rewrites.

## Scan results across the MCP ecosystem

| Server | Tools | Security | Descriptions | Overall | Rating |
|--------|-------|----------|-------------|---------|--------|
| filesystem | 14 | 10.0 | 3.2 | 7.6 | B |
| git | 12 | 10.0 | 2.4 | 7.3 | B |
| memory | 9 | 10.0 | 2.3 | 7.3 | B |
| fetch | 1 | 9.0 | 3.5 | 7.3 | B |
| supabase | 30 | 9.0 | 2.3 | 6.4 | B |

Full report: [CURATION-REPORT.md](CURATION-REPORT.md)

## Try it on an example

The repo includes example MCP servers for instant demo:

```bash
git clone https://github.com/teehooai/teeshield
cd teeshield

teeshield scan examples/insecure-server   # Rating: C (4.8/10)
teeshield scan examples/secure-server     # Rating: B (7.2/10)
```

## What TeeShield checks

**Descriptions** (weighted 40%)
- Scenario triggers ("Use when the user wants to...")
- Parameter examples
- Error handling guidance
- Disambiguation between similar tools
- Length (too short = vague, too long = noisy)

**Security** (weighted 30%)
- Path traversal
- Command injection
- SQL injection
- SSRF (unrestricted network access)
- Credential exposure

**Architecture** (weighted 20%)
- Test coverage
- Error handling
- Type annotations
- Input validation patterns

**License** (weighted 10%)
- MIT, Apache-2.0, BSD = OK
- GPL, AGPL = warning
- Missing = fail

## Rating scale

| Rating | Score | Meaning |
|--------|-------|---------|
| A+ | 9.0+ | Production-ready |
| A | 8.0+ | Safe with minor suggestions |
| B | 6.0+ | Usable, needs improvements |
| C | 4.0+ | Significant issues |
| F | <4.0 | Unsafe, do not deploy |

## JSON output

```bash
teeshield scan ./server --format json
teeshield scan ./server --format json -o report.json
```

## GitHub Action

Add TeeShield to your CI pipeline:

```yaml
- uses: teehooai/teeshield@v0.1.0
  with:
    target: '.'
    fail-below: '6.0'
```

## Commands

| Command | Description |
|---------|-------------|
| `teeshield scan <path>` | Scan and rate an MCP server |
| `teeshield rewrite <path>` | Rewrite tool descriptions |
| `teeshield harden <path>` | Security hardening recommendations |
| `teeshield eval <original> <improved>` | Compare tool selection accuracy |

## Threat model

TeeShield is a **static analysis linter**, not a runtime sandbox.

**What it catches:**
- Ambiguous tool definitions that lead to agent misuse
- Missing side-effect declarations (writes, deletes, network calls)
- Unsafe permission patterns (unbounded file access, unrestricted queries)
- Vague descriptions that give agents no operational boundaries

**What it does NOT do:**
- Runtime isolation or sandboxing
- Prompt injection detection
- Network traffic monitoring
- Access control enforcement

TeeShield runs before deployment. For runtime protection, pair it with tools like MCP Proxy or container sandboxes.

## License

MIT
