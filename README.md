# TeeShield -- Security Scanner for MCP Servers & AI Agents

![TeeShield Verified](https://img.shields.io/badge/MCP-TeeShield_Verified-green)
[![PyPI](https://img.shields.io/pypi/v/teeshield)](https://pypi.org/project/teeshield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**`npm audit` for MCP tools.** Static analysis linter that scans MCP server tool definitions and AI agent configurations for security vulnerabilities, malicious patterns, and description quality issues. 46 standardized checks across 4 categories.

## Why TeeShield?

MCP is the open protocol connecting AI agents to tools. But the ecosystem has two problems:

**Problem 1: Tool descriptions are terrible.** We scanned 79 MCP tools across 7 public servers -- average description quality is 3.1/10. Agents pick tools by reading descriptions, so vague text like *"access filesystem"* gives them no boundaries.

**Problem 2: Agent installations are insecure.** Skills can contain reverse shells, credential theft, and prompt injection. Configurations ship with no auth, disabled sandboxes, and open DM policies.

TeeShield is a dual-module static analysis linter:

| Module | Command | What it does |
|--------|---------|-------------|
| **MCP Server Scanner** | `teeshield scan` | Score tool descriptions, detect code vulnerabilities, rate overall quality (F/C/B/A/A+) |
| **Agent Security Checker** | `teeshield agent-check` | 18 config checks, 15 malicious pattern detections, toxic flow analysis, rug pull detection |

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

Full report: [MCP-SECURITY-REPORT.md](MCP-SECURITY-REPORT.md) | Raw data: [CURATION-REPORT.md](CURATION-REPORT.md)

## Try it on an example

The repo includes example MCP servers for instant demo:

```bash
git clone https://github.com/teehooai/teeshield
cd teeshield

teeshield scan examples/insecure-server   # Rating: C (4.8/10)
teeshield scan examples/secure-server     # Rating: B (7.2/10)
```

## What TeeShield checks

**Security** (weighted 40%)
- Path traversal
- Command injection / dangerous eval
- SQL injection (Python + TypeScript)
- SSRF (unrestricted network access)
- Hardcoded credentials
- Unsafe deserialization (pickle, yaml.load)
- Prototype pollution (TypeScript)

**Descriptions** (weighted 35%)
- Action verb starts ("List", "Create", "Execute")
- Scenario triggers ("Use when the user wants to...")
- Parameter documentation
- Parameter examples
- Error handling guidance
- Disambiguation between similar tools
- Length (too short = vague, too long = noisy)

**Architecture** (weighted 25%)
- Test coverage (gradual: count-based)
- Error handling (gradual: coverage-based)
- README quality (gradual: length-based)
- Type annotations
- Dependency management
- Environment configuration

**License** (pass/fail gate, not weighted)
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
- uses: teehooai/teeshield@v0.2.0
  with:
    target: '.'
    fail-below: '6.0'
```

## Agent security scanning (new in v0.2)

Scan AI agent installations for security misconfigurations and malicious skills.

```bash
teeshield agent-check ~/.openclaw
```

**What it checks:**
- 10 configuration security checks (auth, sandbox, SSRF, permissions, etc.)
- 20+ malicious skill patterns (reverse shells, credential theft, prompt injection)
- Toxic flow detection -- flags skills that can read sensitive data AND send it externally
- Typosquat detection for skill names
- Excessive permission requests

**Advanced options:**

```bash
# Verify skill integrity (rug pull detection)
teeshield agent-check --verify

# Only approved skills allowed
teeshield agent-check --allowlist approved.json

# Strict mode: fail on any finding
teeshield agent-check --policy strict

# Ignore specific rules
teeshield agent-check --ignore TS-W001 --ignore typosquat

# Auto-fix configuration issues
teeshield agent-check --fix

# SARIF output for GitHub Code Scanning
teeshield agent-check --format sarif > results.sarif
```

**Skill pinning (rug pull protection):**

```bash
teeshield agent-pin add ~/.openclaw/skills/my-skill/SKILL.md
teeshield agent-pin add-all
teeshield agent-pin verify    # detect tampered skills
teeshield agent-pin list
```

**46 standardized issue codes** across 4 categories:

| Code | Category | Example |
|------|----------|---------|
| TS-E001~E015 | Error (malicious) | Reverse shell, credential theft, prompt injection |
| TS-W001~W011 | Warning (suspicious) | Typosquat, toxic flow, unapproved skill |
| TS-C001~C018 | Config | No auth, sandbox disabled, SSRF enabled |
| TS-P001~P002 | Pin | Verified, tampered |

## Commands

| Command | Description |
|---------|-------------|
| `teeshield scan <path>` | Scan and rate an MCP server |
| `teeshield rewrite <path>` | Rewrite tool descriptions |
| `teeshield harden <path>` | Suggest security hardening (advisory only) |
| `teeshield eval <original> <improved>` | Compare tool selection accuracy |
| `teeshield agent-check [dir]` | Scan an AI agent for security issues |
| `teeshield agent-pin <cmd>` | Manage skill pins for rug pull detection |

## Threat model

TeeShield is a **static analysis linter**, not a runtime sandbox.

**What it catches:**
- Ambiguous tool definitions that lead to agent misuse
- Missing side-effect declarations (writes, deletes, network calls)
- Unsafe permission patterns (unbounded file access, unrestricted queries)
- Vague descriptions that give agents no operational boundaries
- Malicious agent skills (reverse shells, credential theft, prompt injection)
- Dangerous capability combinations (data exfiltration flows)
- Insecure agent configurations (no auth, disabled sandbox, open DM policy)
- Skill tampering (rug pull detection via content hashing)

**What it does NOT do:**
- Runtime isolation or sandboxing
- Network traffic monitoring
- Access control enforcement

TeeShield runs before deployment. For runtime protection, pair it with tools like MCP Proxy or container sandboxes.

## License

MIT
