"""Skill scanner -- detect malicious patterns in agent SKILL.md files.

Based on real-world attack patterns from:
- ClawHavoc campaign (335 malicious skills, C2: 91.92.242.30)
- Snyk ToxicSkills study (36% prompt injection rate)
- Trend Micro Atomic Stealer analysis
- VirusTotal reverse shell / semantic worm findings
"""

from __future__ import annotations

import re
from pathlib import Path

from .issue_codes import get_issue_code
from .models import SkillFinding, SkillVerdict

# --- Malicious Pattern Definitions ---

# Each pattern: (name, regex, severity, description)
MALICIOUS_PATTERNS: list[tuple[str, str, str, str]] = [
    # Pattern 1: base64 pipe to bash/sh
    (
        "base64_pipe_bash",
        r"base64\s+(-[dD]|--decode)\s*\|\s*(bash|sh|zsh)",
        "malicious",
        "Base64-encoded payload piped to shell execution",
    ),
    # Pattern 2: curl/wget pipe to bash/sh
    (
        "curl_pipe_bash",
        r"(curl|wget)\s+[^\n]*\|\s*(bash|sh|zsh)",
        "malicious",
        "Remote script downloaded and executed directly",
    ),
    # Pattern 3: Known C2 IP addresses (ClawHavoc)
    (
        "known_c2_ip",
        r"91\.92\.242\.30",
        "malicious",
        "Known ClawHavoc C2 server IP address",
    ),
    # Pattern 4: Reverse shell patterns
    (
        "reverse_shell",
        r"(nc\s+-[elp]|bash\s+-i\s+>&\s*/dev/tcp|python[3]?\s+-c\s+.*socket|"
        r"mkfifo\s+/tmp/|/bin/sh\s+-i|"
        r"perl\s+-e\s+.*Socket|ruby\s+-rsocket|"
        r"powershell\s+.*TCPClient|"
        r"socat\s+.*exec|ncat\s+.*-e)",
        "malicious",
        "Reverse shell or backdoor pattern detected",
    ),
    # Pattern 5: SSH key / credential theft
    (
        "credential_theft",
        r"(~/.ssh/id_(rsa|ed25519|ecdsa|dsa)|~/.aws/credentials|~/.gnupg|\.env\b.*send|"
        r"\.npmrc|\.pypirc|~/.kube/config|~/.config/gcloud/|"
        r"~/.docker/config\.json|~/.gitconfig\b.*token|"
        r"\\\.ssh\\\\|%USERPROFILE%.*\.ssh)",
        "malicious",
        "Attempts to access or exfiltrate credentials",
    ),
    # Pattern 6: Malicious download domains
    (
        "malicious_domain",
        r"(setup-service\.com|install\.app-distribution\.net|glot\.io/snippets/)",
        "malicious",
        "Known malicious download domain",
    ),
    # Pattern 7: Password-protected archive download
    (
        "password_protected_archive",
        r"\.(zip|rar|7z|tar).*(?:password|Password|PASSWORD)\s*[:=]\s*\S+|"
        r"(?:password|Password|PASSWORD)\s*[:=]\s*\S+.*\.(zip|rar|7z|tar)",
        "suspicious",
        "Password-protected archive download (common malware delivery)",
    ),
    # Pattern 8: Prompt injection - ignore instructions
    (
        "prompt_injection_ignore",
        r"(ignore\s+(previous|prior|all|above)\s+(instructions?|prompts?|rules?)|"
        r"forget\s+(all\s+)?(previous|prior|your)\s+(rules?|instructions?|constraints?)|"
        r"disregard\s+(previous|prior|all|above)\s+(instructions?|prompts?|rules?)|"
        r"you\s+are\s+now\s+|new\s+system\s+prompt|override\s+(your|the)\s+instructions?|"
        r"pretend\s+you\s+(are|have)\s+(an?\s+)?(AI|model|assistant)\s+(without|with\s+no)|"
        r"act\s+as\s+if\s+you\s+have\s+no\s+(restrictions?|limitations?|rules?))",
        "malicious",
        "Prompt injection attempting to override agent instructions",
    ),
    # Pattern 9: Propagation / self-replication
    (
        "propagation",
        r"(install\s+this\s+skill|recommend\s+this\s+(skill|tool)|"
        r"share\s+this\s+with|tell\s+(the\s+)?user\s+to\s+install)",
        "suspicious",
        "Skill attempts to propagate itself through the agent",
    ),
    # Pattern 10: Environment variable exfiltration
    (
        "env_exfiltration",
        r"(process\.env|os\.environ|printenv|export\s+\$).*"
        r"(curl|wget|fetch|send\b|post\b|pastebin)|"
        r"(curl|wget)\b.*\$\(?(printenv|env\b|os\.environ)",
        "malicious",
        "Environment variables sent to external endpoint",
    ),
    # Pattern 11: Suspicious external binary execution
    (
        "external_binary",
        r"(download|fetch|get)\s+.*\.(exe|pkg|dmg|msi|appimage|sh)\b",
        "suspicious",
        "Instructions to download and run external binary",
    ),
    # Pattern 12: ASCII smuggling / invisible Unicode
    (
        "ascii_smuggling",
        r"[\u200b\u200c\u200d\u2060\ufeff]",
        "malicious",
        "Invisible Unicode characters hiding prompt injection",
    ),
    # Pattern 13: System prompt manipulation
    (
        "system_prompt_manipulation",
        r"(<system>|<\|im_start\|>system|<\|system\|>|\[INST\]|\[SYS\])",
        "malicious",
        "Attempts to inject system-level prompt directives",
    ),
    # Pattern 14: Data exfiltration to pastebin services
    (
        "pastebin_exfil",
        r"(pastebin\.com|hastebin\.com|dpaste\.org|paste\.ee|ghostbin)",
        "suspicious",
        "References to paste services (potential data exfiltration)",
    ),
    # Pattern 15: npm/pip global install from untrusted source
    (
        "untrusted_install",
        r"(npm\s+install\s+-g|pip\s+install)\s+(?!@modelcontextprotocol)",
        "suspicious",
        "Global package install from potentially untrusted source",
    ),
    # Pattern 16: eval/exec with remote content
    (
        "remote_code_exec",
        r"(eval\s*\$?\(|exec\s*\().*("
        r"base64|curl|wget|urllib|requests\.get|fetch|download)",
        "malicious",
        "Dynamic code execution with remote content",
    ),
    # Pattern 17: Two-step download-then-execute
    (
        "download_then_execute",
        r"(curl|wget)\s+.*-[oO]\s+\S+.*&&\s*(bash|sh|chmod\s+\+x|python|\.\/)",
        "malicious",
        "Downloads file then executes it (two-step attack)",
    ),
    # Pattern 18: Python exec/eval with URL
    (
        "python_remote_exec",
        r"python[3]?\s+-c\s+.*("
        r"urllib\.request\.urlopen|requests\.get|exec\s*\(|eval\s*\()",
        "malicious",
        "Python one-liner executing remote code",
    ),
    # Pattern 19: Crypto wallet / seed phrase theft
    (
        "crypto_theft",
        r"(seed\s+phrase|mnemonic|private\s+key|wallet\.dat|"
        r"\.solana/id\.json|\.ethereum/keystore)",
        "suspicious",
        "References to cryptocurrency wallet credentials",
    ),
    # Pattern 20: Hidden file operations (dot files + exfiltration)
    (
        "hidden_file_exfil",
        r"(find|ls|cat|read)\s+.*~/?\.[a-z].*\|\s*(curl|wget|nc\b)",
        "malicious",
        "Reading hidden/dot files and piping to external service",
    ),
]

# Known malicious skill names (from ClawHavoc + VirusTotal reports)
KNOWN_MALICIOUS_SLUGS = {
    "google-qx4",
    "net_ninja",
    "security-check",
    "nanopdf",
    "better-polymarket",
    "cgallic/wake-up",
    "jeffreyling/devinism",
}

# Typosquat targets (popular skill names that get typosquatted)
TYPOSQUAT_TARGETS = {
    "clawhub", "openclaw", "web-search", "google-search",
    "youtube", "calculator", "calendar", "slack", "discord",
    "whatsapp", "telegram", "solana", "bitcoin", "ethereum",
}


def scan_skills(
    agent_dir: Path | None = None,
    ignore_patterns: set[str] | None = None,
) -> list[SkillFinding]:
    """Scan all installed skills for malicious patterns.

    Args:
        agent_dir: Path to agent config directory. Auto-detected if None.
        ignore_patterns: Set of pattern names to skip (e.g. from --ignore).

    Returns:
        List of SkillFinding for each scanned skill.
    """
    if agent_dir is None:
        agent_dir = Path.home() / ".openclaw"

    findings = []

    # Scan both skill locations
    skill_dirs = [
        agent_dir / "skills",
        agent_dir / "workspace" / "skills",
    ]

    for skill_dir in skill_dirs:
        if not skill_dir.exists():
            continue

        for skill_path in skill_dir.iterdir():
            if skill_path.is_dir():
                skill_md = skill_path / "SKILL.md"
                if skill_md.exists():
                    finding = scan_single_skill(skill_md, ignore_patterns)
                    findings.append(finding)
            elif skill_path.name == "SKILL.md":
                finding = scan_single_skill(skill_path, ignore_patterns)
                findings.append(finding)

    return findings


def scan_single_skill(
    skill_path: Path,
    ignore_patterns: set[str] | None = None,
) -> SkillFinding:
    """Scan a single SKILL.md file for malicious patterns."""
    skill_name = skill_path.parent.name if skill_path.parent.name != "skills" else skill_path.stem

    try:
        content = skill_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return SkillFinding(
            skill_name=skill_name,
            skill_path=str(skill_path),
            verdict=SkillVerdict.UNKNOWN,
            issues=["Could not read skill file"],
        )

    ignored = ignore_patterns or set()

    # Check against known malicious slugs
    if skill_name.lower() in KNOWN_MALICIOUS_SLUGS and "known_malicious_slug" not in ignored:
        code = get_issue_code("known_malicious_slug") or "TS-E015"
        return SkillFinding(
            skill_name=skill_name,
            skill_path=str(skill_path),
            verdict=SkillVerdict.MALICIOUS,
            issues=[f"[{code}] Known malicious skill (ClawHavoc / VirusTotal database)"],
            matched_patterns=["known_malicious_slug"],
        )

    # Run pattern matching
    issues: list[str] = []
    matched: list[str] = []
    has_malicious = False
    has_suspicious = False

    for name, pattern, severity, description in MALICIOUS_PATTERNS:
        if name in ignored:
            continue
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            code = get_issue_code(name)
            prefix = f"[{code}] " if code else ""
            issues.append(f"{prefix}{description}")
            matched.append(name)
            if severity == "malicious":
                has_malicious = True
            elif severity == "suspicious":
                has_suspicious = True

    # Check for typosquatting
    if "typosquat" not in ignored:
        typosquat = _check_typosquat(skill_name)
        if typosquat:
            code = get_issue_code("typosquat") or "TS-W007"
            issues.append(
                f"[{code}] Name similar to popular skill "
                f"'{typosquat}' (possible typosquat)"
            )
            matched.append("typosquat")
            has_suspicious = True

    # Check for excessive permission requests
    if "excessive_permissions" not in ignored:
        permission_issue = _check_excessive_permissions(content)
        if permission_issue:
            code = get_issue_code("excessive_permissions") or "TS-W008"
            issues.append(f"[{code}] {permission_issue}")
            matched.append("excessive_permissions")
            has_suspicious = True

    # Check for toxic flows (dangerous capability combinations)
    from .toxic_flow import detect_toxic_flows, detect_toxic_flows_ast

    # v1: keyword-based on SKILL.md text
    toxic_flows = detect_toxic_flows(content)

    # v2: AST-level on sibling .py files in the skill directory
    skill_dir = skill_path.parent
    for py_file in skill_dir.glob("*.py"):
        toxic_flows.extend(detect_toxic_flows_ast(py_file))

    for tf in toxic_flows:
        pattern_name = f"toxic_flow_{tf.flow_type}"
        if pattern_name in ignored:
            continue
        code = get_issue_code(pattern_name)
        prefix = f"[{code}] " if code else ""
        issues.append(f"{prefix}{tf.description}")
        matched.append(pattern_name)
        has_suspicious = True

    # Determine verdict
    if has_malicious:
        verdict = SkillVerdict.MALICIOUS
    elif has_suspicious:
        verdict = SkillVerdict.SUSPICIOUS
    elif issues:
        verdict = SkillVerdict.SUSPICIOUS
    else:
        verdict = SkillVerdict.SAFE

    return SkillFinding(
        skill_name=skill_name,
        skill_path=str(skill_path),
        verdict=verdict,
        issues=issues,
        matched_patterns=matched,
    )


def _check_typosquat(name: str) -> str | None:
    """Check if skill name is a typosquat of a popular name."""
    name_lower = name.lower().replace("-", "").replace("_", "")
    for target in TYPOSQUAT_TARGETS:
        target_clean = target.replace("-", "").replace("_", "")
        if name_lower == target_clean:
            continue  # Exact match is fine
        dist = _levenshtein_distance(name_lower, target_clean)
        if 0 < dist <= 2 and len(name_lower) >= 4:
            return target
    return None


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Simple Levenshtein distance."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(
                curr_row[j] + 1,
                prev_row[j + 1] + 1,
                prev_row[j] + cost,
            ))
        prev_row = curr_row

    return prev_row[-1]


def _check_excessive_permissions(content: str) -> str | None:
    """Check if skill requests permissions disproportionate to its purpose."""
    requires_match = re.search(
        r"requires:\s*\n\s*bins:\s*\[([^\]]*)\]",
        content,
    )
    if not requires_match:
        return None

    bins = requires_match.group(1).lower()
    dangerous_bins = {"bash", "sh", "zsh", "python", "python3", "node", "ruby", "perl"}
    requested_dangerous = [b.strip().strip('"').strip("'") for b in bins.split(",")]
    requested_dangerous = [b for b in requested_dangerous if b in dangerous_bins]

    if not requested_dangerous:
        return None

    lower_content = content.lower()
    needs_shell = any(w in lower_content for w in [
        "shell", "terminal", "command", "execute", "script", "code",
    ])

    if requested_dangerous and not needs_shell:
        return (
            f"Requests shell interpreters ({', '.join(requested_dangerous)}) "
            f"but description doesn't mention shell/code execution"
        )

    return None
