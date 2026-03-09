"""Tool Pinning -- hash-based rug pull detection for agent skills.

Inspired by Invariant Labs / Snyk E004 rug pull detection.
Pins SKILL.md content hashes and detects unauthorized changes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import SkillFinding, SkillVerdict

# Default pin storage location
DEFAULT_PIN_DIR = Path.home() / ".teeshield"
PIN_FILENAME = "pins.json"


def _hash_content(content: str) -> str:
    """SHA-256 hash of skill content, normalized (strip trailing whitespace)."""
    normalized = content.rstrip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _load_pins(pin_file: Path) -> dict[str, Any]:
    """Load pins from JSON file."""
    if not pin_file.exists():
        return {}
    try:
        return json.loads(pin_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_pins(pins: dict[str, Any], pin_file: Path) -> None:
    """Save pins to JSON file."""
    pin_file.parent.mkdir(parents=True, exist_ok=True)
    pin_file.write_text(
        json.dumps(pins, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _resolve_pin_file(pin_dir: Path | None = None) -> Path:
    """Resolve the pin file path."""
    base = pin_dir if pin_dir is not None else DEFAULT_PIN_DIR
    return base / PIN_FILENAME


def _skill_key(skill_path: Path) -> str:
    """Generate a stable key for a skill based on its path."""
    resolved = skill_path.resolve()
    if resolved.name == "SKILL.md":
        return resolved.parent.name
    return resolved.stem


def pin_skill(
    skill_path: Path,
    pin_dir: Path | None = None,
) -> dict[str, str]:
    """Pin a skill by recording its content hash.

    Args:
        skill_path: Path to SKILL.md file or directory containing it.
        pin_dir: Directory for pins.json. Defaults to ~/.teeshield/.

    Returns:
        Dict with skill_name, hash, pinned_at, path.
    """
    if skill_path.is_dir():
        skill_path = skill_path / "SKILL.md"

    if not skill_path.exists():
        raise FileNotFoundError(f"Skill file not found: {skill_path}")

    content = skill_path.read_text(encoding="utf-8")
    content_hash = _hash_content(content)
    skill_name = _skill_key(skill_path)
    now = datetime.now(timezone.utc).isoformat()

    pin_file = _resolve_pin_file(pin_dir)
    pins = _load_pins(pin_file)

    pin_entry = {
        "hash": content_hash,
        "pinned_at": now,
        "path": str(skill_path.resolve()),
    }
    pins[skill_name] = pin_entry
    _save_pins(pins, pin_file)

    return {"skill_name": skill_name, **pin_entry}


def pin_all_skills(
    agent_dir: Path | None = None,
    pin_dir: Path | None = None,
) -> list[dict[str, str]]:
    """Pin all installed skills.

    Args:
        agent_dir: Path to agent config directory. Auto-detected if None.
        pin_dir: Directory for pins.json. Defaults to ~/.teeshield/.

    Returns:
        List of pin entries.
    """
    if agent_dir is None:
        agent_dir = Path.home() / ".openclaw"

    results = []
    skill_dirs = [
        agent_dir / "skills",
        agent_dir / "workspace" / "skills",
    ]

    for skill_dir in skill_dirs:
        if not skill_dir.exists():
            continue
        for item in skill_dir.iterdir():
            if item.is_dir():
                skill_md = item / "SKILL.md"
                if skill_md.exists():
                    results.append(pin_skill(skill_md, pin_dir))
            elif item.name == "SKILL.md":
                results.append(pin_skill(item, pin_dir))

    return results


def list_pins(pin_dir: Path | None = None) -> dict[str, Any]:
    """List all pinned skills.

    Returns:
        Dict of {skill_name: {hash, pinned_at, path}}.
    """
    pin_file = _resolve_pin_file(pin_dir)
    return _load_pins(pin_file)


def verify_skill(
    skill_path: Path,
    pin_dir: Path | None = None,
) -> SkillFinding:
    """Verify a single skill against its pin.

    Returns:
        SkillFinding with verdict SAFE (matches), TAMPERED (changed),
        or UNKNOWN (not pinned).
    """
    if skill_path.is_dir():
        skill_path = skill_path / "SKILL.md"

    skill_name = _skill_key(skill_path)
    pin_file = _resolve_pin_file(pin_dir)
    pins = _load_pins(pin_file)

    if skill_name not in pins:
        return SkillFinding(
            skill_name=skill_name,
            skill_path=str(skill_path),
            verdict=SkillVerdict.UNKNOWN,
            issues=["Skill is not pinned — run 'teeshield agent-pin add' to establish baseline"],
        )

    if not skill_path.exists():
        return SkillFinding(
            skill_name=skill_name,
            skill_path=str(skill_path),
            verdict=SkillVerdict.UNKNOWN,
            issues=["Pinned skill file not found (may have been removed)"],
        )

    content = skill_path.read_text(encoding="utf-8")
    current_hash = _hash_content(content)
    pinned_hash = pins[skill_name]["hash"]
    pinned_at = pins[skill_name].get("pinned_at", "unknown")

    if current_hash == pinned_hash:
        return SkillFinding(
            skill_name=skill_name,
            skill_path=str(skill_path),
            verdict=SkillVerdict.SAFE,
            issues=[],
            matched_patterns=["pin_verified"],
        )

    return SkillFinding(
        skill_name=skill_name,
        skill_path=str(skill_path),
        verdict=SkillVerdict.TAMPERED,
        issues=[
            f"SKILL.md content changed since pinned ({pinned_at})",
            f"Expected hash: {pinned_hash[:16]}...",
            f"Current hash:  {current_hash[:16]}...",
            "This may indicate a rug pull attack — review changes before continuing",
        ],
        matched_patterns=["pin_tampered"],
    )


def verify_all_skills(
    agent_dir: Path | None = None,
    pin_dir: Path | None = None,
) -> list[SkillFinding]:
    """Verify all pinned skills against their recorded hashes.

    Returns:
        List of SkillFinding for each pinned skill.
    """
    pin_file = _resolve_pin_file(pin_dir)
    pins = _load_pins(pin_file)

    if not pins:
        return []

    findings = []
    for skill_name, pin_data in pins.items():
        skill_path = Path(pin_data["path"])
        finding = verify_skill(skill_path, pin_dir)
        findings.append(finding)

    return findings


def unpin_skill(
    skill_name: str,
    pin_dir: Path | None = None,
) -> bool:
    """Remove a skill's pin.

    Returns:
        True if the skill was unpinned, False if not found.
    """
    pin_file = _resolve_pin_file(pin_dir)
    pins = _load_pins(pin_file)

    if skill_name not in pins:
        return False

    del pins[skill_name]
    _save_pins(pins, pin_file)
    return True
