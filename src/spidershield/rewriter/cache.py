"""Rewrite cache -- deterministic results for repeated runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

CACHE_DIR = Path.home() / ".spidershield" / "rewrite-cache"

# Bump this version when the rewrite prompt changes significantly.
# Invalidates all existing cache entries to force fresh rewrites.
PROMPT_VERSION = "v2.5"


def cache_key(tool_name: str, original_desc: str, model: str) -> str:
    """Generate a deterministic cache key from tool name, description, model, and prompt version."""
    payload = f"{PROMPT_VERSION}|{tool_name}|{original_desc}|{model}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_cached(tool_name: str, original_desc: str, model: str) -> str | None:
    """Return cached rewrite if available, else None."""
    key = cache_key(tool_name, original_desc, model)
    path = CACHE_DIR / f"{key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("rewritten")
    except (json.JSONDecodeError, OSError):
        return None


def set_cached(tool_name: str, original_desc: str, model: str, rewritten: str) -> None:
    """Store a rewrite result in the cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    key = cache_key(tool_name, original_desc, model)
    data = {
        "tool_name": tool_name,
        "model": model,
        "rewritten": rewritten,
    }
    (CACHE_DIR / f"{key}.json").write_text(
        json.dumps(data, indent=2), encoding="utf-8"
    )


def clear_cache() -> int:
    """Remove all cached rewrites. Returns number of entries cleared."""
    if not CACHE_DIR.exists():
        return 0
    count = 0
    for f in CACHE_DIR.glob("*.json"):
        f.unlink()
        count += 1
    return count
