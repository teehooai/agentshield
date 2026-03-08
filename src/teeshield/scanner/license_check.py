"""License detection for MCP server repositories."""

from __future__ import annotations

from pathlib import Path

# Permissive licenses that allow forking, modifying, and selling
PERMISSIVE_LICENSES = {"mit", "apache-2.0", "apache 2.0", "bsd-2-clause", "bsd-3-clause", "isc", "unlicense"}
COPYLEFT_LICENSES = {"gpl", "agpl", "lgpl"}


def check_license(path: Path) -> tuple[str | None, bool]:
    """Check the license of a repository.

    Returns (license_name, is_fork_safe).
    """
    # Check common license file locations
    for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"]:
        license_file = path / name
        if license_file.exists():
            content = license_file.read_text(errors="ignore").lower()
            return _classify_license(content)

    # Check package.json
    pkg_json = path / "package.json"
    if pkg_json.exists():
        import json

        try:
            pkg = json.loads(pkg_json.read_text())
            license_str = pkg.get("license", "")
            # Skip indirect references like "SEE LICENSE IN LICENSE"
            if license_str and "see license" not in license_str.lower():
                return _classify_from_name(license_str)
        except (json.JSONDecodeError, KeyError):
            pass

    # Walk up to parent directories to find LICENSE (monorepo support)
    for ancestor in path.parents:
        for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING"]:
            license_file = ancestor / name
            if license_file.exists():
                content = license_file.read_text(errors="ignore").lower()
                return _classify_license(content)
        # Stop at git root
        if (ancestor / ".git").exists():
            break

    # Check pyproject.toml
    pyproject = path / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text()
        for line in content.splitlines():
            if "license" in line.lower() and "=" in line:
                value = line.split("=", 1)[1].strip().strip('"').strip("'")
                return _classify_from_name(value)

    return None, False


def _classify_license(content: str) -> tuple[str, bool]:
    """Classify license from file content."""
    if "mit license" in content or "permission is hereby granted, free of charge" in content:
        return "MIT", True
    if "apache license" in content and "version 2.0" in content:
        return "Apache-2.0", True
    if "bsd" in content and "redistribution" in content:
        return "BSD", True
    if "gnu general public license" in content or "gpl" in content:
        if "lesser" in content or "lgpl" in content:
            return "LGPL", False
        if "affero" in content or "agpl" in content:
            return "AGPL", False
        return "GPL", False
    if "isc license" in content:
        return "ISC", True
    if "unlicense" in content or "public domain" in content:
        return "Unlicense", True
    return "Unknown", False


def _classify_from_name(name: str) -> tuple[str, bool]:
    """Classify license from its name string."""
    name_lower = name.lower().strip()
    if name_lower in PERMISSIVE_LICENSES:
        return name, True
    if any(cl in name_lower for cl in COPYLEFT_LICENSES):
        return name, False
    return name, False
