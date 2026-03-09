"""Integration tests for CLI commands using example servers."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
INSECURE = str(ROOT / "examples" / "insecure-server")
SECURE = str(ROOT / "examples" / "secure-server")


def _run(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run teeshield CLI via subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "teeshield"] + args,
        capture_output=True,
        text=True,
        timeout=30,
        check=check,
    )


# --- scan command ---


class TestScan:
    def test_scan_insecure_table(self):
        r = _run(["scan", INSECURE])
        assert r.returncode == 0
        output = r.stdout + r.stderr
        assert "insecure" in output.lower() or "Rating" in output or "Scan" in output

    def test_scan_secure_table(self):
        r = _run(["scan", SECURE])
        assert r.returncode == 0

    def test_scan_json_file(self, tmp_path):
        """Test JSON output via file (avoids Rich console escape codes in stdout)."""
        out = str(tmp_path / "report.json")
        r = _run(["scan", INSECURE, "--format", "json", "-o", out])
        assert r.returncode == 0
        data = json.loads(Path(out).read_text())
        assert "overall_score" in data
        assert "security_issues" in data
        assert "tool_count" in data
        assert data["tool_count"] > 0

    def test_scan_sarif_file(self, tmp_path):
        """Test SARIF output via file."""
        out = str(tmp_path / "report.sarif")
        r = _run(["scan", INSECURE, "--format", "sarif", "-o", out], check=False)
        assert r.returncode == 0
        data = json.loads(Path(out).read_text())
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "TeeShield"

    def test_scan_nonexistent_path(self):
        r = _run(["scan", "/nonexistent/path"], check=False)
        assert r.returncode != 0

    def test_insecure_scores_lower(self, tmp_path):
        """Insecure example should score lower than secure example."""
        out1 = str(tmp_path / "insecure.json")
        out2 = str(tmp_path / "secure.json")
        _run(["scan", INSECURE, "--format", "json", "-o", out1])
        _run(["scan", SECURE, "--format", "json", "-o", out2])
        d1 = json.loads(Path(out1).read_text())
        d2 = json.loads(Path(out2).read_text())
        assert d1["description_score"] < d2["description_score"]


# --- rewrite command ---


class TestRewrite:
    def test_rewrite_dry_run(self):
        r = _run(["rewrite", INSECURE, "--dry-run"])
        assert r.returncode == 0
        output = r.stdout + r.stderr
        assert "Before" in output or "Original" in output or "Quality" in output

    def test_rewrite_output_json(self, tmp_path):
        out = str(tmp_path / "rewrites.json")
        r = _run(["rewrite", INSECURE, "--dry-run", "-o", out])
        assert r.returncode == 0
        data = json.loads(Path(out).read_text())
        assert isinstance(data, list)
        assert len(data) > 0
        assert "name" in data[0]
        assert "original" in data[0]
        assert "rewritten" in data[0]


# --- harden command ---


class TestHarden:
    def test_harden_insecure(self):
        r = _run(["harden", INSECURE])
        assert r.returncode == 0
        output = r.stdout + r.stderr
        assert (
            "suggestion" in output.lower()
            or "advisory" in output.lower()
            or "No issues" in output
        )

    def test_harden_secure(self):
        r = _run(["harden", SECURE])
        assert r.returncode == 0

    def test_harden_nonexistent(self):
        r = _run(["harden", "/nonexistent/path"], check=False)
        assert r.returncode != 0


# --- eval command ---


class TestEval:
    def test_eval_heuristic(self):
        """Eval should work without API key using heuristic fallback."""
        r = _run(["eval", INSECURE, SECURE], check=False)
        output = r.stdout + r.stderr
        assert r.returncode == 0 or "No test scenarios" in output
