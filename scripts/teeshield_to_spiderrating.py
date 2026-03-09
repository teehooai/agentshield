"""Convert TeeShield scan output to SpiderRating format.

Usage:
    # Scan + convert in one step
    python scripts/teeshield_to_spiderrating.py owner/repo

    # Convert existing TeeShield JSON
    python scripts/teeshield_to_spiderrating.py --from-json scan_report.json

    # Output to SpiderRating data directory
    python scripts/teeshield_to_spiderrating.py owner/repo \
        --out-dir ../spidershield/web/public/data/servers/

Thin wrapper around teeshield.spiderrating -- all logic lives in the library.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Add project root to path so we can import teeshield
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from teeshield.spiderrating import convert, parse_owner_repo


def run_teeshield_scan(target: str) -> dict:
    """Run teeshield scan and return the JSON report."""
    from teeshield.scanner.runner import run_scan_report
    report = run_scan_report(target)
    return json.loads(report.model_dump_json())


def main():
    parser = argparse.ArgumentParser(
        description="Convert TeeShield scan to SpiderRating format"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="GitHub repo (owner/repo or URL) to scan and convert",
    )
    parser.add_argument(
        "--from-json",
        help="Path to existing TeeShield JSON report",
    )
    parser.add_argument(
        "--out-dir",
        help="Output directory for SpiderRating JSON (default: stdout)",
    )
    parser.add_argument(
        "--owner",
        help="Override owner (when using --from-json)",
    )
    parser.add_argument(
        "--repo",
        help="Override repo name (when using --from-json)",
    )

    args = parser.parse_args()

    if not args.target and not args.from_json:
        parser.error("Provide either a target repo or --from-json")

    # Get the TeeShield report
    if args.from_json:
        report = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        owner = args.owner or "unknown"
        repo = args.repo or "unknown"
        # Try to parse from target field
        target_str = report.get("target", "")
        if "/" in target_str:
            try:
                owner, repo = parse_owner_repo(target_str)
            except ValueError:
                pass
    else:
        owner, repo = parse_owner_repo(args.target)
        print(f"Scanning {owner}/{repo}...", file=sys.stderr)
        report = run_teeshield_scan(args.target)

    # Convert
    result = convert(report, owner, repo)

    # Output
    json_str = json.dumps(result, indent=2)

    if args.out_dir:
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{owner}__{repo}.json"
        out_path = out_dir / filename
        out_path.write_text(json_str, encoding="utf-8")
        print(f"Written: {out_path}", file=sys.stderr)
    else:
        print(json_str)


if __name__ == "__main__":
    main()
