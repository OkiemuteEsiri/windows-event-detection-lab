from __future__ import annotations

import argparse
from pathlib import Path

from .detections import run_all
from .io import load_events
from .reporting import render_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze synthetic/offline Windows events for defensive detection patterns.")
    parser.add_argument("input", help="Path to JSON event dataset")
    parser.add_argument("--output", default="reports/generated-report.md", help="Markdown report path")
    args = parser.parse_args()

    events = load_events(args.input)
    findings = run_all(events)
    report = render_markdown(findings)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"Analyzed {len(events)} events; produced {len(findings)} findings -> {output}")


if __name__ == "__main__":
    main()
