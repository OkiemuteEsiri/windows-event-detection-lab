from __future__ import annotations

from collections import Counter
from .models import Finding


def metrics(findings: list[Finding]) -> dict[str, object]:
    return {
        "total_findings": len(findings),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "hosts": len({f.host for f in findings}),
        "techniques": dict(Counter(f.attack_technique for f in findings)),
    }


def render_markdown(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = [
        "# Windows Event Detection Report",
        "",
        "## Executive Summary",
        f"- Total findings: **{m['total_findings']}**",
        f"- Critical findings: **{m['critical']}**",
        f"- High findings: **{m['high']}**",
        f"- Hosts represented: **{m['hosts']}**",
        "",
        "> ATT&CK mappings are analytical context and do not establish compromise by themselves.",
        "",
        "## Findings",
    ]
    if not findings:
        lines.append("No detections matched the supplied dataset.")
    for finding in findings:
        lines.extend([
            "",
            f"### {finding.title}",
            f"- Finding ID: `{finding.finding_id}`",
            f"- Host: `{finding.host}`",
            f"- Severity: **{finding.severity.upper()}**",
            f"- Risk score: **{finding.score}/100**",
            f"- Confidence: **{finding.confidence}/100**",
            f"- ATT&CK: `{finding.attack_technique}`",
            f"- Evidence events: {', '.join(f'`{x}`' for x in finding.event_ids)}",
            f"- Rationale: {finding.rationale}",
            f"- Remediation / validation: {finding.remediation}",
        ])
    return "\n".join(lines) + "\n"
