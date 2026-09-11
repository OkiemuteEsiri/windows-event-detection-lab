# Windows Event Detection Lab

Defensive detection engineering and incident-response lab for analyzing Windows event telemetry with explainable, testable Python detections.

## Why this project exists

Windows event logs contain high-value signals for identity abuse, privilege changes, defense evasion, persistence-related configuration and suspicious command execution. The hard part is not simply matching event IDs; it is building detections that preserve evidence, separate confidence from severity, withstand malformed data, support analyst validation and provide a defensible remediation workflow.

This repository demonstrates that workflow using **synthetic, offline telemetry only**.

## What it demonstrates

- Validated immutable Windows event and finding models
- Fail-closed JSON ingestion and duplicate evidence-ID detection
- Deterministic finding IDs for tracking and revalidation
- Bounded 0–100 risk scoring
- Separate severity and confidence values
- ATT&CK contextual mappings without treating them as proof of compromise
- Multi-signal defensive detections
- Markdown executive/technical reporting
- Offline command-line analysis
- Unit-tested detection behavior
- Least-privilege GitHub Actions CI
- Remediation and post-remediation validation methodology

## Architecture

```text
Synthetic Windows JSON
        |
        v
   src/io.py
 schema + duplicate + UTC validation
        |
        v
 src/models.py
 canonical event/finding models
        |
        v
src/detections.py
 correlation + scoring + ATT&CK context
        |
        +-------------> tests/test_detections.py
        |
        v
src/reporting.py
 Markdown findings + metrics
        |
        v
   src/cli.py
 analyst-facing offline workflow
```

## Repository structure

```text
.github/workflows/ci.yml     Least-privilege CI
src/models.py                Canonical validated models
src/io.py                    Fail-closed JSON ingestion
src/detections.py            Detection and correlation logic
src/reporting.py             Metrics and Markdown reporting
src/cli.py                   Offline CLI
data/synthetic_events.json   Clearly synthetic Windows telemetry
tests/test_detections.py     10 unit tests
docs/methodology.md          Detection, triage and validation methodology
reports/example-report.md    Example executive investigation output
```

## Detection coverage

| Detection | Windows signal | ATT&CK context |
|---|---|---|
| Repeated failed logons | Event 4625 burst | T1110 Brute Force |
| Privileged group membership change | 4728 / 4732 / 4756 | T1098 Account Manipulation |
| Security audit log cleared | 1102 | T1070.001 Clear Windows Event Logs |
| Windows service installed | 7045 | T1543.003 Windows Service |
| Scheduled task created | 4698 | T1053.005 Scheduled Task |
| Encoded PowerShell execution | 4104 / 4688 | T1059.001 PowerShell |

These mappings provide investigative context. A matching event does **not** establish compromise by itself.

## Risk model

Findings contain two distinct analytical dimensions:

- **Risk score (0–100):** prioritization based on the behavior and available context.
- **Confidence (0–100):** strength of evidence that the observed telemetry genuinely represents the detection condition.

This separation avoids the common mistake of treating a high-impact possibility as high-confidence proof.

## Running the lab

Python 3.12 is used in CI and no external Python package is required.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_events.json --output reports/generated-report.md
```

The CLI reads the supplied JSON, validates the dataset, executes the detection set, prioritizes findings and writes a Markdown report.

## Example investigation workflow

1. Ingest normalized Windows telemetry.
2. Reject malformed records and duplicate evidence IDs.
3. Run defensive detections.
4. Prioritize by score while retaining confidence separately.
5. Review host, user, source, process and change-management context.
6. Preserve relevant evidence before containment.
7. Remediate the root cause.
8. Re-run detections against post-remediation telemetry.
9. Close only when validation evidence supports closure.

## Data-quality controls

The ingestion layer rejects:

- records missing required fields;
- duplicate `event_id` values;
- unsupported Windows channels;
- invalid/non-positive event codes;
- timestamps without timezone information;
- non-array JSON input.

This matters because detection engineering is only as trustworthy as its telemetry pipeline.

## Recruiter-facing engineering signals

This repository demonstrates practical capability across:

- Detection Engineering
- Windows Security Monitoring
- Incident Response
- Python security automation
- Evidence-preserving analysis
- Risk prioritization
- MITRE ATT&CK mapping
- Unit testing
- CI/CD security engineering
- Remediation validation
- Security reporting

## Safety and scope

All examples are synthetic and intentionally non-operational. The project does not contain malware, password harvesting, credential extraction, persistence deployment, EDR bypass logic, exploit automation or live endpoint modification. It is designed for defensive analysis, authorized labs and portfolio demonstration.

## Limitations

This is not a replacement for a SIEM, EDR, Windows Event Forwarding architecture or production detection content. Real deployments require environment-specific baselines, allowlists, identity and asset context, telemetry completeness monitoring, peer review, tuning and operational governance.

## Roadmap

- Add time-window correlation for failed-logon-to-success sequences
- Add process-parent context for 4688 telemetry
- Add rule metadata/versioning and detection lifecycle state
- Add synthetic baseline and false-positive test fixtures
- Add Sigma-compatible rule examples for selected detections
- Add coverage mapping across Windows telemetry sources
