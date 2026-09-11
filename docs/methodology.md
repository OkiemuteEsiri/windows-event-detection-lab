# Detection Methodology

## Objective

This project demonstrates defensive Windows event detection using clearly synthetic, offline telemetry. It focuses on analytical quality, evidence preservation, explainable prioritization, and remediation validation rather than exploitation.

## Event sources

The current lab uses representative Windows channels and event identifiers, including:

- Security: 4625 failed logon, 4728/4732/4756 privileged group membership, 1102 audit log clear, 4698 scheduled task creation, 4688 process creation.
- System: 7045 service installation.
- PowerShell Operational: 4104 script-block telemetry.

## Detection principles

1. **Fail closed on malformed data.** Missing required fields, duplicate evidence IDs, invalid channels, and non-timezone-aware timestamps are rejected.
2. **Separate severity from confidence.** A potentially serious behavior can still have moderate confidence until corroborating context is available.
3. **Preserve evidence references.** Every finding keeps the event IDs that generated it.
4. **Use deterministic finding identifiers.** Equivalent evidence produces stable IDs for revalidation and case tracking.
5. **Avoid treating ATT&CK as proof.** Technique mappings provide investigation context only.

## Current detections

| Detection | Event signal | ATT&CK | Primary validation |
|---|---|---|---|
| Repeated failed logons | 4625 burst by host/source | T1110 | Validate user/source, lockout and adjacent successful logons |
| Privileged group change | 4728/4732/4756 | T1098 | Confirm change ticket and initiating identity |
| Security log cleared | 1102 | T1070.001 | Confirm administrative intent and telemetry continuity |
| Windows service installed | 7045 | T1543.003 | Validate signer, path, deployment record and owner |
| Scheduled task created | 4698 | T1053.005 | Validate task action, owner and business purpose |
| Encoded PowerShell | 4104/4688 | T1059.001 | Review parent process, script content and adjacent activity |

## Triage workflow

1. Validate event integrity and timestamps.
2. Confirm host identity, ownership and expected administrative activity.
3. Review nearby authentication, process, endpoint and network telemetry.
4. Determine whether the activity is authorized, suspicious or confirmed malicious.
5. Preserve evidence before containment or remediation.
6. Remediate the root cause rather than only suppressing the alert.
7. Re-run the detection against post-remediation telemetry and document closure evidence.

## Limitations

This lab is not a full SIEM, EDR, Windows Event Forwarding deployment, or production detection pack. It does not include offensive payloads, credential theft, endpoint modification, live response actions, or production data. Real environments require environment-specific baselines, suppression logic, identity context, asset criticality, and peer-reviewed detection engineering.