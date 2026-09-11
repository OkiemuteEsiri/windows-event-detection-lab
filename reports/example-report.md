# Example Windows Event Detection Report

> Synthetic demonstration only. No production or client telemetry is included.

## Executive summary

The synthetic dataset produced several investigation-worthy signals across authentication, privilege, audit integrity, persistence-related configuration, and PowerShell telemetry. The highest-priority item is a Security event log clear on `DC-01`, followed by a privileged group membership change and high-confidence execution/configuration signals on other lab systems.

## Priority observations

1. **Security audit log cleared — Critical**
   - Host: `DC-01`
   - ATT&CK context: T1070.001
   - Analyst action: validate administrative intent, preserve alternate telemetry, review adjacent identity and endpoint events.

2. **Privileged group membership changed — High**
   - Host: `DC-01`
   - ATT&CK context: T1098
   - Analyst action: confirm approved change, initiating account, target identity and post-change activity.

3. **Encoded PowerShell execution — High**
   - Host: `WS-205`
   - ATT&CK context: T1059.001
   - Analyst action: inspect full script-block context, parent process and adjacent network/authentication telemetry.

4. **Service and scheduled-task creation — Medium/High**
   - Host: `SRV-22`
   - ATT&CK context: T1543.003 / T1053.005
   - Analyst action: validate deployment provenance, service/task owner and approved change records.

## Decision guidance

No individual event should be treated as proof of compromise without contextual validation. Containment should be proportional to evidence, business criticality and confidence. After remediation, rerun the detection set and retain evidence showing that unauthorized configuration or activity is no longer present.