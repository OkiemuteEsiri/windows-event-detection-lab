from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from typing import Iterable

from .models import Finding, WindowsEvent


def _id(rule: str, host: str, event_ids: Iterable[str]) -> str:
    raw = f"{rule}|{host}|{'|'.join(sorted(event_ids))}".encode()
    return sha256(raw).hexdigest()[:16]


def _severity(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def detect_failed_logon_burst(events: list[WindowsEvent]) -> list[Finding]:
    buckets: dict[tuple[str, str], list[WindowsEvent]] = defaultdict(list)
    for event in events:
        if event.event_code == 4625:
            buckets[(event.host, event.source_ip)].append(event)
    findings = []
    for (host, source_ip), group in buckets.items():
        if len(group) >= 5:
            score = min(90, 45 + len(group) * 5)
            ids = tuple(e.event_id for e in group)
            findings.append(Finding(_id("failed-logon-burst", host, ids), "Repeated failed logons", host, _severity(score), score, 80, "T1110", ids, f"{len(group)} failed logons from {source_ip or 'unknown source'}.", "Validate source, user impact, lockout context, and authentication telemetry; contain only after analyst validation."))
    return findings


def detect_privileged_group_change(events: list[WindowsEvent]) -> list[Finding]:
    findings = []
    for event in events:
        if event.event_code in {4728, 4732, 4756} and any(x in event.group_name.lower() for x in ("admin", "domain admins", "enterprise admins")):
            score = 82
            ids = (event.event_id,)
            findings.append(Finding(_id("priv-group-change", event.host, ids), "Privileged group membership changed", event.host, "high", score, 90, "T1098", ids, f"{event.target_user or 'An account'} was added to {event.group_name}.", "Confirm approved change, review initiating identity, inspect adjacent sign-ins, and remove unauthorized privilege."))
    return findings


def detect_security_log_cleared(events: list[WindowsEvent]) -> list[Finding]:
    findings = []
    for event in events:
        if event.event_code == 1102:
            ids = (event.event_id,)
            findings.append(Finding(_id("security-log-cleared", event.host, ids), "Security audit log cleared", event.host, "critical", 92, 95, "T1070.001", ids, "Windows Security audit log clear event observed.", "Preserve remaining telemetry, validate administrative intent, check EDR/SIEM continuity, and investigate surrounding activity."))
    return findings


def detect_service_install(events: list[WindowsEvent]) -> list[Finding]:
    findings = []
    for event in events:
        if event.event_code == 7045:
            suspicious = any(token in (event.details + " " + event.service_name).lower() for token in ("temp", "appdata", "powershell", "cmd.exe"))
            score = 78 if suspicious else 50
            ids = (event.event_id,)
            findings.append(Finding(_id("service-install", event.host, ids), "New Windows service installed", event.host, _severity(score), score, 85 if suspicious else 65, "T1543.003", ids, f"Service {event.service_name or 'unknown'} was installed.", "Validate service provenance, signer, owner, deployment record, and remove unauthorized services after evidence preservation."))
    return findings


def detect_scheduled_task(events: list[WindowsEvent]) -> list[Finding]:
    findings = []
    for event in events:
        if event.event_code == 4698:
            score = 72
            ids = (event.event_id,)
            findings.append(Finding(_id("scheduled-task", event.host, ids), "Scheduled task created", event.host, "high", score, 75, "T1053.005", ids, f"Scheduled task {event.task_name or 'unknown'} was created.", "Verify task owner, action, business purpose, and remove unauthorized tasks after collecting relevant evidence."))
    return findings


def detect_encoded_powershell(events: list[WindowsEvent]) -> list[Finding]:
    findings = []
    for event in events:
        if event.event_code in {4104, 4688} and "powershell" in (event.process_name + " " + event.command_line).lower() and any(x in event.command_line.lower() for x in ("-enc", "-encodedcommand", "frombase64string")):
            ids = (event.event_id,)
            findings.append(Finding(_id("encoded-powershell", event.host, ids), "Encoded PowerShell execution", event.host, "high", 80, 85, "T1059.001", ids, "Encoded or Base64-oriented PowerShell execution pattern observed.", "Review full script block/process context, parent process, signer, user, and adjacent network/authentication activity."))
    return findings


def run_all(events: list[WindowsEvent]) -> list[Finding]:
    findings = []
    for detector in (detect_failed_logon_burst, detect_privileged_group_change, detect_security_log_cleared, detect_service_install, detect_scheduled_task, detect_encoded_powershell):
        findings.extend(detector(events))
    return sorted(findings, key=lambda f: (-f.score, f.title, f.finding_id))
