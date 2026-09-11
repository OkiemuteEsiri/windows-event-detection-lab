from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

ALLOWED_CHANNELS = {"Security", "System", "Microsoft-Windows-PowerShell/Operational"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class WindowsEvent:
    event_id: str
    timestamp: datetime
    host: str
    channel: str
    event_code: int
    user: str
    source_ip: str = ""
    process_name: str = ""
    command_line: str = ""
    target_user: str = ""
    group_name: str = ""
    service_name: str = ""
    task_name: str = ""
    details: str = ""

    def __post_init__(self) -> None:
        if not self.event_id.strip() or not self.host.strip():
            raise ValueError("event_id and host are required")
        if self.channel not in ALLOWED_CHANNELS:
            raise ValueError(f"unsupported channel: {self.channel}")
        if self.event_code <= 0:
            raise ValueError("event_code must be positive")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone aware")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    host: str
    severity: str
    score: int
    confidence: int
    attack_technique: str
    event_ids: tuple[str, ...]
    rationale: str
    remediation: str

    def __post_init__(self) -> None:
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError("invalid severity")
        if not 0 <= self.score <= 100 or not 0 <= self.confidence <= 100:
            raise ValueError("score and confidence must be 0-100")
        if not self.event_ids:
            raise ValueError("at least one evidence event is required")
