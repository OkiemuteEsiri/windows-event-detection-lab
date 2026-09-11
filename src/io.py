from __future__ import annotations

import json
from pathlib import Path

from .models import WindowsEvent, parse_utc

REQUIRED = {"event_id", "timestamp", "host", "channel", "event_code", "user"}


def load_events(path: str | Path) -> list[WindowsEvent]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    seen: set[str] = set()
    events: list[WindowsEvent] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"record {index} must be an object")
        missing = REQUIRED - item.keys()
        if missing:
            raise ValueError(f"record {index} missing fields: {sorted(missing)}")
        if item["event_id"] in seen:
            raise ValueError(f"duplicate event_id: {item['event_id']}")
        seen.add(item["event_id"])
        events.append(WindowsEvent(
            event_id=str(item["event_id"]),
            timestamp=parse_utc(str(item["timestamp"])),
            host=str(item["host"]),
            channel=str(item["channel"]),
            event_code=int(item["event_code"]),
            user=str(item["user"]),
            source_ip=str(item.get("source_ip", "")),
            process_name=str(item.get("process_name", "")),
            command_line=str(item.get("command_line", "")),
            target_user=str(item.get("target_user", "")),
            group_name=str(item.get("group_name", "")),
            service_name=str(item.get("service_name", "")),
            task_name=str(item.get("task_name", "")),
            details=str(item.get("details", "")),
        ))
    return sorted(events, key=lambda e: (e.timestamp, e.event_id))
