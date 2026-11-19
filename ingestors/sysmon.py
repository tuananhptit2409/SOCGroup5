"""Windows Sysmon parser for JSON/JSONL exports (EVTX is NOT supported).

Accepted layouts per line:
  * flat:      {"EventID": 1, "UtcTime": "...", "Computer": "...", "Image": "..."}
  * nested:    {"EventID": 1, "Computer": "...", "EventData": {...}}
  * winlogbeat {"@timestamp": "...", "winlog": {"event_id": 1, "computer_name": "...", "event_data": {...}}}
  * XML-style  {"Event": {"System": {...}, "EventData": {...}}}
"""
from __future__ import annotations

import json
from typing import Any

from ingestors.base import ParseError, load_json_line

SOURCE_TYPE = "sysmon"
SUPPORTED_EVENT_IDS = (1, 3, 11)


def _event_data(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        data = value.get("Data", value)
        if isinstance(data, dict):
            return data
        value = data
    if isinstance(value, list):  # [{"@Name": "Image", "#text": "..."}]
        out: dict[str, Any] = {}
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("@Name"), str):
                out[item["@Name"]] = item.get("#text")
        return out
    raise ParseError("unexpected_field_type", "EventData must be an object")


def flatten(obj: dict[str, Any]) -> dict[str, Any]:
    """Merge the supported layouts into one flat field dictionary."""
    if isinstance(obj.get("winlog"), dict):
        winlog = obj["winlog"]
        flat = dict(_event_data(winlog.get("event_data")))
        flat.setdefault("EventID", winlog.get("event_id"))
        flat.setdefault("Computer", winlog.get("computer_name"))
        flat.setdefault("TimeCreated", obj.get("@timestamp"))
        return flat
    if isinstance(obj.get("Event"), dict):
        event = obj["Event"]
        system = event.get("System") if isinstance(event.get("System"), dict) else {}
        flat = dict(_event_data(event.get("EventData")))
        event_id = system.get("EventID")
        if isinstance(event_id, dict):
            event_id = event_id.get("#text")
        flat.setdefault("EventID", event_id)
        flat.setdefault("Computer", system.get("Computer"))
        created = system.get("TimeCreated")
        if isinstance(created, dict):
            created = created.get("@SystemTime")
        flat.setdefault("TimeCreated", created)
        return flat
    if "EventData" in obj:
        flat = dict(_event_data(obj.get("EventData")))
        for key, value in obj.items():
            if key != "EventData":
                flat.setdefault(key, value)
        return flat
    return obj


def parse_line(line: str) -> dict[str, Any]:
    """Parse one Sysmon JSON line into raw fields (values are not validated here)."""
    try:
        obj = load_json_line(line)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseError("malformed_json", str(exc)[:120]) from exc
    if not isinstance(obj, dict):
        raise ParseError("not_a_json_object")
    flat = flatten(obj)
    raw_id = flat.get("EventID")
    if raw_id is None:
        raise ParseError("missing_required_field", "EventID")
    try:
        if isinstance(raw_id, bool):
            raise ValueError
        event_id = int(raw_id)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ParseError("unexpected_field_type", "EventID must be an integer") from exc
    if event_id not in SUPPORTED_EVENT_IDS:
        raise ParseError("unsupported_event_type", f"EventID {event_id}")
    return {
        "raw": obj,
        "event_id": event_id,
        "timestamp_raw": flat.get("UtcTime") or flat.get("TimeCreated") or flat.get("@timestamp"),
        "computer": flat.get("Computer"),
        "user": flat.get("User"),
        "image": flat.get("Image"),
        "command_line": flat.get("CommandLine"),
        "parent_image": flat.get("ParentImage"),
        "src_ip": flat.get("SourceIp"),
        "src_port": flat.get("SourcePort"),
        "dst_ip": flat.get("DestinationIp"),
        "dst_port": flat.get("DestinationPort"),
        "protocol": flat.get("Protocol"),
        "initiated": flat.get("Initiated"),
        "target_filename": flat.get("TargetFilename"),
    }


def connection_initiated(raw_line: str) -> bool | None:
    """Return the Sysmon ``Initiated`` flag of an Event ID 3 line (None if absent)."""
    try:
        value = flatten(json.loads(raw_line)).get("Initiated")
    except (json.JSONDecodeError, AttributeError, ParseError):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return {"true": True, "false": False}.get(value.strip().lower())
    return None
