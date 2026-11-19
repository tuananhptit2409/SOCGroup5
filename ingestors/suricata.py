"""Suricata EVE JSON (one JSON object per line) parser."""
from __future__ import annotations

import json
from typing import Any

from ingestors.base import ParseError, load_json_line

SOURCE_TYPE = "suricata"
SUPPORTED_EVENT_TYPES = ("alert", "dns", "http", "flow")


def _section(obj: dict[str, Any], name: str) -> dict[str, Any]:
    """Return a nested section; missing is fine, a non-object is a type error."""
    value = obj.get(name)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ParseError("unexpected_field_type", f"{name} must be an object")
    return value


def parse_line(line: str) -> dict[str, Any]:
    """Parse one EVE line. Fields absent from the event are returned as None."""
    try:
        obj = load_json_line(line)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ParseError("malformed_json", str(exc)[:120]) from exc
    if not isinstance(obj, dict):
        raise ParseError("not_a_json_object")
    event_type = obj.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        raise ParseError("missing_required_field", "event_type")
    if event_type not in SUPPORTED_EVENT_TYPES:
        raise ParseError("unsupported_event_type", event_type[:40])
    alert = _section(obj, "alert")
    dns = _section(obj, "dns")
    http = _section(obj, "http")
    return {
        "raw": obj,
        "event_type": event_type,
        "timestamp_raw": obj.get("timestamp"),
        "sensor": obj.get("host"),
        "src_ip": obj.get("src_ip"),
        "dst_ip": obj.get("dest_ip"),
        "src_port": obj.get("src_port"),
        "dst_port": obj.get("dest_port"),
        "protocol": obj.get("proto"),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "alert_severity": alert.get("severity"),
        "category": alert.get("category"),
        "dns_rrname": dns.get("rrname"),
        "http_hostname": http.get("hostname"),
        "http_url": http.get("url"),
        "http_method": http.get("http_method"),
    }
