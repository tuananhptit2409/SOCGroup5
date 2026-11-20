"""Normalizer for parsed Suricata EVE records."""
from __future__ import annotations

from typing import Any

from normalizer.models import (NormalizeContext, UnifiedEvent, format_timestamp, normalize_ip,
                               normalize_port, optional_text, parse_timestamp)

SOURCE_TYPE = "suricata"
_ACTIONS = {"alert": "ids_alert", "dns": "dns_query", "http": "http_request", "flow": "network_flow"}
# Suricata priority 1 is the most severe; the toolkit scale is 1 (info) .. 5 (critical).
_ALERT_SEVERITY = {1: 4, 2: 3, 3: 2}


def _message(parsed: dict[str, Any]) -> str:
    kind = parsed["event_type"]
    if kind == "alert":
        return optional_text(parsed.get("signature"), "alert.signature", 500) or "Suricata alert"
    if kind == "dns":
        name = optional_text(parsed.get("dns_rrname"), "dns.rrname", 255)
        return f"DNS query {name}" if name else "DNS event"
    if kind == "http":
        method = optional_text(parsed.get("http_method"), "http.http_method", 16) or ""
        host = optional_text(parsed.get("http_hostname"), "http.hostname", 255) or ""
        url = optional_text(parsed.get("http_url"), "http.url", 300) or ""
        return f"HTTP {method} {host}{url}".strip() if (method or host or url) else "HTTP event"
    return "Network flow"


def normalize(parsed: dict[str, Any], raw_line: str, event_id: str, ctx: NormalizeContext) -> UnifiedEvent:
    """Build a UnifiedEvent from ``ingestors.suricata.parse_line`` output."""
    dt = parse_timestamp(parsed.get("timestamp_raw"))
    severity = 1
    if parsed["event_type"] == "alert":
        raw_sev = parsed.get("alert_severity")
        severity = _ALERT_SEVERITY.get(raw_sev, 2) if isinstance(raw_sev, int) and not isinstance(raw_sev, bool) else 2
    protocol = optional_text(parsed.get("protocol"), "proto", 16)
    return UnifiedEvent(
        event_id=event_id,
        timestamp_utc=format_timestamp(dt),
        ts_epoch=dt.timestamp(),
        source_type=SOURCE_TYPE,
        action=_ACTIONS[parsed["event_type"]],
        severity=severity,
        message=_message(parsed),
        hostname=optional_text(parsed.get("sensor"), "host", 255),
        src_ip=normalize_ip(parsed.get("src_ip"), "src_ip"),
        dst_ip=normalize_ip(parsed.get("dst_ip"), "dest_ip"),
        src_port=normalize_port(parsed.get("src_port"), "src_port"),
        dst_port=normalize_port(parsed.get("dst_port"), "dest_port"),
        protocol=protocol.upper() if protocol else None,
        raw_event=parsed["raw"],
    )
