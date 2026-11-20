"""Normalizer for parsed Sysmon records (Event ID 1, 3, 11)."""
from __future__ import annotations

from typing import Any

from normalizer.models import (NormalizationError, NormalizeContext, UnifiedEvent, format_timestamp,
                               normalize_ip, normalize_port, optional_text, parse_timestamp)

SOURCE_TYPE = "sysmon"
_ACTIONS = {1: "process_creation", 3: "network_connection", 11: "file_create"}


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    return path.replace("/", "\\").rsplit("\\", 1)[-1] or None


def normalize(parsed: dict[str, Any], raw_line: str, event_id: str, ctx: NormalizeContext) -> UnifiedEvent:
    """Build a UnifiedEvent from ``ingestors.sysmon.parse_line`` output."""
    dt = parse_timestamp(parsed.get("timestamp_raw"))
    sysmon_id = parsed["event_id"]
    image = optional_text(parsed.get("image"), "Image")
    if sysmon_id == 1 and image is None:
        raise NormalizationError("missing_required_field", "Image")
    command_line = optional_text(parsed.get("command_line"), "CommandLine")
    parent = optional_text(parsed.get("parent_image"), "ParentImage")
    name = _basename(image)
    if sysmon_id == 1:
        message = f"Process created: {name}"
    elif sysmon_id == 3:
        message = f"Network connection by {name or 'unknown process'}"
    else:
        target = optional_text(parsed.get("target_filename"), "TargetFilename", 500)
        message = f"File created: {target}" if target else "File created"
    protocol = optional_text(parsed.get("protocol"), "Protocol", 16)
    return UnifiedEvent(
        event_id=event_id,
        timestamp_utc=format_timestamp(dt),
        ts_epoch=dt.timestamp(),
        source_type=SOURCE_TYPE,
        action=_ACTIONS[sysmon_id],
        severity=1,
        message=message[:500],
        hostname=optional_text(parsed.get("computer"), "Computer", 255),
        username=optional_text(parsed.get("user"), "User", 255),
        src_ip=normalize_ip(parsed.get("src_ip"), "SourceIp"),
        dst_ip=normalize_ip(parsed.get("dst_ip"), "DestinationIp"),
        src_port=normalize_port(parsed.get("src_port"), "SourcePort"),
        dst_port=normalize_port(parsed.get("dst_port"), "DestinationPort"),
        protocol=protocol.upper() if protocol else None,
        process_name=name,
        process_path=image,
        command_line=command_line,
        parent_process=parent,
        raw_event=parsed["raw"],
    )
