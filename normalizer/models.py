"""Unified Event Schema and value-normalization helpers."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = 2   # 2: thêm url, http_status, user_agent (access log web)
MAX_TEXT = 8192  # stored text fields are truncated to this many characters


class NormalizationError(ValueError):
    """The record is invalid (bad required field or a present-but-invalid value)."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass(frozen=True)
class NormalizeContext:
    """Per-run inputs the normalizers need (kept explicit for testability)."""
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    syslog_default_year: int | None = None
    syslog_utc_offset_minutes: int = 0
    web_server_name: str | None = None      # tên máy chủ web gán cho dòng access.log (log không ghi tên máy)


@dataclass
class UnifiedEvent:
    event_id: str
    timestamp_utc: str
    ts_epoch: float
    source_type: str
    action: str
    severity: int
    message: str
    hostname: str | None = None
    username: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    process_name: str | None = None
    process_path: str | None = None
    command_line: str | None = None
    parent_process: str | None = None
    url: str | None = None              # web: đường dẫn + query string của request
    http_status: int | None = None      # web: mã trả về (200, 404, ...)
    user_agent: str | None = None       # web: chương trình gửi request (trình duyệt, sqlmap, ...)
    raw_event: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return the event in Unified Event Schema form."""
        return {
            "event_id": self.event_id, "schema_version": self.schema_version,
            "timestamp_utc": self.timestamp_utc, "source_type": self.source_type,
            "hostname": self.hostname, "username": self.username,
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": self.protocol, "action": self.action, "severity": self.severity,
            "message": self.message, "process_name": self.process_name,
            "process_path": self.process_path, "command_line": self.command_line,
            "parent_process": self.parent_process, "url": self.url, "http_status": self.http_status,
            "user_agent": self.user_agent, "raw_event": self.raw_event,
        }


def parse_timestamp(value: Any) -> datetime:
    """Parse ISO-8601 / 'YYYY-MM-DD HH:MM:SS' / epoch into an aware UTC datetime.

    Timestamps without an offset are taken as UTC (Sysmon ``UtcTime``).
    """
    if value is None or value == "":
        raise NormalizationError("missing_required_field", "timestamp")
    if isinstance(value, bool):
        raise NormalizationError("invalid_timestamp", repr(value))
    try:
        if isinstance(value, (int, float)):
            seconds = float(value) / 1000.0 if abs(value) > 1e11 else float(value)
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        elif isinstance(value, str):
            text = value.strip()
            if text.endswith(("Z", "z")):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
        else:
            raise ValueError("unsupported type")
    except (ValueError, OverflowError, OSError) as exc:
        raise NormalizationError("invalid_timestamp", str(value)[:60]) from exc
    if not 1970 <= dt.year <= 2100:
        raise NormalizationError("invalid_timestamp", f"year {dt.year} out of range")
    return dt


def format_timestamp(dt: datetime) -> str:
    """Format an aware datetime as UTC ISO-8601 with a trailing Z."""
    dt = dt.astimezone(timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{dt.microsecond:06d}Z" if dt.microsecond else f"{base}Z"


def epoch_to_iso(epoch: float) -> str:
    return format_timestamp(datetime.fromtimestamp(epoch, tz=timezone.utc))


def normalize_ip(value: Any, field_name: str = "ip") -> str | None:
    """Return a canonical IP string, None when absent, or raise when invalid."""
    if value is None or value == "" or value == "-":
        return None
    if not isinstance(value, str):
        raise NormalizationError("invalid_ip", f"{field_name}={value!r}"[:80])
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise NormalizationError("invalid_ip", f"{field_name}={value[:45]}") from exc
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped          # ::ffff:10.0.0.5 -> 10.0.0.5, so sources correlate
    return str(address)


def normalize_port(value: Any, field_name: str = "port") -> int | None:
    """Return a port 0-65535, None when absent, or raise when invalid."""
    if value is None or value == "":
        return None
    if isinstance(value, bool) or isinstance(value, float):
        raise NormalizationError("invalid_port", f"{field_name}={value!r}")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise NormalizationError("invalid_port", f"{field_name}={str(value)[:20]}") from exc
    if not 0 <= port <= 65535:
        raise NormalizationError("invalid_port", f"{field_name}={port}")
    return port


def optional_text(value: Any, field_name: str, max_len: int = MAX_TEXT) -> str | None:
    """Return a trimmed string, None when absent; non-scalar values are invalid."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        raise NormalizationError("unexpected_field_type", field_name)
    text = str(value).strip()
    return text[:max_len] if text else None
