"""Normalizer for parsed Linux authentication records."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from normalizer.models import (NormalizationError, NormalizeContext, UnifiedEvent, format_timestamp,
                               normalize_ip, normalize_port, optional_text, parse_timestamp)

SOURCE_TYPE = "linux_auth"
_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}
_SEVERITY = {"failed_login": 2, "invalid_user": 2, "successful_login": 1, "account_lockout": 3,
             "sudo_command": 1, "sudo_auth_failure": 2, "auth_failure": 2, "other": 1}
_MESSAGES = {
    "failed_login": "Failed SSH login",
    "invalid_user": "SSH login attempt for invalid user",
    "successful_login": "Successful SSH login",
    "account_lockout": "Account locked after repeated failures",
    "sudo_auth_failure": "sudo authentication failure",
    "auth_failure": "Authentication failure",
}


def syslog_timestamp(ts_raw: str, ctx: NormalizeContext) -> datetime:
    """Convert a syslog timestamp to UTC.

    Classic syslog has no year. With ``syslog_default_year`` configured that
    year is used. Otherwise the most recent year (current year, then earlier
    ones) in which the date exists and does not lie more than one day in the
    future is chosen; this handles December lines read in January and
    29 February lines read in a non-leap year.
    """
    if ts_raw[:1].isdigit():
        return parse_timestamp(ts_raw)
    parts = ts_raw.split()
    try:
        month = _MONTHS[parts[0]]
        day = int(parts[1])
        hour, minute, second = (int(p) for p in parts[2].split(":"))
    except (KeyError, IndexError, ValueError) as exc:
        raise NormalizationError("invalid_timestamp", ts_raw[:40]) from exc
    offset = timedelta(minutes=ctx.syslog_utc_offset_minutes)
    if ctx.syslog_default_year is not None:
        candidates = [ctx.syslog_default_year]
    else:
        candidates = list(range(ctx.now.year, ctx.now.year - 8, -1))
    for year in candidates:
        try:
            dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc) - offset
        except ValueError:
            continue            # e.g. 29 February in a non-leap year, or 31 November
        if ctx.syslog_default_year is not None or dt <= ctx.now + timedelta(days=1):
            return dt
    raise NormalizationError("invalid_timestamp", ts_raw[:40])


def normalize(parsed: dict[str, Any], raw_line: str, event_id: str, ctx: NormalizeContext) -> UnifiedEvent:
    """Build a UnifiedEvent from ``ingestors.linux_auth.parse_line`` output."""
    dt = syslog_timestamp(str(parsed.get("timestamp_raw") or ""), ctx)
    action = parsed.get("action") or "other"
    hostname = optional_text(parsed.get("hostname"), "hostname", 255)
    if hostname is None:
        raise NormalizationError("missing_required_field", "hostname")
    command = optional_text(parsed.get("sudo_command"), "sudo_command")
    if action == "sudo_command":
        target = optional_text(parsed.get("sudo_target_user"), "sudo_target_user", 100) or "?"
        message = f"sudo as {target}: {command or ''}"[:500]
    else:
        message = _MESSAGES.get(action) or optional_text(parsed.get("message"), "message", 500) or "syslog message"
    return UnifiedEvent(
        event_id=event_id,
        timestamp_utc=format_timestamp(dt),
        ts_epoch=dt.timestamp(),
        source_type=SOURCE_TYPE,
        action=action,
        severity=_SEVERITY.get(action, 1),
        message=message,
        hostname=hostname,
        username=optional_text(parsed.get("username"), "username", 255),
        src_ip=normalize_ip(parsed.get("src_ip"), "src_ip"),
        src_port=normalize_port(parsed.get("src_port"), "src_port"),
        process_name=optional_text(parsed.get("process"), "process", 255),
        command_line=command,
        raw_event={"raw": raw_line},
    )
