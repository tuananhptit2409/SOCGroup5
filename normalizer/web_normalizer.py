"""Chuẩn hóa dòng access log (đã parse bởi ingestors/web_access.py) thành UnifiedEvent."""
from datetime import datetime, timedelta, timezone
from typing import Any

from normalizer.models import (NormalizationError, NormalizeContext, UnifiedEvent, format_timestamp,
                               normalize_ip, optional_text)

SOURCE_TYPE = "web_access"
_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def parse_access_time(text: str) -> datetime:
    """'16/Nov/2026:07:41:00 +0700' -> datetime UTC (2026-11-16 00:41:00+00:00).

    Tự tách từng phần thay vì dùng strptime("%b"), vì %b phụ thuộc ngôn ngữ của máy.
    """
    try:
        date_part, offset = text.split(" ")
        day, month_name, rest = date_part.split("/")
        year, hour, minute, second = rest.split(":")
        sign = 1 if offset[0] == "+" else -1
        if offset[0] not in "+-" or len(offset) != 5:
            raise ValueError("bad offset")
        tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5])))
        local = datetime(int(year), _MONTHS[month_name], int(day), int(hour), int(minute), int(second), tzinfo=tz)
    except (ValueError, KeyError, IndexError, OverflowError) as exc:   # Overflow: số quá lớn, ví dụ năm 99999999999
        raise NormalizationError("invalid_timestamp", text[:40]) from exc
    if not 1970 <= local.year <= 2100:
        raise NormalizationError("invalid_timestamp", f"year {local.year} out of range")
    return local.astimezone(timezone.utc)


def normalize(parsed: dict[str, Any], raw_line: str, event_id: str, ctx: NormalizeContext) -> UnifiedEvent:
    dt = parse_access_time(parsed["timestamp_raw"])
    status = int(parsed["status"])               # regex đã bảo đảm đúng 3 chữ số
    if not 100 <= status <= 599:
        raise NormalizationError("invalid_http_status", str(status))
    method = parsed.get("method") or "-"
    url = optional_text(parsed.get("url"), "url", 2048)
    return UnifiedEvent(
        event_id=event_id,
        timestamp_utc=format_timestamp(dt),
        ts_epoch=dt.timestamp(),
        source_type=SOURCE_TYPE,
        action="web_request",
        severity=2 if status >= 500 else 1,       # bản thân một request chỉ là thông tin; rule SOC-005 mới đánh giá
        message=f"{method} {url or '-'} -> {status}"[:500],
        hostname=ctx.web_server_name,
        username=optional_text(parsed.get("remote_user"), "remote_user", 255),
        src_ip=normalize_ip(parsed.get("client_ip"), "client_ip"),
        protocol="HTTP",
        url=url,
        http_status=status,
        user_agent=optional_text(parsed.get("user_agent"), "user_agent", 1000),
        raw_event={key: value for key, value in parsed.items() if value is not None},
    )
