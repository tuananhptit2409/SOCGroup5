"""Phần dùng chung cho mọi rule phát hiện.

- Detection: kết quả của một rule (một "phát hiện"), chưa phải alert.
- Rule: lớp cha; mỗi rule con viết hàm detect(conn) trả về list[Detection].
- Các hàm tiện ích: gom nhóm dòng, chia đợt theo thời gian, kiểm tra ngưỡng,
  kiểm tra IP nội bộ.
"""
import ipaddress
import sqlite3
from dataclasses import dataclass
from typing import Any


@dataclass
class Detection:
    """Một lần rule bắt được hoạt động đáng ngờ của một thực thể (IP / máy)."""
    rule_id: str
    rule_name: str
    severity: int                          # 1 (thấp) .. 5 (nghiêm trọng)
    entity_key: str                        # ví dụ "203.0.113.10|web01"
    first_ts: float                        # thời điểm bắt đầu (epoch giây)
    last_ts: float                         # thời điểm kết thúc
    events: list[tuple[str, str]]          # danh sách (event_id, vai trò của event)
    evidence: dict[str, Any]               # bằng chứng, lưu dạng JSON
    rationale: str                         # câu giải thích vì sao rule báo
    mitre: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    hostname: str | None = None
    username: str | None = None


class Rule:
    """Lớp cha của mọi rule. Rule con đặt các thuộc tính và viết hàm detect()."""
    rule_id = ""
    name = ""
    description = ""
    severity = 3
    mitre = None
    threshold = None
    window_seconds = None

    def detect(self, conn: sqlite3.Connection) -> list[Detection]:
        """Đọc bảng events và trả về các Detection tìm được."""
        raise NotImplementedError

    def metadata(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "name": self.name, "description": self.description,
                "severity": self.severity, "mitre": self.mitre, "threshold": self.threshold,
                "window_seconds": self.window_seconds}


def group_rows(rows, columns: tuple[str, ...]) -> dict[tuple, list]:
    """Gom các dòng có cùng giá trị ở các cột `columns` vào một nhóm.

    Ví dụ group_rows(rows, ("src_ip", "hostname")) trả về
    {("1.2.3.4", "web01"): [dòng, dòng, ...], ...}. Thứ tự dòng trong mỗi nhóm
    được giữ nguyên (nên nếu rows đã sắp theo thời gian thì nhóm cũng vậy).
    """
    groups: dict[tuple, list] = {}
    for row in rows:
        key = tuple(row[column] for column in columns)
        if key not in groups:
            groups[key] = []
        groups[key].append(row)
    return groups


def sessionize(rows, gap: float, ts_key: str = "ts_epoch") -> list[list]:
    """Chia các dòng (đã sắp theo thời gian) thành từng đợt.

    Hai dòng liên tiếp cách nhau quá `gap` giây thì dòng sau mở một đợt mới.
    Ví dụ thời điểm [0, 10, 20, 100, 105] với gap 60 -> [[0, 10, 20], [100, 105]].
    """
    sessions: list[list] = []
    current: list = []
    previous_ts = None
    for row in rows:
        ts = row[ts_key]
        if previous_ts is not None and ts - previous_ts > gap:
            sessions.append(current)
            current = []
        current.append(row)
        previous_ts = ts
    if current:
        sessions.append(current)
    return sessions


def first_threshold_index(times: list[float], threshold: int, window: float) -> int | None:
    """Vị trí của event làm đủ `threshold` event trong vòng `window` giây (None nếu không có).

    Với mỗi vị trí j, xét `threshold` event kết thúc tại j: nếu event đầu và
    event cuối cách nhau không quá `window` giây thì đã đạt ngưỡng.
    """
    for j in range(threshold - 1, len(times)):
        first = times[j - threshold + 1]
        if times[j] - first <= window:
            return j
    return None


# Các dải địa chỉ được coi là "nội bộ" (mạng riêng, loopback, link-local).
INTERNAL_NETWORKS = [ipaddress.ip_network(net) for net in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "fe80::/10", "::1/128")]


def is_internal_ip(value: str | None) -> bool:
    """True nếu IP thuộc mạng nội bộ (RFC1918, loopback, link-local, IPv6 ULA)."""
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    for network in INTERNAL_NETWORKS:
        if network.version == address.version and address in network:
            return True
    return False
