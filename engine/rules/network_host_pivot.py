"""RULE SOC-004 — Network-to-Host Pivot (lateral movement, ghép Suricata + Sysmon).

Điều kiện của đề: một IP nội bộ bị Suricata cảnh báo mức cao, SAU ĐÓ chính IP
này khởi tạo kết nối tới các máy nội bộ khác (Sysmon Event ID 3 ghi nhận).

Cách rule làm việc:
  1. Lấy các Suricata alert có severity >= min_alert_severity (mặc định 4 = HIGH).
  2. Với mỗi alert, tìm "IP pivot" = đầu nội bộ của alert:
       - alert đi từ ngoài vào máy nội bộ  -> IP đích   (direction = "inbound")
       - alert đi từ máy nội bộ ra ngoài   -> IP nguồn  (direction = "outbound", ví dụ C2)
     Đầu còn lại là "peer" (máy của kẻ tấn công).
  3. Lấy các kết nối Sysmon mà IP pivot là bên KHỞI TẠO, đích là một máy nội
     bộ khác, bỏ qua cổng hạ tầng (DNS 53, NTP 123, NetBIOS 137/138).
  4. Kết nối nằm trong [thời điểm alert, alert + 300 giây] và không quay về
     peer thì tính là dấu hiệu lateral movement.
  5. Nhiều alert của cùng IP pivot gần nhau gộp thành một Detection.
     Severity 4; chạm >= 3 máy nội bộ thì 5 (CRITICAL).
"""
import sqlite3

from config import PivotConfig
from engine.rules.base import Detection, Rule, is_internal_ip, sessionize

MAX_TARGETS_IN_EVIDENCE = 100


class NetworkHostPivotRule(Rule):
    rule_id = "SOC-004"
    name = "Network-to-Host Pivot"
    description = ("High-severity IDS alert on an internal host, followed by internal connections "
                   "initiated by that host (possible lateral movement).")
    severity = 4
    mitre = "TA0008 Lateral Movement (T1021 Remote Services)"

    def __init__(self, config: PivotConfig | None = None) -> None:
        self.config = config or PivotConfig()
        self.window_seconds = self.config.window_seconds
        self.threshold = self.config.min_internal_targets

    def detect(self, conn: sqlite3.Connection) -> list[Detection]:
        # Bước 1-2: alert mức cao, nhóm theo IP pivot.
        alerts_by_pivot = self._high_alerts_by_pivot(conn)
        detections = []
        for pivot_ip in sorted(alerts_by_pivot):
            # Bước 3: kết nối nội bộ do IP pivot khởi tạo.
            connections = self._internal_connections(conn, pivot_ip)
            if not connections:
                continue
            # Bước 4: alert nào có kết nối nội bộ ngay sau nó?
            matched = []
            for item in alerts_by_pivot[pivot_ip]:
                follow = self._connections_after(item, connections)
                targets = {row["dst_ip"] for row in follow}
                if follow and len(targets) >= self.config.min_internal_targets:
                    item["connections"] = follow
                    matched.append(item)
            # Bước 5: gộp các alert gần nhau.
            for burst in sessionize(matched, self.config.window_seconds):
                detections.append(self._build(pivot_ip, burst))
        return detections

    def _high_alerts_by_pivot(self, conn) -> dict[str, list[dict]]:
        alerts = conn.execute(
            "SELECT event_id, src_ip, dst_ip, ts_epoch, message, severity FROM events "
            "WHERE action = 'ids_alert' AND severity >= ? AND src_ip IS NOT NULL "
            "AND dst_ip IS NOT NULL AND src_ip <> dst_ip ORDER BY ts_epoch, event_id",
            (self.config.min_alert_severity,)).fetchall()
        by_pivot: dict[str, list[dict]] = {}
        for alert in alerts:
            if is_internal_ip(alert["dst_ip"]):
                pivot_ip, peer, direction = alert["dst_ip"], alert["src_ip"], "inbound"
            elif is_internal_ip(alert["src_ip"]):
                pivot_ip, peer, direction = alert["src_ip"], alert["dst_ip"], "outbound"
            else:
                continue                        # cả hai đầu đều ở ngoài: không có máy nội bộ nào
            item = {"alert": alert, "peer": peer, "direction": direction, "ts_epoch": alert["ts_epoch"]}
            by_pivot.setdefault(pivot_ip, []).append(item)
        return by_pivot

    def _internal_connections(self, conn, pivot_ip: str) -> list:
        """Kết nối Sysmon do pivot_ip khởi tạo tới một máy nội bộ khác (đã sắp theo thời gian)."""
        rows = conn.execute(
            "SELECT event_id, src_ip, dst_ip, dst_port, hostname, process_name, ts_epoch FROM events "
            "WHERE action = 'network_connection' AND source_type = 'sysmon' AND src_ip = ? "
            "AND dst_ip IS NOT NULL AND dst_ip <> src_ip ORDER BY ts_epoch, event_id",
            (pivot_ip,)).fetchall()
        result = []
        for row in rows:
            if not is_internal_ip(row["dst_ip"]):
                continue                        # kết nối ra Internet không phải lateral movement
            if row["dst_port"] in self.config.ignore_dst_ports:
                continue                        # DNS, NTP, NetBIOS: lưu lượng hạ tầng bình thường
            result.append(row)
        return result

    def _connections_after(self, item: dict, connections: list) -> list:
        """Kết nối trong [alert, alert + window] và không quay lại máy của kẻ tấn công."""
        start = item["ts_epoch"]
        end = start + self.config.window_seconds
        follow = []
        for row in connections:
            if start <= row["ts_epoch"] <= end and row["dst_ip"] != item["peer"]:
                follow.append(row)
        return follow

    def _build(self, pivot_ip: str, burst: list[dict]) -> Detection:
        first = burst[0]                        # alert sớm nhất (burst đã sắp theo thời gian)
        first_alert = first["alert"]

        # Gom alert và kết nối của cả đợt, bỏ trùng theo event_id.
        alert_ids = []
        connections = {}
        for item in burst:
            if item["alert"]["event_id"] not in alert_ids:
                alert_ids.append(item["alert"]["event_id"])
            for row in item["connections"]:
                connections[row["event_id"]] = row
        conn_rows = sorted(connections.values(), key=lambda row: (row["ts_epoch"], row["event_id"]))

        targets = sorted({(row["dst_ip"], row["dst_port"]) for row in conn_rows},
                         key=lambda target: (target[0], target[1] or 0))
        target_hosts = sorted({row["dst_ip"] for row in conn_rows})
        hostname = _most_common([row["hostname"] for row in conn_rows if row["hostname"]])
        processes = sorted({row["process_name"] for row in conn_rows if row["process_name"]})

        severity = self.severity
        if len(target_hosts) >= self.config.escalate_targets:
            severity = 5
        delay = conn_rows[0]["ts_epoch"] - first_alert["ts_epoch"]
        all_times = [item["ts_epoch"] for item in burst] + [row["ts_epoch"] for row in conn_rows]

        shown = ", ".join(target_hosts[:5])
        if len(target_hosts) > 5:
            shown += " ..."
        host_text = f" ({hostname})" if hostname else ""
        rationale = (f"High-severity Suricata alert '{first_alert['message']}' "
                     f"({first_alert['src_ip']} -> {first_alert['dst_ip']}, {first['direction']}) "
                     f"was followed {delay:.0f}s later by {len(conn_rows)} internal connection(s) initiated "
                     f"by {pivot_ip}{host_text} to {len(target_hosts)} internal host(s): {shown}. "
                     f"The host may have been compromised and used to move laterally.")

        events = [(event_id, "suricata_alert") for event_id in alert_ids]
        events += [(row["event_id"], "sysmon_internal_connection") for row in conn_rows]
        evidence = {
            "pivot_ip": pivot_ip,
            "remote_ips": sorted({item["peer"] for item in burst})[:20],
            "alert_direction": first["direction"],
            "signatures": sorted({item["alert"]["message"] for item in burst})[:20],
            "max_alert_severity": max(item["alert"]["severity"] for item in burst),
            "suricata_alert_count": len(alert_ids),
            "internal_connection_count": len(conn_rows),
            "internal_target_count": len(target_hosts),
            "internal_targets": [f"{ip}:{port}" for ip, port in targets[:MAX_TARGETS_IN_EVIDENCE]],
            "first_delay_seconds": round(delay, 3),
            "processes": processes[:20],
            "window_seconds": self.config.window_seconds,
            "min_alert_severity": self.config.min_alert_severity,
        }
        return Detection(
            rule_id=self.rule_id, rule_name=self.name, severity=severity,
            entity_key=f"{pivot_ip}|{hostname or '-'}", first_ts=min(all_times), last_ts=max(all_times),
            events=events, rationale=rationale, mitre=self.mitre, src_ip=pivot_ip,
            dst_ip=target_hosts[0] if len(target_hosts) == 1 else None,
            hostname=hostname, evidence=evidence)


def _most_common(values: list[str]) -> str | None:
    """Giá trị xuất hiện nhiều nhất (giá trị gặp trước thắng khi bằng nhau); None nếu rỗng."""
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    best = None
    for value, count in counts.items():
        if best is None or count > counts[best]:
            best = value
    return best
