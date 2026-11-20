"""RULE SOC-002 — Internal Port Scan (quét cổng).

Điều kiện: một IP nội bộ kết nối tới >= 15 cổng KHÁC NHAU của cùng một máy
trong vòng 30 giây.

Cách rule làm việc:
  1. Lấy các kết nối mạng (Suricata flow + Sysmon Event ID 3), gom theo cặp
     (IP nguồn, IP đích), mỗi nhóm đã sắp theo thời gian.
  2. Chia mỗi cặp thành từng đợt (sessionize).
  3. Trong mỗi đợt, dùng "cửa sổ trượt" 30 giây để tìm số cổng khác nhau lớn
     nhất. Đạt ngưỡng thì báo.
"""
import sqlite3

from config import PortScanConfig
from engine.rules.base import Detection, Rule, group_rows, is_internal_ip, sessionize

MAX_PORTS_IN_EVIDENCE = 500


class PortScanRule(Rule):
    rule_id = "SOC-002"
    name = "Internal Port Scan"
    description = "One internal source probing many destination ports of one host."
    severity = 3
    mitre = "T1046 Network Service Discovery"

    def __init__(self, config: PortScanConfig | None = None) -> None:
        self.config = config or PortScanConfig()
        self.threshold = self.config.threshold
        self.window_seconds = self.config.window_seconds

    def detect(self, conn: sqlite3.Connection) -> list[Detection]:
        connections = conn.execute(
            "SELECT event_id, src_ip, dst_ip, dst_port, ts_epoch FROM events "
            "WHERE action IN ('network_flow', 'network_connection') AND src_ip IS NOT NULL "
            "AND dst_ip IS NOT NULL AND dst_port IS NOT NULL "
            "ORDER BY src_ip, dst_ip, ts_epoch, event_id").fetchall()

        detections = []
        for (src_ip, dst_ip), rows in group_rows(connections, ("src_ip", "dst_ip")).items():
            if self.config.internal_only and not is_internal_ip(src_ip):
                continue                          # chỉ xét máy trong mạng nội bộ
            if len(rows) < self.config.threshold:
                continue                          # ít kết nối hơn ngưỡng thì không thể là quét
            for burst in sessionize(rows, self.config.window_seconds):
                peak = self._max_distinct_ports(burst)
                if peak >= self.config.threshold:
                    detections.append(self._build(src_ip, dst_ip, burst, peak))
        return detections

    def _max_distinct_ports(self, burst: list) -> int:
        """Số cổng khác nhau lớn nhất trong một khoảng `window_seconds` bất kỳ.

        Cửa sổ trượt: `right` đi dần về phía sau; khi kết nối ở `left` đã cũ hơn
        `window_seconds` so với kết nối ở `right` thì bỏ nó ra khỏi cửa sổ.
        `port_count[p]` = số kết nối tới cổng p đang nằm trong cửa sổ.
        """
        if len(burst) < self.config.threshold:
            return 0
        port_count: dict[int, int] = {}
        left = 0
        best = 0
        for right in range(len(burst)):
            port = burst[right]["dst_port"]
            port_count[port] = port_count.get(port, 0) + 1
            # Thu hẹp cửa sổ từ bên trái cho đến khi đủ ngắn.
            while burst[right]["ts_epoch"] - burst[left]["ts_epoch"] > self.config.window_seconds:
                old_port = burst[left]["dst_port"]
                port_count[old_port] -= 1
                if port_count[old_port] == 0:
                    del port_count[old_port]
                left += 1
            best = max(best, len(port_count))     # len = số cổng khác nhau trong cửa sổ
        return best

    def _build(self, src_ip: str, dst_ip: str, burst: list, peak: int) -> Detection:
        ports = sorted({row["dst_port"] for row in burst})
        evidence = {
            "distinct_ports": len(ports),
            "max_ports_in_window": peak,
            "threshold": self.config.threshold,
            "window_seconds": self.config.window_seconds,
            "ports": ports[:MAX_PORTS_IN_EVIDENCE],
            "ports_truncated": len(ports) > MAX_PORTS_IN_EVIDENCE,
        }
        return Detection(
            rule_id=self.rule_id, rule_name=self.name, severity=self.severity,
            entity_key=f"{src_ip}|{dst_ip}", first_ts=burst[0]["ts_epoch"], last_ts=burst[-1]["ts_epoch"],
            events=[(row["event_id"], "scan_connection") for row in burst],
            rationale=(f"{src_ip} contacted {len(ports)} distinct ports on {dst_ip}; up to {peak} "
                       f"distinct ports within {self.config.window_seconds}s "
                       f"(threshold {self.config.threshold})."),
            mitre=self.mitre, src_ip=src_ip, dst_ip=dst_ip, evidence=evidence)
