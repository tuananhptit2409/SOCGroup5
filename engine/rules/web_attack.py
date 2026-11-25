"""RULE SOC-005 — Web Attack (tấn công website, đọc từ access log nginx / Apache).

Rule bổ sung ngoài 4 rule của đề, dành cho website mở ra Internet.

Cách rule làm việc:
  1. Lấy mọi request web ('web_request'), gom theo IP client, chia thành từng
     đợt (request cách nhau quá group_gap_seconds = 300 giây thì sang đợt mới).
  2. Xét từng request: giải mã URL (%27 -> ') rồi tìm dấu hiệu
       - tấn công: SQL injection, XSS, path traversal, command injection
       - dò thám: file nhạy cảm (/.env, /.git/, phpmyadmin ...), công cụ quét
         tự khai trong User-Agent (sqlmap, nikto, nmap ...)
  3. Một đợt được báo khi có ít nhất một trong các điều kiện:
       - có request tấn công                               -> MEDIUM (3)
           ... và server trả 2xx cho request đó (có thể đã thành công)   -> HIGH (4)
       - >= error_threshold (20) response 4xx trong error_window_seconds (60 giây)
         (dò thư mục / quét website)                        -> MEDIUM (3)
       - dùng công cụ quét, hoặc >= min_probe_requests (3) lần dò file nhạy cảm -> LOW (2)

Giới hạn: website dùng HTTPS thì Suricata không đọc được request, nhưng access
log vẫn có, nên rule này vẫn hoạt động. Request POST không có nội dung (body)
trong access log, nên tấn công nằm trong body không được thấy.
"""
import re
import sqlite3
from urllib.parse import unquote_plus

from config import WebAttackConfig
from engine.rules.base import Detection, Rule, first_threshold_index, group_rows, sessionize

MAX_SAMPLES_IN_EVIDENCE = 20

# (tên dấu hiệu, regex) — so khớp trên URL đã giải mã và viết thường.
# Mỗi regex được viết sao cho không có hai cách khớp cùng một đoạn chữ (ví dụ chú
# thích SQL /*...*/ dùng [^*] chứ không dùng .), nên không bị ReDoS (xem benchmarks/fuzz_test.py).
ATTACK_PATTERNS = [
    ("sql_injection", re.compile(
        r"union(\s|/\*[^*]{0,20}\*/)+(all\s+)?select|'\s*or\s*'?\d{1,5}'?\s*=\s*'?\d|\bor\s+1\s*=\s*1\b"
        r"|sleep\(\s*\d|benchmark\(|information_schema|waitfor\s+delay|;\s*drop\s+table|'\s*(--|#)")),
    ("xss", re.compile(r"<\s*script|javascript:|on(error|load|mouseover)\s*=|<\s*svg|document\.cookie|alert\(")),
    ("path_traversal", re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini")),
    ("command_injection", re.compile(
        r"(;|\||&&)\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|ping)(\s|$)|\$\(|\$\{jndi:")),
]
PROBE_PATTERN = re.compile(
    r"/\.env\b|/\.git/|/\.svn/|/\.htaccess|/wp-config\.php|/phpmyadmin|/server-status|/\.aws/"
    r"|/backup\.(zip|sql|tar|gz)|/config\.php\.bak")
SCANNER_AGENT = re.compile(
    r"sqlmap|nikto|nmap|masscan|wpscan|dirbuster|gobuster|feroxbuster|ffuf|nuclei|acunetix|nessus|zgrab|hydra")


def decode_url(url: str | None) -> str:
    """Giải mã URL hai lần (kẻ tấn công hay mã hóa hai lớp: %2527 -> %27 -> ') rồi viết thường."""
    text = url or ""
    for _ in range(2):
        text = unquote_plus(text)
    return text.lower()


def classify_request(url: str | None, user_agent: str | None) -> tuple[list[str], bool, bool]:
    """Trả về (các loại tấn công, có dò file nhạy cảm không, có phải công cụ quét không)."""
    decoded = decode_url(url)[:4096]
    attacks = []
    for name, pattern in ATTACK_PATTERNS:
        if pattern.search(decoded):
            attacks.append(name)
    agent = (user_agent or "")[:1000].lower()
    if "${jndi:" in agent and "command_injection" not in attacks:
        attacks.append("command_injection")        # Log4Shell thường được gửi trong User-Agent
    is_probe = bool(PROBE_PATTERN.search(decoded))
    is_scanner = bool(SCANNER_AGENT.search(agent))
    return attacks, is_probe, is_scanner


class WebAttackRule(Rule):
    rule_id = "SOC-005"
    name = "Web Attack"
    description = "Attack payloads, sensitive-file probing, scanners or many 4xx errors from one client IP."
    severity = 3
    mitre = "T1190 Exploit Public-Facing Application / T1595 Active Scanning"

    def __init__(self, config: WebAttackConfig | None = None) -> None:
        self.config = config or WebAttackConfig()
        self.threshold = self.config.error_threshold
        self.window_seconds = self.config.error_window_seconds

    def detect(self, conn: sqlite3.Connection) -> list[Detection]:
        requests = conn.execute(
            "SELECT event_id, src_ip, hostname, url, http_status, user_agent, message, ts_epoch, timestamp_utc "
            "FROM events WHERE action = 'web_request' AND src_ip IS NOT NULL "
            "ORDER BY src_ip, hostname, ts_epoch, event_id").fetchall()
        detections = []
        for (src_ip, hostname), rows in group_rows(requests, ("src_ip", "hostname")).items():
            for burst in sessionize(rows, self.config.group_gap_seconds):
                detection = self._check_burst(src_ip, hostname, burst)
                if detection is not None:
                    detections.append(detection)
        return detections

    def _check_burst(self, src_ip: str, hostname: str | None, burst: list) -> Detection | None:
        attack_rows, probe_rows, scanner_rows, error_rows = [], [], [], []
        categories: dict[str, int] = {}
        for row in burst:
            attacks, is_probe, is_scanner = classify_request(row["url"], row["user_agent"])
            for name in attacks:
                categories[name] = categories.get(name, 0) + 1
            if attacks:
                attack_rows.append(row)
            if is_probe:
                probe_rows.append(row)
            if is_scanner:
                scanner_rows.append(row)
            if row["http_status"] is not None and 400 <= row["http_status"] <= 499:
                error_rows.append(row)

        # Đếm lỗi 4xx dồn dập: >= error_threshold lỗi trong error_window_seconds giây.
        error_times = [row["ts_epoch"] for row in error_rows]
        error_burst = first_threshold_index(error_times, self.config.error_threshold,
                                            self.config.error_window_seconds) is not None
        recon = bool(scanner_rows) or len(probe_rows) >= self.config.min_probe_requests

        if not attack_rows and not error_burst and not recon:
            return None                              # đợt này bình thường
        succeeded = [row for row in attack_rows if 200 <= (row["http_status"] or 0) <= 299]
        if succeeded:
            severity, pattern = 4, "attack_payload_answered_2xx"
        elif attack_rows:
            severity, pattern = 3, "attack_payload"
        elif error_burst:
            severity, pattern = 3, "error_burst"
        else:
            severity, pattern = 2, "reconnaissance"

        flagged = {}                                 # event_id -> (row, vai trò), bỏ trùng
        if error_burst:
            for row in error_rows:
                flagged[row["event_id"]] = (row, "web_error_response")
        for row in probe_rows + scanner_rows:
            flagged[row["event_id"]] = (row, "web_probe_request")
        for row in attack_rows:
            flagged[row["event_id"]] = (row, "web_attack_request")
        ordered = sorted(flagged.values(), key=lambda item: (item[0]["ts_epoch"], item[0]["event_id"]))

        statuses: dict[str, int] = {}
        for row in burst:
            key = str(row["http_status"])
            statuses[key] = statuses.get(key, 0) + 1
        samples = attack_rows or probe_rows or scanner_rows or error_rows
        agents = sorted({row["user_agent"] for row in scanner_rows if row["user_agent"]})

        reason = f"{len(burst)} web request(s) from {src_ip} to {hostname or 'the web server'}"
        if attack_rows:
            reason += f"; {len(attack_rows)} contained attack payloads ({', '.join(sorted(categories))})"
        if succeeded:
            reason += f"; {len(succeeded)} of them were answered 2xx (the attack may have worked)"
        if error_burst:
            reason += (f"; at least {self.config.error_threshold} 4xx errors within "
                       f"{self.config.error_window_seconds}s (directory brute force / scanning)")
        if scanner_rows:
            reason += f"; scanner user agent: {agents[0][:80] if agents else '?'}"
        if probe_rows:
            reason += f"; {len(probe_rows)} probe(s) for sensitive files"

        evidence = {
            "pattern": pattern,
            "requests": len(burst),
            "attack_requests": len(attack_rows),
            "attack_categories": categories,
            "answered_2xx": len(succeeded),
            "probe_requests": len(probe_rows),
            "scanner_requests": len(scanner_rows),
            "scanner_user_agents": [agent[:200] for agent in agents[:5]],
            "error_responses": len(error_rows),
            "error_burst": error_burst,
            "status_counts": statuses,
            "samples": [{"time": row["timestamp_utc"], "request": row["message"][:300]}
                        for row in samples[:MAX_SAMPLES_IN_EVIDENCE]],
            "error_threshold": self.config.error_threshold,
            "error_window_seconds": self.config.error_window_seconds,
        }
        return Detection(
            rule_id=self.rule_id, rule_name=self.name, severity=severity,
            entity_key=f"{src_ip}|{hostname or '-'}",
            first_ts=ordered[0][0]["ts_epoch"], last_ts=ordered[-1][0]["ts_epoch"],
            events=[(row["event_id"], role) for row, role in ordered],
            rationale=reason + ".", mitre=self.mitre, src_ip=src_ip, hostname=hostname, evidence=evidence)
