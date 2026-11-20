"""RULE SOC-001 — SSH Brute Force (dò mật khẩu SSH).

Điều kiện của đề: một IP đăng nhập SSH thất bại >= 5 lần trong 60 giây, SAU ĐÓ
đăng nhập thành công hoặc tài khoản bị khóa.

Cách rule làm việc:
  1. Lấy mọi event 'failed_login' của auth.log, gom theo cặp (IP nguồn, máy đích).
  2. Mỗi cặp được chia thành từng đợt tấn công (sessionize).
  3. Đợt nào có đủ `threshold` lần thất bại trong `window_seconds` giây thì báo.
  4. Tìm tiếp trong `followup_seconds` giây sau đợt:
       - có đăng nhập THÀNH CÔNG từ cùng IP  -> severity 5 (CRITICAL)
       - có KHÓA tài khoản                    -> severity 4 (HIGH)
       - không có gì                           -> severity 3 (MEDIUM)
  5. Nếu bật require_followup (đúng nguyên văn đề) thì trường hợp "không có gì"
     không được báo.
"""
import sqlite3

from config import SshBruteForceConfig
from engine.rules.base import Detection, Rule, first_threshold_index, group_rows, sessionize


class SshBruteForceRule(Rule):
    rule_id = "SOC-001"
    name = "SSH Brute Force"
    description = "Repeated failed SSH logins from one source IP against one host."
    severity = 3
    mitre = "T1110.001 Brute Force: Password Guessing"

    def __init__(self, config: SshBruteForceConfig | None = None) -> None:
        self.config = config or SshBruteForceConfig()
        self.threshold = self.config.threshold
        self.window_seconds = self.config.window_seconds

    def detect(self, conn: sqlite3.Connection) -> list[Detection]:
        failed_logins = conn.execute(
            "SELECT event_id, src_ip, hostname, username, ts_epoch FROM events "
            "WHERE action = 'failed_login' AND source_type = 'linux_auth' AND src_ip IS NOT NULL "
            "ORDER BY src_ip, hostname, ts_epoch, event_id").fetchall()

        detections = []
        groups = group_rows(failed_logins, ("src_ip", "hostname"))
        for (src_ip, hostname), rows in groups.items():
            for burst in sessionize(rows, self.config.window_seconds):
                times = [row["ts_epoch"] for row in burst]
                hit = first_threshold_index(times, self.config.threshold, self.config.window_seconds)
                if hit is None:
                    continue                      # đợt này chưa đủ ngưỡng
                detection = self._build(conn, src_ip, hostname, burst, times[hit])
                failures_only = detection.evidence["pattern"] == "failed_login_burst"
                if self.config.require_followup and failures_only:
                    continue                      # chế độ đúng đề: phải có thành công / khóa
                detections.append(detection)
        return detections

    def _find_followups(self, conn, src_ip, hostname, usernames, first_ts, threshold_ts, until):
        """Tìm đăng nhập thành công và khóa tài khoản xảy ra sau đợt thất bại."""
        success_rows = conn.execute(
            "SELECT event_id, username, hostname, ts_epoch, timestamp_utc FROM events "
            "WHERE action = 'successful_login' AND source_type = 'linux_auth' AND src_ip = ? "
            "AND ts_epoch >= ? AND ts_epoch <= ? ORDER BY ts_epoch",
            (src_ip, threshold_ts, until)).fetchall()
        successes = [row for row in success_rows if row["hostname"] == hostname]

        # Dòng khóa tài khoản đôi khi không ghi IP; khi đó so khớp theo tên user bị dò.
        lockout_rows = conn.execute(
            "SELECT event_id, username, hostname, src_ip, ts_epoch, timestamp_utc FROM events "
            "WHERE action = 'account_lockout' AND ts_epoch >= ? AND ts_epoch <= ? ORDER BY ts_epoch",
            (first_ts, until)).fetchall()
        lockouts = []
        for row in lockout_rows:
            if row["hostname"] != hostname:
                continue
            same_ip = row["src_ip"] == src_ip
            same_user = row["src_ip"] is None and row["username"] in usernames
            if same_ip or same_user:
                lockouts.append(row)
        return successes, lockouts

    def _build(self, conn, src_ip, hostname, burst, threshold_ts) -> Detection:
        first_ts = burst[0]["ts_epoch"]
        last_ts = burst[-1]["ts_epoch"]
        until = last_ts + self.config.followup_seconds
        usernames = sorted({row["username"] for row in burst if row["username"]})[:50]
        successes, lockouts = self._find_followups(conn, src_ip, hostname, usernames,
                                                   first_ts, threshold_ts, until)

        # Mức độ: mặc định MEDIUM, bị khóa -> HIGH, đăng nhập được -> CRITICAL.
        severity = self.severity
        pattern = "failed_login_burst"
        reason = (f"{len(burst)} failed SSH logins from {src_ip} to {hostname or 'unknown host'} "
                  f"with at least {self.config.threshold} inside {self.config.window_seconds}s")
        if lockouts:
            severity = 4
            pattern = "account_lockout"
            reason += f"; followed by account lockout ({lockouts[0]['username']})"
        if successes:
            severity = 5
            pattern = "success_after_failures"
            reason += (f"; followed by a SUCCESSFUL login as {successes[0]['username']} at "
                       f"{successes[0]['timestamp_utc']} (possible credential compromise)")

        events = []
        for row in burst:
            events.append((row["event_id"], "failed_login"))
        for row in successes:
            events.append((row["event_id"], "successful_login_after_failures"))
        for row in lockouts:
            events.append((row["event_id"], "account_lockout"))

        end_ts = last_ts
        for row in successes + lockouts:
            end_ts = max(end_ts, row["ts_epoch"])

        evidence = {
            "pattern": pattern,
            "failed_count": len(burst),
            "threshold": self.config.threshold,
            "window_seconds": self.config.window_seconds,
            "followup_seconds": self.config.followup_seconds,
            "matches_assignment_condition": pattern != "failed_login_burst",
            "target_usernames": usernames,
            "successful_logins": [_login_info(row) for row in successes],
            "account_lockouts": [_login_info(row) for row in lockouts],
        }
        return Detection(
            rule_id=self.rule_id, rule_name=self.name, severity=severity,
            entity_key=f"{src_ip}|{hostname or '-'}", first_ts=first_ts, last_ts=end_ts,
            events=events, rationale=reason + ".", mitre=self.mitre,
            src_ip=src_ip, hostname=hostname,
            username=usernames[0] if len(usernames) == 1 else None,
            evidence=evidence)


def _login_info(row) -> dict:
    return {"event_id": row["event_id"], "username": row["username"], "timestamp_utc": row["timestamp_utc"]}
