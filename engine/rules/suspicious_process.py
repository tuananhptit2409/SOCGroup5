"""RULE SOC-003 — Suspicious Process Execution (tiến trình đáng ngờ, Sysmon Event ID 1).

Cách rule làm việc: mỗi lần một tiến trình được tạo, cộng điểm theo các dấu hiệu
  - chạy từ thư mục lạ: Temp, AppData, Users\Public, Downloads ...   (+2)
  - dòng lệnh đáng ngờ: PowerShell mã hóa (-enc), tải file (certutil,
    bitsadmin, DownloadString), xóa shadow copy ...                     (+2 / +3)
  - Word/Excel/Outlook sinh ra cmd/powershell                          (+3)
  - web server (w3wp, httpd, nginx, php-cgi, tomcat ...) sinh ra shell  (+3, dấu hiệu webshell)
Tổng điểm >= min_score (mặc định 2) thì báo; điểm càng cao severity càng cao.
Chỉ có dấu hiệu thư mục mà cha là trình cài đặt tin cậy (msiexec) thì trừ 2 điểm.
Các lần chạy cùng file trên cùng máy, gần nhau, gộp thành một Detection.
"""
import logging
import re
import sqlite3
from typing import Any

from config import SuspiciousProcessConfig
from engine.rules.base import Detection, Rule, sessionize

logger = logging.getLogger(__name__)
MAX_SCAN_CHARS = 8192

# (indicator name, compiled pattern, score)
_LOCATION = (
    ("exec_from_appdata_temp", re.compile(r"\\appdata\\local\\temp\\", re.I), 2),
    ("exec_from_temp", re.compile(r"\\(windows\\temp|temp|tmp)\\", re.I), 2),
    ("exec_from_appdata", re.compile(r"\\appdata\\(roaming|local|locallow)\\", re.I), 2),
    ("exec_from_unusual_dir", re.compile(
        r"\\users\\public\\|\\programdata\\[^\\]+\.exe$|\\\$recycle\.bin\\|\\perflogs\\|\\downloads\\", re.I), 2),
)
_COMMAND = (
    ("encoded_powershell", re.compile(
        r"(powershell|pwsh)[^|&]{0,200}\s-e(c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I), 3),
    ("hidden_window", re.compile(r"\s-w(in|indowstyle)?\s+h(idden)?\b", re.I), 2),
    ("download_cradle", re.compile(
        r"downloadstring|downloadfile|net\.webclient|frombase64string|invoke-expression|\biex\b", re.I), 2),
    ("certutil_download_or_decode", re.compile(r"certutil(\.exe)?\b.{0,200}-(urlcache|decode|decodehex)\b", re.I), 3),
    ("bitsadmin_transfer", re.compile(r"bitsadmin(\.exe)?\b.{0,200}/transfer\b", re.I), 3),
    ("mshta_remote_script", re.compile(r"mshta(\.exe)?\b.{0,200}(https?:|javascript:|vbscript:)", re.I), 3),
    ("regsvr32_scriptlet", re.compile(r"regsvr32(\.exe)?\b.{0,200}(/i:https?:|scrobj\.dll)", re.I), 3),
    ("rundll32_script", re.compile(r"rundll32(\.exe)?\b.{0,200}javascript:", re.I), 3),
    ("shadow_copy_deletion", re.compile(
        r"vssadmin(\.exe)?\b.{0,100}delete\s+shadows|wmic\b.{0,100}shadowcopy\s+delete", re.I), 3),
    ("wmic_process_create", re.compile(r"wmic\b.{0,200}process\s+call\s+create", re.I), 3),
)
_OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe",
                   "onenote.exe", "acrord32.exe"}
# Tiến trình web server: nếu nó sinh ra cmd/powershell thì thường là webshell
# (kẻ tấn công khai thác lỗ hổng của trang web rồi chạy lệnh trên máy chủ).
_WEB_SERVER_PARENTS = {"w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "php.exe", "tomcat.exe",
                       "tomcat9.exe", "java.exe", "node.exe"}
_SCRIPT_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}


def _basename(path: str | None) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _severity(score: int) -> int:
    if score >= 7:
        return 5
    if score >= 5:
        return 4
    if score >= 3:
        return 3
    return 2


class SuspiciousProcessRule(Rule):
    rule_id = "SOC-003"
    name = "Suspicious Process Execution"
    description = "Process started from an unusual folder, with a suspicious command line or parent."
    severity = 2
    mitre = "T1059 Command and Scripting Interpreter / T1204 User Execution"

    def __init__(self, config: SuspiciousProcessConfig | None = None) -> None:
        self.config = config or SuspiciousProcessConfig()
        self.threshold = self.config.min_score
        self.window_seconds = self.config.dedup_window_seconds
        self._allow: list[re.Pattern[str]] = []
        for pattern in self.config.allow_image_patterns:
            try:
                self._allow.append(re.compile(pattern, re.I))
            except re.error as exc:
                logger.warning("event=invalid_allow_pattern pattern=%r error=%s", pattern, exc)
        self._trusted = {name.lower() for name in self.config.trusted_parent_names}

    def score(self, process_path: str | None, command_line: str | None,
              parent_process: str | None) -> tuple[int, list[str], list[str]]:
        """Return (score, indicators, notes) for one process creation."""
        path = (process_path or "").replace("/", "\\")
        if any(p.search(path) for p in self._allow):
            return 0, [], ["image_allow_listed"]
        score, indicators, notes = 0, [], []
        for name, pattern, points in _LOCATION:
            if pattern.search(path):
                score += points
                indicators.append(name)
                break  # one location indicator at most
        location_only = bool(indicators)
        command = (command_line or "")[:MAX_SCAN_CHARS]
        for name, pattern, points in _COMMAND:
            if command and pattern.search(command):
                score += points
                indicators.append(name)
                location_only = False
        parent = _basename(parent_process)
        if not parent_process:
            notes.append("parent_unknown")
        if not command_line:
            notes.append("command_line_unknown")
        if parent in _OFFICE_PARENTS and _basename(path) in _SCRIPT_CHILDREN:
            score += 3
            indicators.append("office_spawned_script_host")
            location_only = False
        if parent in _WEB_SERVER_PARENTS and _basename(path) in _SCRIPT_CHILDREN:
            score += 3
            indicators.append("web_server_spawned_shell")
            location_only = False
        if location_only and parent in self._trusted:
            score -= 2
            notes.append("trusted_installer_parent")
        return max(score, 0), indicators, notes

    def detect(self, conn: sqlite3.Connection) -> list[Detection]:
        cursor = conn.execute(
            "SELECT event_id, hostname, username, process_path, process_name, command_line, "
            "parent_process, ts_epoch FROM events WHERE action = 'process_creation' "
            "ORDER BY ts_epoch, event_id")
        hits: dict[tuple[str, str], list[dict[str, Any]]] = {}    # (máy, đường dẫn file) -> các lần chạy
        for row in cursor:
            score, indicators, notes = self.score(row["process_path"], row["command_line"],
                                                  row["parent_process"])
            if score >= self.config.min_score and indicators:
                key = (row["hostname"] or "-", (row["process_path"] or "").lower())
                hits.setdefault(key, []).append({"row": row, "score": score, "indicators": indicators,
                                  "notes": notes, "ts_epoch": row["ts_epoch"]})
        detections = []
        for (hostname, _path), items in sorted(hits.items()):
            for burst in sessionize(items, self.config.dedup_window_seconds):
                detections.append(self._build(hostname, burst))
        return detections

    def _build(self, hostname: str, burst: list[dict[str, Any]]) -> Detection:
        top = max(burst, key=lambda item: item["score"])
        row = top["row"]
        indicators = sorted({name for item in burst for name in item["indicators"]})
        notes = sorted({note for item in burst for note in item["notes"]})
        severity = _severity(top["score"])
        verdict = ("location only: review, not necessarily malicious"
                   if all(name.startswith("exec_from") for name in indicators)
                   else "multiple suspicious indicators")
        users = sorted({item["row"]["username"] for item in burst if item["row"]["username"]})
        return Detection(
            rule_id=self.rule_id, rule_name=self.name, severity=severity,
            entity_key=f"{hostname}|{(row['process_path'] or '').lower()}",
            first_ts=burst[0]["ts_epoch"], last_ts=burst[-1]["ts_epoch"],
            events=[(item["row"]["event_id"], "process_creation") for item in burst],
            rationale=(f"{row['process_name']} on {hostname} matched {', '.join(indicators)} "
                       f"(score {top['score']}; {verdict})."),
            mitre=self.mitre, hostname=None if hostname == "-" else hostname,
            username=users[0] if len(users) == 1 else None,
            evidence={"score": top["score"], "indicators": indicators, "notes": notes,
                      "process_path": row["process_path"],
                      "command_line": (row["command_line"] or "")[:1000] or None,
                      "parent_process": row["parent_process"], "executions": len(burst),
                      "min_score": self.config.min_score})
