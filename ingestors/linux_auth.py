"""Đọc Linux authentication log (/var/log/auth.log hoặc /var/log/secure).

Mỗi dòng có dạng syslog: "<thời gian> <máy> <tiến trình>[<pid>]: <thông điệp>".
Các biểu thức chính quy (regex) bên dưới nhận ra từng loại thông điệp.
"""
import re
from typing import Any

from ingestors.base import ParseError

SOURCE_TYPE = "linux_auth"

_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
# The user name is matched greedily so the LAST "from <ip> port <n>" wins; a
# crafted user name such as "x from 1.2.3.4 port 1" cannot spoof the source IP.
_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.*) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh\d?)?\s*$"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>.*) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh\d?)?(?:: .*)?\s*$"
)
_INVALID_USER = re.compile(r"^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port (?P<port>\d+))?\s*$")
_LOCKOUTS = (
    re.compile(r"pam_faillock\(\S+\): Consecutive login failures for user (?P<user>\S+) account temporarily locked"),
    re.compile(r"pam_tally2?\(\S+\): user (?P<user>\S+) \(\d+\) tally \d+, deny \d+"),
    re.compile(r"[Aa]ccount (?P<user>\S+) (?:is |has been )?locked"),
)
_RHOST = re.compile(r"\brhost=(?P<ip>[0-9a-fA-F:.]+)")
# sudo:    alice : [3 incorrect password attempts ; ]TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:(?P<failures>\d+) incorrect password attempts? ; )?"
                   r"(?:TTY=\S+ ; )?PWD=.*? ; USER=(?P<target>\S+) ; COMMAND=(?P<command>.+?)\s*$")
# pam_unix(<service>:auth): authentication failure; logname=.. uid=.. euid=.. tty=.. ruser=.. rhost=.. user=alice
_PAM_FAILURE = re.compile(r"pam_unix\((?P<service>[^:)]+):auth\): authentication failure;.*")
_PAM_USER = re.compile(r"\buser=(?P<user>\S+)")
_PAM_LOGNAME = re.compile(r"\blogname=(?P<user>\S+)")


def parse_line(line: str) -> dict[str, Any]:
    """Tách một dòng auth.log thành các trường (chuỗi thô, chưa kiểm tra giá trị).

    Ví dụ: "Nov 13 02:10:01 web01 sshd[1234]: Failed password for root from 203.0.113.10 port 50000 ssh2"
      -> hostname="web01", process="sshd", action="failed_login", username="root", src_ip="203.0.113.10"

    Dòng không đúng định dạng syslog -> ParseError. Dòng syslog hợp lệ nhưng
    không phải thông điệp xác thực đã biết -> action="other".
    """
    header = _HEADER.match(line)
    if not header:
        raise ParseError("malformed_syslog_line")
    msg = header.group("msg")
    record: dict[str, Any] = {
        "timestamp_raw": header.group("ts"),
        "hostname": header.group("host"),
        "process": header.group("proc"),
        "pid": header.group("pid"),
        "message": msg,
        "action": "other",
        "username": None,
        "src_ip": None,
        "src_port": None,
        "auth_method": None,
        "sudo_target_user": None,
        "sudo_command": None,
    }
    if record["process"] == "sshd" and _parse_sshd(msg, record):
        return record
    if record["process"] == "sudo" and _parse_sudo(msg, record):
        return record
    if _parse_lockout(msg, record):
        return record
    _parse_pam_failure(msg, record)
    return record


def _parse_sshd(msg: str, record: dict[str, Any]) -> bool:
    """Thông điệp của sshd: đăng nhập thất bại / thành công / user không tồn tại."""
    m = _FAILED.match(msg)
    if m:
        record.update(action="failed_login", username=m["user"], src_ip=m["ip"],
                      src_port=m["port"], auth_method=m["method"])
        return True
    m = _ACCEPTED.match(msg)
    if m:
        record.update(action="successful_login", username=m["user"], src_ip=m["ip"],
                      src_port=m["port"], auth_method=m["method"])
        return True
    m = _INVALID_USER.match(msg)
    if m:
        # sshd còn ghi thêm "Failed password for invalid user ..." cho cùng lần thử,
        # nên dòng này có action riêng và KHÔNG được đếm là failed_login.
        record.update(action="invalid_user", username=m["user"], src_ip=m["ip"], src_port=m["port"])
        return True
    return False


def _parse_sudo(msg: str, record: dict[str, Any]) -> bool:
    """Dòng sudo: chạy lệnh thành công, hoặc nhập sai mật khẩu N lần."""
    m = _SUDO.match(msg)
    if not m:
        return False
    action = "sudo_auth_failure" if m["failures"] else "sudo_command"
    record.update(action=action, username=m["user"], sudo_target_user=m["target"],
                  sudo_command=m["command"])
    return True


def _parse_lockout(msg: str, record: dict[str, Any]) -> bool:
    """Tài khoản bị khóa (pam_faillock, pam_tally ...)."""
    for pattern in _LOCKOUTS:
        m = pattern.search(msg)
        if m:
            rhost = _RHOST.search(msg)
            record.update(action="account_lockout", username=m["user"],
                          src_ip=rhost["ip"] if rhost else None)
            return True
    return False


def _parse_pam_failure(msg: str, record: dict[str, Any]) -> bool:
    """pam_unix(...:auth): authentication failure.

    sshd đã ghi dòng "Failed password" riêng cho cùng lần thử, nên dòng PAM được
    lưu là auth_failure và không bao giờ được rule SSH brute force đếm.
    """
    m = _PAM_FAILURE.search(msg)
    if not m:
        return False
    user = _PAM_USER.search(msg) or _PAM_LOGNAME.search(msg)
    rhost = _RHOST.search(msg)
    is_sudo = m["service"] == "sudo" or record["process"] == "sudo"
    record.update(action="sudo_auth_failure" if is_sudo else "auth_failure",
                  username=user["user"] if user else None,
                  src_ip=rhost["ip"] if rhost else None)
    return True
