"""Đọc access log của web server (nginx / Apache), định dạng "combined" hoặc "common".

Một dòng combined (mặc định của nginx, và Apache với LogFormat combined):

  203.0.113.5 - - [16/Nov/2026:07:41:00 +0700] "GET /login.php?id=1 HTTP/1.1" 404 512 "-" "Mozilla/5.0"
  └ IP client  │ └user [thời gian]               └ request: method, đường dẫn, giao thức  │   │   │     └ User-Agent
               └ ident (luôn là "-")                                              mã trả về ┘   │   └ Referer
                                                                                   số byte trả về ┘

Định dạng common giống hệt nhưng không có Referer và User-Agent. Phần thêm phía
sau (ví dụ nginx ghi thêm request_time) được bỏ qua.
"""
import re
from typing import Any

from ingestors.base import ParseError

SOURCE_TYPE = "web_access"

# Mỗi chuỗi trong ngoặc kép được bắt bằng  "((?:[^"\\]|\\.)*)"  : mọi ký tự trừ " và \,
# hoặc một ký tự đã được escape (\" hay \x22). Cách viết này chạy tuyến tính, không bị ReDoS.
_LINE = re.compile(r"""
    ^(?P<ip>\S+)\ (?P<ident>\S+)\ (?P<user>\S+)\       # IP client, ident, user
    \[(?P<time>[^\]]{1,64})\]\                            # [16/Nov/2026:07:41:00 +0700]
    "(?P<request>(?:[^"\\]|\\.)*)"\                      # "GET /path HTTP/1.1"
    (?P<status>\d{3})\ (?P<size>\d+|-)                    # 404 512
    (?:\ "(?P<referer>(?:[^"\\]|\\.)*)"\ "(?P<agent>(?:[^"\\]|\\.)*)")?   # "referer" "user-agent" (combined)
    (?:\s.*)?$                                            # phần thêm phía sau (bỏ qua)
""", re.VERBOSE)
# Request hợp lệ: "<METHOD> <đường dẫn> HTTP/x.y"
_REQUEST = re.compile(r"^(?P<method>[A-Z]{3,10}) (?P<target>\S+)(?: (?P<protocol>HTTP/\d(?:\.\d)?))?$")


def parse_line(line: str) -> dict[str, Any]:
    """Tách một dòng access log thành các trường thô (chưa kiểm tra giá trị)."""
    m = _LINE.match(line)
    if not m:
        raise ParseError("malformed_access_log_line")
    request = _unescape(m["request"])
    method = target = protocol = None
    parts = _REQUEST.match(request)
    if parts:
        method, target, protocol = parts["method"], parts["target"], parts["protocol"]
    else:
        # Request rác (ví dụ máy quét gửi byte TLS vào cổng 80): vẫn giữ lại làm bằng chứng.
        target = request or None
    return {
        "client_ip": m["ip"],
        "remote_user": None if m["user"] == "-" else m["user"],
        "timestamp_raw": m["time"],
        "request": request,
        "method": method,
        "url": target,
        "protocol": protocol,
        "status": m["status"],
        "size": None if m["size"] == "-" else m["size"],
        "referer": _dash_to_none(m["referer"]),
        "user_agent": _dash_to_none(m["agent"]),
    }


def _dash_to_none(value: str | None) -> str | None:
    if value is None or value == "-":
        return None
    return _unescape(value)


def _unescape(text: str) -> str:
    r"""Bỏ escape mà nginx/Apache thêm vào: \" -> ", \\ -> \, \x22 -> ".

    Chỉ đổi \xHH thành ký tự in được, để chuỗi lưu vào database luôn đọc được.
    """
    def replace(match: re.Match) -> str:
        code = match.group(1)
        if code is not None:
            char = chr(int(code, 16))
            return char if char.isprintable() else match.group(0)
        return match.group(2)
    return re.sub(r"\\x([0-9a-fA-F]{2})|\\(.)", replace, text)
