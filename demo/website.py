"""Website demo để thử SOC Toolkit trên cùng một máy (không cần cài nginx / Apache).

Website ghi access log theo định dạng "combined" giống hệt nginx / Apache, nên
toolkit đọc được bằng nguồn `web_access`.

Chạy:
    python demo/website.py                      # http://127.0.0.1:8080, log: demo/logs/access.log
    python demo/website.py --port 80            # cổng 80 (cổng có thể đang bị IIS / Skype chiếm)
    python demo/website.py --host 0.0.0.0       # cho máy khác trong mạng LAN truy cập

Website này KHÔNG có lỗ hổng thật: trang /products và /search chỉ trả về chữ,
không chạy câu SQL nào. Nó chỉ dùng để sinh log cho toolkit phát hiện.
"""
import argparse
import html
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DEFAULT_LOG = Path(__file__).resolve().parent / "logs" / "access.log"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
PAGES = {
    "/": "<h1>Demo Shop</h1><p><a href='/products?id=1'>Sản phẩm 1</a> | <a href='/search?q=ao'>Tìm kiếm</a></p>",
    "/about": "<h1>Giới thiệu</h1><p>Website demo cho đồ án SOC.</p>",
    "/login": "<h1>Đăng nhập</h1><form method='post'><input name='u'><input name='p' type='password'>"
              "<button>OK</button></form>",
}


def log_time(now: datetime | None = None) -> str:
    """Thời gian kiểu access log: 16/Nov/2026:08:44:00 +0700 (giờ máy, kèm múi giờ)."""
    now = (now or datetime.now()).astimezone()
    offset = now.strftime("%z") or "+0000"
    return f"{now.day:02d}/{MONTHS[now.month - 1]}/{now.year}:{now:%H:%M:%S} {offset}"


def quote(text: str) -> str:
    """Escape như nginx: dấu " và \\ được thêm \\ phía trước."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


class DemoHandler(BaseHTTPRequestHandler):
    log_file: Path = DEFAULT_LOG
    lock = threading.Lock()
    server_version = "DemoShop/1.0"

    def do_GET(self) -> None:
        self.respond()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(min(length, 65536))       # đọc bỏ body
        self.respond()

    def respond(self) -> None:
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        if parts.path in PAGES:
            status, body = 200, PAGES[parts.path]
        elif parts.path == "/products":
            item = html.escape(query.get("id", ["?"])[0])
            status, body = 200, f"<h1>Sản phẩm {item}</h1>"
        elif parts.path == "/search":
            words = html.escape(query.get("q", [""])[0])
            status, body = 200, f"<h1>Kết quả cho: {words}</h1><p>Không tìm thấy.</p>"
        else:
            status, body = 404, "<h1>404 - Không có trang này</h1>"
        data = f"<!doctype html><meta charset='utf-8'>{body}".encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.write_access_log(status, len(data))

    def write_access_log(self, status: int, size: int) -> None:
        agent = self.headers.get("User-Agent") or "-"
        referer = self.headers.get("Referer") or "-"
        line = (f'{self.client_address[0]} - - [{log_time()}] "{quote(self.requestline)}" {status} {size} '
                f'"{quote(referer)}" "{quote(agent)}"\n')
        with self.lock:
            with open(self.log_file, "a", encoding="utf-8") as handle:
                handle.write(line)

    def log_message(self, format: str, *args) -> None:   # noqa: A002 - tắt log mặc định ra màn hình
        pass


def make_server(host: str, port: int, log_file: Path) -> ThreadingHTTPServer:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    handler = type("Handler", (DemoHandler,), {"log_file": log_file})
    return ThreadingHTTPServer((host, port), handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="Website demo ghi access log cho SOC Toolkit")
    parser.add_argument("--host", default="127.0.0.1", help="127.0.0.1 = chỉ máy này; 0.0.0.0 = cả mạng LAN")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="file access log")
    args = parser.parse_args()
    server = make_server(args.host, args.port, args.log)
    print(f"Website demo: http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}")
    print(f"Access log:   {args.log.resolve()}")
    print("Nhấn Ctrl+C để dừng.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Đã dừng.")


if __name__ == "__main__":
    main()
