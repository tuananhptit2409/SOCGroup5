"""Website demo (demo/website.py) ghi access log mà toolkit đọc được."""
import threading
import urllib.request
from dataclasses import replace

from demo.website import make_server
from pipeline import ingest_file


def test_demo_website_writes_combined_log_the_toolkit_reads(db, settings) -> None:
    log = settings.allowed_input_dirs[0] / "access.log"
    server = make_server("127.0.0.1", 0, log)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        for path in ["/", "/products?id=3", "/search?q=ao+so+mi"]:
            urllib.request.urlopen(base + path).read()
        try:
            urllib.request.urlopen(base + "/missing")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
    finally:
        server.shutdown()
        server.server_close()
    result = ingest_file(db, replace(settings, web_server_name="demo"), "web_access", log)
    assert result.new_events == 4 and result.rejected == 0
    with db.connection() as conn:
        rows = conn.execute("SELECT src_ip, url, http_status, hostname FROM events ORDER BY ts_epoch").fetchall()
    assert {r["src_ip"] for r in rows} == {"127.0.0.1"} and {r["hostname"] for r in rows} == {"demo"}
    assert sorted(r["http_status"] for r in rows) == [200, 200, 200, 404]
