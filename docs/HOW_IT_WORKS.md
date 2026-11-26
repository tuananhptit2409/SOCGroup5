# Cấu trúc và cách hoạt động của SOC Analyst Toolkit

Tài liệu này dành cho người mới đọc code (sinh viên năm 2). Đọc xong bạn sẽ biết: hệ thống làm gì, dữ liệu đi qua những bước nào, mỗi thư mục làm gì và nên đọc code theo thứ tự nào.

## 1. Hệ thống làm gì?

Một SOC (Security Operations Center) nhận log từ nhiều nguồn, tìm dấu hiệu tấn công và đưa cho analyst xử lý. Toolkit này làm bản thu nhỏ của việc đó:

| Nguồn log | Ghi lại gì | Ví dụ một dòng |
|---|---|---|
| Linux `auth.log` | Đăng nhập SSH, sudo, khóa tài khoản | `Failed password for root from 203.0.113.10 port 50000 ssh2` |
| Suricata `eve.json` | Lưu lượng mạng: cảnh báo IDS, flow, DNS, HTTP | `{"event_type": "alert", "src_ip": "...", "alert": {"signature": "...", "severity": 1}}` |
| Windows Sysmon (JSON) | Tiến trình được tạo (ID 1), kết nối mạng (ID 3), file được tạo (ID 11) | `{"EventID": 1, "Image": "C:\\...\\powershell.exe", "CommandLine": "..."}` |
| Access log web (nginx / Apache) | Mỗi request vào website: IP, đường dẫn, mã trả về, User-Agent | `203.0.113.5 - - [16/Nov/2026:07:41:00 +0700] "GET /item?id=1%27 HTTP/1.1" 500 512 "-" "sqlmap/1.8"` |

Toolkit **chỉ quan sát và cảnh báo**, không chặn gì cả (nó không phải tường lửa).

## 2. Dữ liệu đi qua 6 bước

```
 file log ─► 1. INGEST ─► 2. NORMALIZE ─► 3. LƯU (SQLite) ─► 4. DETECT ─► 5. DEDUP ─► 6. INCIDENT ─► dashboard / CLI
            đọc từng dòng   đổi về một      raw_events,        5 rule      detection     gộp alert
            tách trường     định dạng chung  events             -> detection -> alert      -> incident
```

| Bước | Thư mục / file | Vào | Ra |
|---|---|---|---|
| 1. Ingest | `ingestors/` | một dòng chữ trong file log | dict các trường thô (chuỗi) |
| 2. Normalize | `normalizer/` | dict trường thô | `UnifiedEvent`: cùng một khuôn cho cả 4 nguồn (thời gian UTC, IP, cổng, user, máy, action, severity...) |
| 3. Lưu | `storage/` | `UnifiedEvent` | dòng trong bảng `events`; dòng gốc trong `raw_events` (cả dòng lỗi, kèm lý do) |
| 4. Detect | `engine/rules/` | bảng `events` | `Detection`: "rule X thấy hoạt động đáng ngờ của thực thể Y từ t1 đến t2" |
| 5. Dedup | `engine/correlation.py` | các `Detection` | `alert`: detection lặp lại của cùng rule, cùng thực thể, trong 10 phút được gộp làm một |
| 6. Incident | `engine/incident_manager.py` | các `alert` | `incident`: các alert cùng IP/máy trong 30 phút gộp thành một vụ việc; có trạng thái, analyst, lịch sử |

`pipeline.py` nối các bước lại bằng hai hàm: `ingest_file()` (bước 1-3) và `run_detection()` (bước 4-6). `main.py` (dòng lệnh) và `ui/` (dashboard) chỉ gọi hai hàm này.

## 3. Theo chân một cuộc tấn công

Kẻ tấn công 203.0.113.10 dò mật khẩu SSH của máy `web01`:

1. `auth.log` có 6 dòng `Failed password for root from 203.0.113.10 ...` trong 25 giây, rồi 1 dòng `Accepted password for root from 203.0.113.10`.
2. **Ingest** (`ingestors/linux_auth.py`): regex nhận ra từng dòng, ra `action="failed_login"` / `"successful_login"`, `src_ip="203.0.113.10"`, `hostname="web01"`.
3. **Normalize** (`normalizer/linux_normalizer.py`): đổi thời gian `Nov 13 02:10:01` sang `2026-11-13T02:10:01Z`, kiểm tra IP hợp lệ, gán severity.
4. **Lưu**: 7 dòng vào bảng `events`.
5. **Detect** (`engine/rules/ssh_bruteforce.py`): gom các lần thất bại theo (IP, máy), thấy 6 lần trong 60 giây (ngưỡng 5) và sau đó có đăng nhập thành công, nên tạo một Detection severity 5 (CRITICAL).
6. **Dedup** (`engine/correlation.py`): chưa có alert nào cho `SOC-001` + `203.0.113.10|web01` nên tạo alert mới. Chạy `detect` lần nữa thì không tạo thêm.
7. **Incident** (`engine/incident_manager.py`): chưa có incident nào đang mở cho `ip:203.0.113.10` nên tạo incident `NEW`. Nếu 5 phút sau IP này còn quét cổng thì alert quét cổng nhập vào **cùng** incident.
8. Analyst mở dashboard, giao incident cho mình, đổi sang `IN_PROGRESS`, ghi chú, xuất báo cáo.

## 4. Năm rule phát hiện (4 rule của đề + 1 rule cho website)

| Rule | File | Ý tưởng (đọc docstring đầu file để biết chi tiết) |
|---|---|---|
| SOC-001 SSH Brute Force | `engine/rules/ssh_bruteforce.py` | ≥ 5 lần SSH thất bại trong 60 giây từ một IP; nặng hơn nếu sau đó đăng nhập được hoặc tài khoản bị khóa |
| SOC-002 Port Scan | `engine/rules/port_scan.py` | một IP nội bộ chạm ≥ 15 cổng khác nhau của một máy trong 30 giây (cửa sổ trượt) |
| SOC-003 Suspicious Process | `engine/rules/suspicious_process.py` | cộng điểm: chạy từ Temp/AppData, PowerShell mã hóa, Office hoặc web server sinh ra shell... |
| SOC-004 Network-to-Host Pivot | `engine/rules/network_host_pivot.py` | Suricata báo động mức cao vào một máy nội bộ, rồi trong 5 phút máy đó kết nối sang máy nội bộ khác |
| SOC-005 Web Attack | `engine/rules/web_attack.py` | trong access log có SQL injection / XSS / path traversal / command injection, công cụ quét, hoặc ≥ 20 lỗi 4xx trong 60 giây từ một IP |

Mọi rule đều có cùng dạng: lớp con của `Rule` (`engine/rules/base.py`), có hàm `detect(conn)` chạy câu SQL lấy event, xử lý bằng Python, trả về `list[Detection]`. Các hàm dùng chung (`group_rows`, `sessionize`, `first_threshold_index`, `is_internal_ip`) nằm trong `base.py`. Mỗi hàm có ví dụ trong docstring.

## 5. Bản đồ thư mục

```
main.py                 dòng lệnh: init-db, run-sample, ingest, detect, watch, incidents, assign, report, dashboard
pipeline.py             nối các bước: ingest_file(), run_detection(), watch_files()
config.py               mọi ngưỡng và đường dẫn (sửa bằng config/settings.json)
ingestors/              bước 1: linux_auth.py, suricata.py, sysmon.py, web_access.py, base.py (đọc file an toàn)
normalizer/             bước 2: models.py (UnifiedEvent + hàm chuẩn hóa), *_normalizer.py
storage/                bước 3: schema.sql (10 bảng), database.py (kết nối, migration),
                        repository.py (mọi câu SQL), models.py (trạng thái, DedupSummary)
engine/rules/           bước 4: 5 rule + base.py
engine/rule_engine.py   chạy lần lượt các rule
engine/correlation.py   bước 5: chống trùng alert
engine/incident_manager.py  bước 6: incident, vòng đời, giao analyst
reporting.py            xuất báo cáo incident (Markdown)
ui/                     dashboard Streamlit (6 trang); ui/data_access.py là lớp lấy dữ liệu cho dashboard
datasets/               sinh dữ liệu mẫu + đáp án (ground truth)
tests/                  411+ test tự động (pytest)
benchmarks/             đo tốc độ, độ chính xác, fuzz, chạy dài
```

## 6. Nên đọc code theo thứ tự nào?

1. `normalizer/models.py`: lớp `UnifiedEvent`, để biết một event có những trường gì.
2. `ingestors/linux_auth.py`, rồi `normalizer/linux_normalizer.py`: một nguồn log từ đầu đến cuối.
3. `pipeline.py`, hàm `ingest_file()` và `_process_batch()`.
4. `engine/rules/base.py`, rồi `ssh_bruteforce.py`: rule dễ nhất.
5. `port_scan.py` (cửa sổ trượt), `suspicious_process.py` (tính điểm), `network_host_pivot.py` (ghép 2 nguồn).
6. `engine/correlation.py`, rồi `engine/incident_manager.py`.
7. `storage/schema.sql` để thấy các bảng, rồi `storage/repository.py` khi cần biết một câu SQL cụ thể.
8. `ui/dashboard.py` và `ui/pages/` cuối cùng.

Mỗi người trong nhóm nên đọc kỹ các file của module mình (xem `phanchiacongviec.txt`) và đọc lướt mục 2-3 của tài liệu này.

## 7. Kiến thức Python / SQL cần có

| Thứ bạn sẽ gặp | Ở đâu | Ghi chú |
|---|---|---|
| `class`, kế thừa | rules, managers | Rule con kế thừa `Rule` |
| `@dataclass` | `Detection`, `UnifiedEvent`, `Settings` | lớp chỉ chứa dữ liệu, Python tự viết `__init__` |
| Type hint `str \| None` | khắp nơi | chỉ là chú thích kiểu, Python không kiểm tra khi chạy |
| `dict`, `set`, list comprehension | khắp nơi | `{row["dst_ip"] for row in rows}` = tập các IP khác nhau |
| Regex (`re`) | `ingestors/linux_auth.py`, `suspicious_process.py` | `(?P<user>...)` là nhóm có tên, lấy ra bằng `m["user"]` |
| `with db.transaction() as conn:` | pipeline, CLI | mở transaction; lỗi thì tự rollback, xong thì commit |
| SQL `SELECT ... WHERE ... ORDER BY`, tham số `?` | rules, repository | dùng `?` thay vì ghép chuỗi để chống SQL injection |
| Generator (`yield`) | `ingestors/base.py: iter_lines`; `storage/database.py` (`@contextmanager` cho `with`) | `iter_lines` đọc file từng dòng, không nạp cả file vào RAM |

Những chỗ khó còn lại đều có lý do và đã có chú thích: đọc file theo byte (chống dòng dài bất thường), cửa sổ trượt (quét cổng), khóa dedup bằng hash.
