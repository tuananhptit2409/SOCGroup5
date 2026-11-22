# Multi-Source SOC Analyst Toolkit

Đồ án mô phỏng một phần hoạt động của Security Operations Center (SOC): thu thập log từ nhiều nguồn, chuẩn hóa, lưu vào SQLite, phát hiện hành vi đáng ngờ bằng rule, gộp cảnh báo thành incident và điều tra trên dashboard.

> Đây là công cụ phục vụ học tập và nghiên cứu. Toàn bộ dữ liệu mẫu là **dữ liệu tổng hợp (synthetic)**, không phải kết quả của tấn công thật. Hệ thống **không** được thiết kế để bảo vệ một SOC production.

## 1. Tính năng

- Đọc 3 nguồn log của đề: Linux authentication log (SSH, sudo, PAM), Suricata EVE JSON (alert/dns/http/flow), Windows Sysmon JSON/JSONL (Event ID 1, 3, 11); thêm nguồn thứ 4 cho website: access log nginx/Apache (combined/common).
- Rule thứ 5 **SOC-005 Web Attack** (thêm ngoài đề): SQL injection, XSS, path traversal, command injection/Log4Shell, công cụ quét, dò thư mục.
- Chuẩn hóa về một Unified Event Schema (timestamp UTC, IP, port, action).
- Lưu raw event và normalized event vào SQLite; nhập lại cùng một file không tạo dữ liệu trùng.
- 4 detection rule: SSH Brute Force, Internal Port Scan, Suspicious Process Execution, Network-to-Host Pivot.
- Deduplication cảnh báo (gộp theo fingerprint + cooldown 10 phút), đo mức giảm nhiễu (raw alerts -> alert -> incident), gộp cảnh báo liên quan thành incident, quản lý vòng đời incident (NEW / IN_PROGRESS / CLOSED / FALSE_POSITIVE), giao incident cho analyst, có lịch sử thay đổi.
- Dashboard Streamlit 6 trang: Overview (kèm chỉ số giảm nhiễu, Top Attacked Assets, Incident Timeline dạng Gantt), Events, Alerts, Incidents (giao analyst), Investigation (timeline tương tác), Upload Logs.
- Xuất báo cáo điều tra (Markdown).
- Bộ test pytest, benchmark hiệu năng và đánh giá độ chính xác.

## 2. Kiến trúc

```
LOG SOURCES -> INGESTION -> NORMALIZATION -> SQLITE -> DETECTION -> CORRELATION/DEDUP -> INCIDENTS -> DASHBOARD -> REPORT
   ingestors/   ingestors/   normalizer/     storage/   engine/rules   engine/correlation  engine/      ui/        reporting.py
```

Chi tiết: [docs/system_architecture.md](docs/system_architecture.md). Người mới đọc code nên bắt đầu từ [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) (luồng dữ liệu, ví dụ một cuộc tấn công, thứ tự đọc code).

| Thư mục / file | Vai trò |
|---|---|
| `config.py` | Cấu hình tập trung (đường dẫn DB, ngưỡng rule) |
| `ingestors/` | Parser cho từng nguồn log, đọc file theo dòng |
| `normalizer/` | Unified Event Schema và 3 normalizer |
| `storage/` | `schema.sql`, quản lý kết nối và migration, `models.py` (dataclass Alert/Incident, trạng thái, chỉ số dedup), repository (mọi câu SQL) |
| `engine/` | Rule engine, 5 rule (4 của đề + SOC-005 web), dedup alert, incident manager |
| `pipeline.py` | Điều phối ingest và detection |
| `reporting.py` | Báo cáo incident |
| `ui/` | Dashboard Streamlit và lớp truy vấn dữ liệu |
| `datasets/` | Bộ sinh dữ liệu mẫu, dữ liệu mẫu, ground truth |
| `tests/`, `benchmarks/` | Kiểm thử, benchmark, đánh giá độ chính xác |
| `docs/` | Tài liệu |

## 3. Công nghệ

Python (3.11 trở lên, khuyến nghị 3.12), SQLite, Streamlit, Pandas, Plotly, pytest, psutil (đo bộ nhớ khi benchmark).

## 4. Yêu cầu

- Python 3.11+ (code dùng `datetime.fromisoformat` kiểu mới, không chạy được trên 3.10).
- Không cần cài SQLite riêng (có sẵn trong Python).

## 5. Cài đặt

```bash
cd DoAnSOC
python -m venv .venv
.venv\Scripts\activate            # Windows   (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
```

## 6. Khởi tạo database

```bash
python main.py init-db
```

Mặc định database nằm ở `data/soc.db`. Đổi vị trí bằng biến môi trường `SOC_DB_PATH` hoặc file `config/settings.json` (xem `config/settings.example.json`).

## 7. Chạy nhanh từ đầu đến cuối

```bash
python main.py run-sample     # tạo DB, nhập 3 file mẫu trong datasets/raw, chạy detection
python main.py incidents      # liệt kê incident
python main.py dashboard      # mở dashboard tại http://127.0.0.1:8501 (chỉ truy cập được từ máy này)
```

Nếu `python main.py dashboard` báo thiếu `streamlit`/`plotly`, bạn chưa cài requirements cho đúng Python đang dùng: kích hoạt `.venv` rồi chạy `python -m pip install -r requirements.txt`.

Kết quả mong đợi với dữ liệu mẫu (27 kịch bản có nhãn, 4 file, 1224 dòng): 1212 event, 12 dòng bị từ chối, 14 alert, 12 incident; 21 raw alerts (17 detection + 4 Suricata alert) -> 14 alert -> 12 incident = giảm 42,9%.

Nếu bạn đã có `data/soc.db` từ phiên bản cũ, chạy lại `python main.py init-db` hoặc `run-sample`: cột mới `assigned_analyst` được thêm tự động, dữ liệu cũ được giữ.

## 8. Nhập log

```bash
python main.py ingest --source linux_auth --file datasets/raw/linux_auth.log
python main.py ingest --source suricata   --file datasets/raw/suricata_eve.jsonl
python main.py ingest --source sysmon     --file datasets/raw/sysmon.jsonl
python main.py detect
python main.py stats                # có mục "deduplication" (raw alerts -> alert -> incident)

# Log "lạ" nằm ngoài datasets/ (ví dụ giảng viên đưa lúc demo): cho phép đúng thư mục của file đó,
# rồi chạy detection luôn
python main.py ingest --source linux_auth --file D:\demo\auth.log --trust-path --detect
```

Hoặc dùng trang **Upload Logs** trên dashboard: chọn loại log, tải file (tối đa 50 MB) -> file được lưu vào `datasets/uploads/`, nhập và chạy detection.

- File đầu vào phải nằm trong thư mục được phép (mặc định `datasets/`). Thêm thư mục bằng `allowed_input_dirs` trong `config/settings.json` hoặc biến `SOC_ALLOWED_INPUT_DIRS`.
- Log Linux không có năm: dùng `syslog_default_year` trong cấu hình; nếu không đặt, hệ thống lấy năm hiện tại (lùi một năm nếu ngày rơi vào tương lai). Lệnh `run-sample` tự đặt năm 2026 cho dữ liệu mẫu. Múi giờ của syslog đặt bằng `syslog_utc_offset_minutes` (mặc định 0 = UTC).
- Đầu vào Sysmon là **JSON/JSONL đã export**. Hệ thống **không** đọc trực tiếp file EVTX.
- Tạo lại dữ liệu mẫu: `python main.py generate-dataset`.

## 9. Dùng dashboard

| Trang | Nội dung |
|---|---|
| Overview | Tổng event, alert, incident; **chỉ số giảm nhiễu** (raw alerts, alert sau dedup, incident, % giảm); biểu đồ theo severity, nguồn, top IP, top host, **Top Attacked Assets**; event timeline; **Incident Timeline** (Gantt từng incident, zoom/hover) |
| Events | Tìm kiếm, lọc theo nguồn / IP / thời gian / severity, phân trang, xem raw event |
| Alerts | Danh sách alert, rule, severity, số event, evidence |
| Incidents | Danh sách incident (lọc theo trạng thái, severity, IP, analyst), chi tiết, cập nhật trạng thái, **giao cho analyst** |
| Investigation | **Timeline tương tác** (Plotly, theo làn: log event / alert / đổi trạng thái / ghi chú) + bảng lọc theo loại, alert liên quan, event liên quan, raw log, ghi chú analyst, tải báo cáo |
| Upload Logs | Tải file log lên, nhập và chạy detection |

Quản lý incident bằng dòng lệnh:

```bash
python main.py update-status --id 1 --status IN_PROGRESS --note "đang kiểm tra"
python main.py assign --id 1 --analyst alice     # giao incident; --analyst "" để bỏ giao
python main.py watch --input linux_auth=/var/log/auth.log --input suricata=/var/log/suricata/eve.json \
                     --input web_access=/var/log/nginx/access.log
                                                 # giám sát liên tục máy chủ thật (xem docs/deploy_web_server.md)
python main.py incidents --analyst alice         # incident của một analyst
python main.py report --id 1            # ghi reports/incident_1.md
```

## 10. Chạy test

```bash
python -m pytest
python -m benchmarks.run_benchmark          # 10K / 100K / 500K event
python -m benchmarks.evaluate_accuracy      # precision / recall / F1 / FPR
python -m benchmarks.soak_test --minutes 10 # soak test (DB tạm, không đụng data/soc.db)
python -m benchmarks.leak_check             # kiểm tra rò rỉ bộ nhớ
python -m benchmarks.fuzz_test              # fuzz testing parser và pipeline
```

Khi đã cài `streamlit` và `plotly`, 6 test `test_pages_with_real_streamlit_apptest` sẽ chạy dashboard bằng công cụ AppTest của Streamlit (nếu chưa cài, chúng được đánh dấu skipped).

## Chạy với một website trên cùng máy (Windows)

Toolkit chỉ cần **file access log** của web server (định dạng combined/common của nginx hoặc Apache). Mở 3 cửa sổ PowerShell trong thư mục dự án, mỗi cửa sổ chạy `.venv\Scripts\Activate.ps1` trước:

1. Website. Dùng website của bạn, hoặc website demo đi kèm: `python demo/website.py` (http://127.0.0.1:8080, ghi `demo\logs\access.log`).
2. Giám sát: `python main.py watch --input web_access=demo\logs\access.log --interval 10`. Với website của bạn, thay bằng đường dẫn access log thật, ví dụ XAMPP là `C:\xampp\apache\logs\access.log`, nginx cho Windows là `C:\nginx\logs\access.log`.
3. Dashboard: `python main.py dashboard`, rồi mở http://localhost:8501 và nhấn R để tải lại sau mỗi vòng watch.

Chi tiết và cách triển khai trên máy chủ thật: [docs/deploy_web_server.md](docs/deploy_web_server.md).

## 11. Tài liệu

- [Cấu trúc và cách hoạt động (đọc trước)](docs/HOW_IT_WORKS.md)
- [Giám sát một website cổng 80 / triển khai thật](docs/deploy_web_server.md)
- [Kế hoạch triển khai](docs/IMPLEMENTATION_PLAN.md)
- [Kiến trúc hệ thống](docs/system_architecture.md)
- [ERD database](docs/database_erd.md)
- [Unified Event Schema](docs/unified_event_schema.md)
- [Detection rules](docs/detection_rules.md)
- [Hướng dẫn điều tra](docs/investigation_guide.md)
- [Chiến lược kiểm thử](docs/testing_strategy.md)
- [Báo cáo benchmark](docs/benchmark_report.md)
- [Đối chiếu yêu cầu đề bài](docs/SPEC_COMPLIANCE.md)
- [Báo cáo triển khai cuối cùng](docs/FINAL_IMPLEMENTATION_REPORT.md)
- [Báo cáo audit độ ổn định](docs/stability_test_report.md)
- [Nhật ký sửa lỗi](docs/BUG_FIX_LOG.md)

## 12. Hạn chế đã biết

- Trong môi trường phát triển (Linux) không cài được `streamlit`/`plotly`: logic các trang được test bằng stub, phần hiển thị đã chạy bằng Streamlit thật trên Windows. Các tính năng dashboard mới (Upload Logs, Gantt, timeline tương tác, giao analyst) cần được mở lại trên máy có Streamlit để xác nhận hiển thị; `python -m pytest` trên máy đó chạy thêm 6 test AppTest.
- Detection chạy theo lô và quét lại toàn bộ event mỗi lần (`python main.py detect`), không phải thời gian thực.
- Chống trùng dựa trên hash của dòng log: hai dòng log giống hệt nhau từng ký tự được coi là một event.
- Sysmon chỉ hỗ trợ JSON/JSONL, Event ID 1, 3, 11. Suricata chỉ hỗ trợ alert, dns, http, flow.
- Rule dựa trên ngưỡng nên bỏ sót tấn công chậm (low-and-slow), password spraying từ nhiều IP, và pivot khi có NAT giữa IDS và host; xem [docs/detection_rules.md](docs/detection_rules.md).
- Khi đổi ngưỡng rule, alert cũ trong database không tự bị xóa.
- Dashboard không có đăng nhập hay phân quyền. `python main.py dashboard` và `.streamlit/config.toml` giới hạn nó ở `127.0.0.1`; nếu tự chạy `streamlit run` từ thư mục khác, hãy thêm `--server.address 127.0.0.1`.
- SQLite chỉ cho một tiến trình ghi tại một thời điểm.
- Detection quét lại toàn bộ dữ liệu mỗi lần chạy: thời gian tăng theo tổng số event (khoảng 7 giây ở 1,3 triệu event trong soak test 30 phút).
