# Multi-Source SOC Analyst Toolkit

Đồ án mô phỏng một phần hoạt động của Security Operations Center (SOC): thu thập log từ nhiều nguồn, chuẩn hóa, lưu vào SQLite, phát hiện hành vi đáng ngờ bằng rule, gộp cảnh báo thành incident và điều tra trên dashboard.

> Đây là công cụ phục vụ học tập và nghiên cứu. Toàn bộ dữ liệu mẫu là **dữ liệu tổng hợp (synthetic)**, không phải kết quả của tấn công thật. Hệ thống **không** được thiết kế để bảo vệ một SOC production.

## 1. Tính năng

- Đọc 3 nguồn log: Linux authentication log, Suricata EVE JSON (alert/dns/http/flow), Windows Sysmon JSON/JSONL (Event ID 1, 3, 11).
- Chuẩn hóa về một Unified Event Schema (timestamp UTC, IP, port, action).
- Lưu raw event và normalized event vào SQLite; nhập lại cùng một file không tạo dữ liệu trùng.
- 4 detection rule: SSH Brute Force, Internal Port Scan, Suspicious Process Execution, Network-to-Host Pivot.
- Deduplication cảnh báo, gộp cảnh báo liên quan thành incident, quản lý vòng đời incident có lịch sử thay đổi.
- Dashboard Streamlit 5 trang: Overview, Events, Alerts, Incidents, Investigation.
- Xuất báo cáo điều tra (Markdown).
- Bộ test pytest, benchmark hiệu năng và đánh giá độ chính xác.

## 2. Kiến trúc

```
LOG SOURCES -> INGESTION -> NORMALIZATION -> SQLITE -> DETECTION -> CORRELATION/DEDUP -> INCIDENTS -> DASHBOARD -> REPORT
   ingest/      ingest/      normalizer/     storage/   engine/rules   engine/correlation  engine/      ui/        reporting.py
```

Chi tiết: [docs/system_architecture.md](docs/system_architecture.md).

| Thư mục / file | Vai trò |
|---|---|
| `config.py` | Cấu hình tập trung (đường dẫn DB, ngưỡng rule) |
| `ingest/` | Parser cho từng nguồn log, đọc file theo dòng |
| `normalizer/` | Unified Event Schema và 3 normalizer |
| `storage/` | `schema.sql`, quản lý kết nối, repository (mọi câu SQL) |
| `engine/` | Rule engine, 4 rule, dedup alert, incident manager |
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

Kết quả mong đợi với dữ liệu mẫu: 921 event, 10 dòng bị từ chối, 7 alert, 7 incident.

## 8. Nhập log

```bash
python main.py ingest --source linux_auth --file datasets/raw/linux_auth.log
python main.py ingest --source suricata   --file datasets/raw/suricata_eve.jsonl
python main.py ingest --source sysmon     --file datasets/raw/sysmon.jsonl
python main.py detect
python main.py stats
```

- File đầu vào phải nằm trong thư mục được phép (mặc định `datasets/`). Thêm thư mục bằng `allowed_input_dirs` trong `config/settings.json` hoặc biến `SOC_ALLOWED_INPUT_DIRS`.
- Log Linux không có năm: dùng `syslog_default_year` trong cấu hình; nếu không đặt, hệ thống lấy năm hiện tại (lùi một năm nếu ngày rơi vào tương lai). Lệnh `run-sample` tự đặt năm 2026 cho dữ liệu mẫu. Múi giờ của syslog đặt bằng `syslog_utc_offset_minutes` (mặc định 0 = UTC).
- Đầu vào Sysmon là **JSON/JSONL đã export**. Hệ thống **không** đọc trực tiếp file EVTX.
- Tạo lại dữ liệu mẫu: `python main.py generate-dataset`.

## 9. Dùng dashboard

| Trang | Nội dung |
|---|---|
| Overview | Tổng event, alert, incident; biểu đồ theo severity, nguồn, top IP, top host, timeline |
| Events | Tìm kiếm, lọc theo nguồn / IP / thời gian / severity, phân trang, xem raw event |
| Alerts | Danh sách alert, rule, severity, số event, evidence |
| Incidents | Danh sách incident, chi tiết, cập nhật trạng thái |
| Investigation | Timeline, alert liên quan, event liên quan, raw log, ghi chú analyst, tải báo cáo |

Quản lý incident bằng dòng lệnh:

```bash
python main.py update-status --id 1 --status IN_PROGRESS --note "đang kiểm tra"
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

Khi đã cài `streamlit` và `plotly`, 5 test `test_pages_with_real_streamlit_apptest` sẽ chạy dashboard bằng công cụ AppTest của Streamlit (nếu chưa cài, chúng được đánh dấu skipped).

## 11. Tài liệu

- [Kế hoạch triển khai](docs/IMPLEMENTATION_PLAN.md)
- [Kiến trúc hệ thống](docs/system_architecture.md)
- [ERD database](docs/database_erd.md)
- [Unified Event Schema](docs/unified_event_schema.md)
- [Detection rules](docs/detection_rules.md)
- [Hướng dẫn điều tra](docs/investigation_guide.md)
- [Chiến lược kiểm thử](docs/testing_strategy.md)
- [Báo cáo benchmark](docs/benchmark_report.md)
- [Báo cáo triển khai cuối cùng](docs/FINAL_IMPLEMENTATION_REPORT.md)
- [Báo cáo audit độ ổn định](docs/stability_test_report.md)
- [Nhật ký sửa lỗi](docs/BUG_FIX_LOG.md)

## 12. Hạn chế đã biết

- **Dashboard chưa được chạy bằng Streamlit thật** trong môi trường phát triển (không cài được `streamlit`/`plotly`). Logic của các trang và lớp truy vấn đã được test; phần hiển thị cần bạn tự kiểm tra trên máy.
- **Chưa chạy thử trên Windows.** Toàn bộ test và benchmark chạy trên Linux, Python 3.13.
- Detection chạy theo lô và quét lại toàn bộ event mỗi lần (`python main.py detect`), không phải thời gian thực.
- Chống trùng dựa trên hash của dòng log: hai dòng log giống hệt nhau từng ký tự được coi là một event.
- Sysmon chỉ hỗ trợ JSON/JSONL, Event ID 1, 3, 11. Suricata chỉ hỗ trợ alert, dns, http, flow.
- Rule dựa trên ngưỡng nên bỏ sót tấn công chậm (low-and-slow), password spraying từ nhiều IP, và kết nối qua NAT; xem [docs/detection_rules.md](docs/detection_rules.md).
- Khi đổi ngưỡng rule, alert cũ trong database không tự bị xóa.
- Dashboard không có đăng nhập hay phân quyền. `python main.py dashboard` và `.streamlit/config.toml` giới hạn nó ở `127.0.0.1`; nếu tự chạy `streamlit run` từ thư mục khác, hãy thêm `--server.address 127.0.0.1`.
- SQLite chỉ cho một tiến trình ghi tại một thời điểm.
- Detection quét lại toàn bộ dữ liệu mỗi lần chạy: thời gian tăng theo tổng số event (khoảng 7 giây ở 1,3 triệu event trong soak test 30 phút).
