# Kế hoạch triển khai

## 1. Hiện trạng repository khi bắt đầu

Thư mục `DoAnSOC` trống hoàn toàn (không có source, README, requirements, database). Vì vậy toàn bộ dự án được khởi tạo từ đầu; không có module nào cần giữ lại hay sửa.

| Hạng mục | Trạng thái ban đầu |
|---|---|
| Module đã tồn tại | Không có |
| Module cần sửa | Không có |
| Module cần xây dựng | Tất cả (bảng bên dưới) |

## 2. Kiến trúc

Pipeline một chiều, mỗi tầng một package:

```
ingestors/ -> normalizer/ -> storage/ -> engine/rules -> engine/correlation -> engine/incident_manager -> ui/ + reporting.py
```

`pipeline.py` điều phối; `config.py` giữ mọi cấu hình; `main.py` là CLI.

## 3. Module và phụ thuộc

| Module | Trách nhiệm | Phụ thuộc vào |
|---|---|---|
| `config.py` | Cấu hình tập trung, override bằng JSON và biến môi trường | (không) |
| `ingestors/base.py` | Đọc dòng có giới hạn độ dài, kiểm tra đường dẫn đầu vào | (không) |
| `ingestors/linux_auth.py`, `suricata.py`, `sysmon.py` | Parse cú pháp từng dòng | `ingestors/base` |
| `normalizer/models.py` | Unified Event Schema, chuẩn hóa timestamp/IP/port | (không) |
| `normalizer/*_normalizer.py` | Chuyển bản ghi đã parse thành `UnifiedEvent` | `models` |
| `storage/schema.sql`, `database.py` | Schema, kết nối, transaction | (không) |
| `storage/repository.py` | Toàn bộ câu SQL (parameterized) | `database`, `models` |
| `engine/rules/*` | 4 detection rule | `config`, `repository` (rule 4) |
| `engine/rule_engine.py` | Đăng ký và chạy rule | `rules` |
| `engine/correlation.py` | Lưu alert, fingerprint, dedup | `repository` |
| `engine/incident_manager.py` | Gộp alert thành incident, vòng đời | `repository` |
| `pipeline.py` | `ingest_file`, `run_detection` | tất cả tầng trên |
| `reporting.py` | Báo cáo Markdown | `incident_manager` |
| `ui/data_access.py` | Truy vấn cho dashboard (không phụ thuộc Streamlit) | `repository`, `incident_manager` |
| `ui/dashboard.py`, `ui/pages/*` | Giao diện Streamlit | `data_access` |
| `datasets/` | Sinh dữ liệu tổng hợp + ground truth | (không) |
| `tests/`, `benchmarks/` | Kiểm thử, benchmark, độ chính xác | toàn hệ thống |

## 4. Các giai đoạn và tiến độ

| Phase | Nội dung | Kết quả |
|---|---|---|
| 1 | Kiểm tra repository, lập kế hoạch | Hoàn thành (repository trống) |
| 2 | Nền tảng: cấu hình, logging, cấu trúc thư mục | Hoàn thành |
| 3 | Ingestion và normalization | Hoàn thành, 127 test |
| 4 | Database và repository | Hoàn thành, 14 test |
| 5 | Detection (4 rule) và correlation | Hoàn thành, 75 test |
| 6 | Incident management và dedup | Hoàn thành, 21 test |
| 7 | Dashboard và investigation | Code hoàn thành; chưa chạy bằng Streamlit thật |
| 8 | Dataset, ground truth, test e2e/bảo mật | Hoàn thành |
| 9 | Benchmark và tối ưu | Hoàn thành (10K / 100K / 500K) |
| 10 | Tài liệu và kiểm chứng cuối | Hoàn thành |

## 5. Giả định đã chọn (khi yêu cầu chưa quy định)

1. **Thang severity** 1-5: 1 INFO, 2 LOW, 3 MEDIUM, 4 HIGH, 5 CRITICAL. Severity Suricata 1/2/3 ánh xạ thành 4/3/2.
2. **event_id** là 32 ký tự đầu của SHA-256 trên `source_type + dòng log`. Nhờ đó nhập lại cùng dữ liệu là idempotent. Hệ quả: hai dòng log giống hệt nhau chỉ lưu một lần.
3. **Giá trị có mặt nhưng sai** (IP không hợp lệ, port ngoài 0-65535, timestamp sai) làm cả event bị từ chối và lưu lý do. **Trường tùy chọn bị thiếu** thì để `null`. Không tự điền dữ liệu.
4. **Timestamp không có múi giờ** được coi là UTC (Sysmon `UtcTime`); syslog dùng `syslog_utc_offset_minutes`.
5. **Dòng syslog hợp lệ nhưng không phải sự kiện xác thực** được lưu với action `other` thay vì bị loại.
6. Dòng `Invalid user ...` của sshd lưu với action `invalid_user`, không tính là `failed_login` (sshd ghi thêm một dòng `Failed password for invalid user` cho cùng lần thử).
7. **Detection chạy theo lô**, quét lại toàn bộ event; kết quả được hợp nhất với alert đã có nên chạy lại không sinh trùng.
8. **Incident gộp theo thực thể**: IP nguồn (nếu có), ngược lại là hostname, trong cửa sổ 30 phút.
9. **Incident CLOSED nhận thêm bằng chứng mới cho cùng một alert** thì tự mở lại (ghi lịch sử); **FALSE_POSITIVE** thì giữ nguyên trạng thái và chỉ ghi chú.
10. **File đầu vào** chỉ được đọc trong các thư mục cho phép (`allowed_input_dirs`).
11. Thêm 4 bảng ngoài 6 bảng tối thiểu: `import_batches`, `alert_events`, `incident_history`, `incident_notes`.
12. `raw_event` không lưu lặp trong bảng `events`; nó được dựng lại từ `raw_events.raw_line` khi đọc.

## 6. Tiêu chí nghiệm thu

| # | Tiêu chí | Cách kiểm chứng | Kết quả |
|---|---|---|---|
| 1 | Đọc được 3 nguồn log | `tests/test_ingest.py`, e2e | PASS |
| 2 | Chuẩn hóa được các loại event | `tests/test_normalizers.py` | PASS |
| 3 | Lưu vào SQLite | `tests/test_database.py` | PASS |
| 4 | Search event | `test_search_events_filters_and_pagination` | PASS |
| 5 | 4 detection rule | `tests/test_rules.py` | PASS |
| 6 | Correlate nhiều nguồn | Rule SOC-004, `test_related_alerts_of_same_source_join_one_incident` | PASS |
| 7 | Deduplicate alert | `tests/test_incidents.py` | PASS |
| 8 | Tạo và quản lý incident | `tests/test_incidents.py` | PASS |
| 9 | Dashboard lấy dữ liệu thật | `test_dashboard_data_reflects_database`; chạy Streamlit thật | PARTIAL (chưa chạy Streamlit thật) |
| 10 | Investigation | `test_incident_views_update_note_and_report` | PASS ở tầng dữ liệu; giao diện chưa kiểm tra |
| 11 | Dataset kiểm thử | `datasets/`, `test_full_pipeline_matches_ground_truth` | PASS |
| 12 | Unit và integration test | `python -m pytest` | PASS (375 passed, 5 skipped) |
| 13 | Benchmark có kết quả thật | `benchmarks/results/` | PASS |
| 14 | README đầy đủ | `README.md` | PASS |
| 15 | Hướng dẫn chạy từ đầu đến cuối | README mục 5-9, `test_cli_run_sample_as_subprocess` | PASS |

> Ghi chú 2026-11-14: thư mục `ingest/` đã đổi tên thành `ingestors/` và có thêm `storage/models.py`; xem `SPEC_COMPLIANCE.md`.
