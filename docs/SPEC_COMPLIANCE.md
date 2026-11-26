# Đối chiếu yêu cầu đề bài (CHỦ ĐỀ 08 — Multi-Source SOC Analyst Toolkit)

Cập nhật: 2026-11-14. Mỗi dòng ghi: yêu cầu của đề -> nơi cài đặt -> test chứng minh -> trạng thái.
Lệnh kiểm chứng toàn bộ: `python -m pytest` (438 passed, 6 skipped vì môi trường phát triển không có Streamlit; trên máy có Streamlit chạy đủ 444).

## 1. Thu thập và chuẩn hóa log

| Yêu cầu | Cài đặt | Test | Trạng thái |
|---|---|---|---|
| Đọc Linux auth.log (SSH thất bại/thành công, sudo) | `ingestors/linux_auth.py`, `normalizer/linux_normalizer.py` (action `failed_login`, `successful_login`, `invalid_user`, `account_lockout`, `sudo_command`, `sudo_auth_failure`, `auth_failure`) | `test_ingest.py::test_linux_sudo_lines`, `test_linux_pam_failure_is_not_a_failed_ssh_login`; `test_normalizers.py::test_linux_sudo_command_normalized`, `test_linux_sudo_failure_normalized` | ĐẠT |
| Đọc Suricata eve.json (alert, dns, http, flow) | `ingestors/suricata.py`, `normalizer/suricata_normalizer.py` | `test_ingest.py`, `test_normalizers.py` | ĐẠT |
| Đọc Windows Sysmon (Event ID 1, 3, 11) | `ingestors/sysmon.py`, `normalizer/sysmon_normalizer.py` (JSON/JSONL đã export, không đọc EVTX) | `test_ingest.py`, `test_normalizers.py` | ĐẠT (giới hạn: không đọc EVTX) |
| Thư mục `ingestors/` | Đổi tên từ `ingest/` | `test_security.py` quét `ingestors/` | ĐẠT |
| Unified Event Schema (timestamp UTC, IP, port, user, host, action, severity) | `normalizer/models.py`; `docs/unified_event_schema.md` | `test_normalizers.py` | ĐẠT |
| Dòng lỗi không làm dừng pipeline | `pipeline.ingest_file` lưu `raw_events.status = 'rejected'` kèm lý do | `test_pipeline_e2e.py`, `benchmarks/fuzz_test.py` | ĐẠT |

## 2. Lưu trữ

| Yêu cầu | Cài đặt | Test | Trạng thái |
|---|---|---|---|
| SQLite, raw + normalized event | `storage/schema.sql`, `storage/database.py`, `storage/repository.py` | `test_database.py` | ĐẠT |
| `storage/models.py` (mô hình Alert/Incident) | `AlertRecord`, `IncidentRecord`, `DedupSummary`, hằng trạng thái/nhãn | `test_incidents.py::test_dedup_summary_*` | ĐẠT |
| Nhập lại không tạo trùng | `raw_id` = hash dòng, `INSERT OR IGNORE` | `test_pipeline_e2e.py`, `test_config_cli.py::test_cli_run_sample_as_subprocess` | ĐẠT |

## 3. Detection rules (4 rule bắt buộc)

| Rule | Điều kiện của đề | Cài đặt | Test | Trạng thái |
|---|---|---|---|---|
| SOC-001 SSH Brute Force | ≥ 5 lần thất bại trong 60 giây, sau đó đăng nhập thành công hoặc bị khóa, cùng IP | `engine/rules/ssh_bruteforce.py`; `followup_seconds` = 60; `require_followup = true` cho chế độ đúng nguyên văn; mặc định còn báo đợt thất bại đơn thuần ở mức MEDIUM | `test_rules.py::test_ssh_strict_assignment_mode_requires_success_or_lockout`, `test_ssh_default_followup_is_60_seconds`, `test_ssh_success_after_brute_force_escalates_to_critical`, `test_ssh_account_lockout_escalates_to_high`, các test ngưỡng 4/5/6 | ĐẠT |
| SOC-002 Port Scan | Một IP quét nhiều cổng trong thời gian ngắn | `engine/rules/port_scan.py` (≥ 15 cổng / 30 giây) | `test_rules.py` (14/15/16 cổng, biên cửa sổ) | ĐẠT |
| SOC-003 Suspicious Process | Tiến trình chạy từ Temp **hoặc AppData**, PowerShell mã hóa, Office sinh shell... | `engine/rules/suspicious_process.py` (thêm `exec_from_appdata`) | `test_rules.py::test_process_scoring` (AppData\Roaming, AppData\LocalLow) | ĐẠT |
| SOC-004 Network-to-Host Pivot | IP nội bộ bị Suricata cảnh báo mức cao, **sau đó** IP này khởi tạo kết nối tới host nội bộ khác (Sysmon) | `engine/rules/network_host_pivot.py` (viết lại: alert severity ≥ 4, kết nối nội bộ trong 300 giây sau alert, bỏ DNS/NTP/NetBIOS, CRITICAL khi ≥ 3 máy) | `test_rules.py::test_pivot_*` (17 test: đúng/sai hướng, ngoài cửa sổ, alert severity thấp, kết nối về lại attacker, host khác, cổng hạ tầng, alert đi ra, sai thứ tự...) | ĐẠT |

## 3b. Mở rộng ngoài đề: giám sát website

| Mở rộng | Cài đặt | Test | Trạng thái |
|---|---|---|---|
| Nguồn thứ 4: access log nginx/Apache | `ingestors/web_access.py`, `normalizer/web_normalizer.py`, cột `url` / `http_status` / `user_agent` | `test_ingest.py::test_web_access_*`, `test_normalizers.py::test_web_access_*` | XONG |
| Rule SOC-005 Web Attack | `engine/rules/web_attack.py` | `test_rules.py::test_web_*` (12 test), accuracy 70 kịch bản | XONG |
| Giám sát liên tục | `main.py watch`, `pipeline.watch_files` | `test_pipeline_e2e.py::test_watch_*`, `test_config_cli.py::test_cli_watch_*` | XONG |

## 4. Correlation, deduplication, incident

| Yêu cầu | Cài đặt | Test | Trạng thái |
|---|---|---|---|
| Gộp cảnh báo trùng (dedup) | `engine/correlation.py`: fingerprint + giao thời gian + cooldown 600 giây; `occurrence_count` = số detection gộp vào | `test_incidents.py::test_cooldown_boundary_is_inclusive`, `test_occurrence_count_is_idempotent_and_independent_of_import_order`; `test_rules.py::test_ssh_two_bursts_within_cooldown_are_one_deduplicated_alert` | ĐẠT |
| Đo hiệu quả dedup | `Repository.dedup_summary()`; `python main.py stats` mục `deduplication`; Overview | `test_incidents.py::test_dedup_summary_counts_raw_alerts_against_incidents`; `test_dashboard.py::test_overview_dedup_assets_and_gantt`; dữ liệu mẫu 21 -> 14 -> 12 (giảm 42,9%) | ĐẠT |
| Gộp alert liên quan thành incident | `engine/incident_manager.py` (cùng thực thể IP/host, trong 30 phút) | `test_rules.py::test_pivot_and_lateral_port_scan_from_same_host_join_one_incident`; kịch bản S20+S21 trong e2e | ĐẠT |
| Vòng đời NEW / IN_PROGRESS / CLOSED / FALSE_POSITIVE, lịch sử | `IncidentManager.update_status`, `incident_history` | `test_incidents.py` | ĐẠT |
| Giao incident cho analyst (`assigned_analyst`) | Cột `incidents.assigned_analyst` (migration tự động), `IncidentManager.assign`, CLI `assign`, lọc `incidents --analyst`, form trên trang Incidents | `test_incidents.py::test_assign_reassign_and_unassign_incident`, `test_old_database_without_assigned_analyst_is_migrated`, `test_assigned_analyst_appears_in_report`; `test_config_cli.py::test_cli_assign_stats_dedup_and_trusted_unseen_log`; `test_dashboard.py::test_assign_incident_and_filter_by_analyst` | ĐẠT |

## 5. Dashboard

| Yêu cầu | Cài đặt | Test | Trạng thái |
|---|---|---|---|
| Tổng quan (event, alert, incident, severity) | `ui/dashboard.py` | `test_dashboard.py` | ĐẠT |
| Top attacked assets | `Repository.top_attacked_assets`, biểu đồ trên Overview | `test_overview_dedup_assets_and_gantt` | ĐẠT |
| Tìm kiếm event | `ui/pages/1_Events.py` | `test_event_search_filters_and_pagination` | ĐẠT |
| Incident timeline tương tác | Overview: Gantt (`px.timeline`); Investigation: scatter theo làn + lọc theo loại | `test_overview_dedup_assets_and_gantt`, `test_incident_timeline_chart_has_lanes`, `test_pages_with_data_render_all_sections` | ĐẠT (logic); cần mở trình duyệt để xem hiển thị |
| Upload log trên dashboard | `ui/pages/5_Upload_Logs.py`, `data_access.ingest_uploaded` (lưu vào `datasets/uploads/`, tên file được làm sạch, giới hạn 50 MB, chạy detection) | `test_ingest_uploaded_saves_imports_and_detects`, `test_safe_upload_name`, `test_upload_page_imports_file` | ĐẠT (logic); cần mở trình duyệt để xem hiển thị |
| Điều tra (alert, event, raw log, ghi chú, báo cáo) | `ui/pages/4_Investigation.py`, `reporting.py` | `test_dashboard.py`, `test_incidents.py` | ĐẠT |

## 6. Dataset, kiểm thử, đánh giá

| Yêu cầu | Cài đặt | Bằng chứng | Trạng thái |
|---|---|---|---|
| Dataset có kịch bản tấn công + bình thường, có ground truth | `datasets/generate_dataset.py` -> `datasets/raw/`, `datasets/ground_truth/scenarios.json`: 23 kịch bản (brute force, scan, process, pivot/lateral movement, beaconing từ AppData, sudo, nhiễu và dòng lỗi) | `test_pipeline_e2e.py::test_full_pipeline_matches_ground_truth` (kiểm tra từng kịch bản, `occurrence_count`, nhóm incident) | ĐẠT |
| Log "lạ" khi demo | `ingest --trust-path --detect`; trang Upload Logs | `test_cli_assign_stats_dedup_and_trusted_unseen_log` | ĐẠT |
| Precision / recall | `benchmarks/evaluate_accuracy.py` (275 kịch bản, có ca khó) | `benchmarks/results/accuracy_results.md` | ĐẠT |
| Hiệu năng | `benchmarks/run_benchmark.py` (10K / 100K / 500K) | `benchmarks/results/benchmark_results.md`; 0 lỗi | ĐẠT |

## 7. Còn hạn chế

- Sysmon chỉ đọc JSON/JSONL đã export, không đọc EVTX.
- Detection chạy theo lô (`detect` hoặc sau khi upload), không thời gian thực.
- Beaconing (S22) được phát hiện qua tiến trình chạy từ AppData (SOC-003); chưa có rule riêng phát hiện chu kỳ kết nối đều đặn (ngoài 4 rule bắt buộc).
- Hiển thị của các phần dashboard mới cần được mở bằng Streamlit thật trên máy có cài `streamlit`/`plotly`.
