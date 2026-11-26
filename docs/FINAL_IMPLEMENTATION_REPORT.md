# Báo cáo triển khai cuối cùng — Multi-Source SOC Analyst Toolkit

Ngày: 2026-11-13. Môi trường phát triển và kiểm thử: Linux x86_64 (máy ảo, 2 vCPU, 7,8 GB RAM), Python 3.13.18, SQLite 3.53.1.

## 0c. Cập nhật 2026-11-16: giám sát website (nguồn thứ 4 + SOC-005)

- Nguồn mới `web_access`: access log nginx/Apache (combined, common), `ingestors/web_access.py` + `normalizer/web_normalizer.py`. Unified Event Schema lên phiên bản 2 (thêm `url`, `http_status`, `user_agent`; database cũ được migration tự động).
- Rule mới **SOC-005 Web Attack** (`engine/rules/web_attack.py`): SQL injection, XSS, path traversal, command injection (cả Log4Shell trong User-Agent), công cụ quét, dò file nhạy cảm, lỗi 4xx dồn dập. HIGH khi request tấn công được trả 2xx.
- Dữ liệu mẫu thêm S24-S27: 1224 dòng, 1212 event, 14 alert, 12 incident, giảm nhiễu 42,9%. S27 cho thấy kẻ dò SSH và tấn công web cùng IP được gộp vào một incident.
- Accuracy: SOC-005 precision 0,778, recall 0,778 trên 70 kịch bản (có ca khó cố ý: POST body, dò chậm, tìm kiếm chữ "union select", kiểm tra link chết).
- Fuzz tìm ra WEB-01 (OverflowError), đã sửa; WEB-02 (ReDoS) sửa khi phát triển. 438 passed, 6 skipped.

## 0b. Cập nhật 2026-11-16: đơn giản hóa code, chế độ giám sát liên tục

- Viết lại các file khó đọc nhất cho dễ hiểu với sinh viên năm 2, không đổi hành vi (cùng bộ test): `engine/rules/base.py`, 4 rule, `engine/correlation.py`, `pipeline.py`, `ingestors/linux_auth.py`. Bỏ `itertools.groupby`, `bisect`, `Counter`, `defaultdict`, toán tử `:=`, hàm lồng nhau; rule trả về `list` thay vì generator; tách hàm dài thành các bước có tên; docstring tiếng Việt giải thích cách rule làm việc.
- Lệnh mới `watch`: theo dõi liên tục file log trên máy chủ thật, chỉ đọc phần mới, chịu được logrotate và dòng ghi dở.
- SOC-003 thêm dấu hiệu webshell (`web_server_spawned_shell`).
- Tài liệu mới: `docs/HOW_IT_WORKS.md`, `docs/deploy_web_server.md`.
- 416 passed, 6 skipped. Accuracy không đổi. Benchmark 500K event: 29,2 giây (`benchmark_after_simplify.md`, trước đó 21,1 giây trên cùng loại máy; phần lớn chênh lệch nằm ở bước ghi database, phần code không bị sửa, nên chủ yếu do máy đo dao động).

## 0. Cập nhật 2026-11-14: sửa đồ án cho khớp đề bài (CHỦ ĐỀ 08)

Đối chiếu từng yêu cầu của đề: [SPEC_COMPLIANCE.md](SPEC_COMPLIANCE.md). Các thay đổi chính:

- **SOC-004** viết lại theo đúng nghĩa của đề (lateral movement): IP nội bộ bị Suricata cảnh báo mức cao, sau đó chính IP đó kết nối tới máy nội bộ khác (Sysmon) trong 5 phút.
- **SOC-001**: `followup_seconds` = 60 giây; thêm chế độ đúng nguyên văn đề (`require_followup`), evidence `matches_assignment_condition`.
- **SOC-003**: thêm dấu hiệu chạy từ `AppData` (Roaming/Local/LocalLow).
- **Dedup**: cooldown 600 giây; `occurrence_count` = số detection đã gộp; chỉ số giảm nhiễu raw alerts -> alert -> incident (`stats`, Overview, `DetectionSummary.dedup`).
- **Incident**: trường `assigned_analyst`, lệnh `assign`, lọc theo analyst, migration tự động cho DB cũ.
- **Cấu trúc**: `ingest/` đổi tên thành `ingestors/`; thêm `storage/models.py`.
- **Linux auth**: parse `sudo` và `pam_unix ... authentication failure`.
- **Dashboard**: 6 trang; Overview có chỉ số giảm nhiễu, Top Attacked Assets, Incident Timeline dạng Gantt; Investigation có timeline tương tác; Incidents có giao analyst; trang mới Upload Logs. CLI có `ingest --trust-path --detect` cho log lạ lúc demo.
- **Dataset**: 23 kịch bản (thêm S18-S23: alert severity thấp, SSH lặp lại để kiểm tra cooldown, scan + brute force cùng IP gộp một incident, beacon từ AppData, sudo). 1007 dòng -> 997 event, 10 bị từ chối, 11 alert, 10 incident, giảm nhiễu 44,4%.
- **Kiểm thử**: 411 passed, 6 skipped (AppTest cần Streamlit). Accuracy 275 kịch bản; benchmark 10K/100K/500K: 0 lỗi; soak 2 phút và fuzz: không lỗi.

Các mục dưới đây là báo cáo gốc ngày 2026-11-13; số liệu mới nhất xem mục 0 và các tài liệu liên quan.

## 1. Kết luận ngắn

Pipeline từ log thô đến incident đã được xây dựng, chạy thật và khớp với ground truth của bộ dữ liệu mẫu. 375 test chạy đạt, 5 test bị bỏ qua vì môi trường không có Streamlit. Benchmark đã chạy ở cả ba mức 10K / 100K / 500K event; soak test 10 phút và 30 phút không lỗi. Kết quả audit độ ổn định (audit lại ngày 2026-11-14, tìm và sửa thêm 2 lỗi HIGH bằng fuzz testing): `docs/stability_test_report.md`; danh sách lỗi: `docs/BUG_FIX_LOG.md`.

**Dự án chưa hoàn thành 100%.** Hai hạng mục chưa được kiểm chứng:

1. Dashboard chưa được chạy bằng Streamlit thật (không cài được `streamlit` và `plotly` trong môi trường phát triển). *Cập nhật: người dùng đã chạy `run-sample` và dashboard thật trên Windows; các trang mới của bản 2026-11-14 cần mở lại để kiểm tra hiển thị.*
2. Chưa chạy thử trên Windows, là hệ điều hành của máy đích. *Cập nhật: `run-sample` đã chạy được trên Windows.*

## 2. Trạng thái theo tiêu chí nghiệm thu

| # | Tiêu chí | Trạng thái | Bằng chứng |
|---|---|---|---|
| 1 | Đọc 3 nguồn log | PASS | `tests/test_ingest.py` (45 test), e2e |
| 2 | Chuẩn hóa event | PASS | `tests/test_normalizers.py` (82 test) |
| 3 | Lưu vào SQLite | PASS | `tests/test_database.py` (14 test) |
| 4 | Search event | PASS | Tìm theo IP, thời gian, severity, nguồn, văn bản; phân trang |
| 5 | 4 detection rule | PASS | `tests/test_rules.py` (75 test) |
| 6 | Correlate nhiều nguồn | PASS | SOC-004 (Suricata + Sysmon); alert khác rule cùng IP vào một incident |
| 7 | Deduplicate alert | PASS | Chạy lại detection và nhập lại file không sinh trùng |
| 8 | Tạo và quản lý incident | PASS | `tests/test_incidents.py` (21 test) |
| 9 | Dashboard lấy dữ liệu thật | PARTIAL | Lớp truy vấn và logic trang đã test; chưa chạy Streamlit thật |
| 10 | Investigation | PARTIAL | Timeline, evidence, ghi chú, báo cáo đã test ở tầng dữ liệu; giao diện chưa kiểm tra |
| 11 | Dataset kiểm thử | PASS | 17 kịch bản có nhãn, 931 dòng |
| 12 | Unit và integration test | PASS | 375 passed, 5 skipped |
| 13 | Benchmark thật | PASS | `benchmarks/results/` |
| 14 | README | PASS | Đủ 12 mục |
| 15 | Hướng dẫn chạy từ đầu đến cuối | PASS trên Linux | `test_cli_run_sample_as_subprocess`; NOT TESTED trên Windows |

## 3. Chức năng đã hoàn thiện

- **Ingestion**: Linux auth (failed / successful login, invalid user, account lockout, dòng syslog khác; timestamp có hoặc không có năm), Suricata EVE (alert, dns, http, flow), Sysmon JSON/JSONL (Event ID 1, 3, 11; bốn kiểu bố cục JSON). Đọc theo dòng, giới hạn độ dài dòng, dòng lỗi được lưu kèm lý do và không làm dừng pipeline.
- **Normalization**: Unified Event Schema phiên bản 1; timestamp về UTC; kiểm tra IP và port; phân biệt trường thiếu với giá trị sai.
- **Database**: 10 bảng, khóa ngoại, CHECK, UNIQUE, index, transaction, repository với SQL tham số hóa, script khởi tạo, cấu hình tập trung.
- **Detection**: rule engine và 4 rule, mỗi rule một module, ngưỡng cấu hình được, có evidence, lý do kết luận và ánh xạ MITRE ATT&CK.
- **Correlation và dedup**: fingerprint, hợp nhất alert giao nhau, `occurrence_count`, gộp alert liên quan theo thực thể.
- **Incident**: 4 trạng thái, lịch sử thay đổi, ghi chú analyst, timeline, tự mở lại khi có bằng chứng mới, incident mới cho đợt mới sau khi đóng.
- **Báo cáo**: Markdown, đã escape dữ liệu lấy từ log.
- **CLI**: `init-db`, `generate-dataset`, `run-sample`, `ingest`, `detect`, `stats`, `incidents`, `update-status`, `report`, `dashboard`.
- **Dashboard**: 5 trang (code hoàn chỉnh, xem mục 8 về mức độ kiểm chứng).

## 4. Kiến trúc cuối cùng

```
DoAnSOC/
├── main.py                  CLI
├── config.py                Cấu hình tập trung
├── logging_setup.py
├── pipeline.py              ingest_file, run_detection
├── reporting.py             Báo cáo incident
├── ingestors/               base.py, linux_auth.py, suricata.py, sysmon.py
├── normalizer/              models.py, linux_normalizer.py, suricata_normalizer.py, sysmon_normalizer.py
├── storage/                 schema.sql, database.py, models.py, repository.py
├── engine/                  rule_engine.py, correlation.py, incident_manager.py
│   └── rules/               base.py, ssh_bruteforce.py, port_scan.py, suspicious_process.py, network_host_pivot.py
├── ui/                      dashboard.py, common.py, data_access.py
│   └── pages/               1_Events.py, 2_Alerts.py, 3_Incidents.py, 4_Investigation.py, 5_Upload_Logs.py
├── datasets/                synth.py, generate_dataset.py, raw/, ground_truth/
├── benchmarks/              run_benchmark.py, evaluate_accuracy.py, soak_test.py, leak_check.py, fuzz_test.py, results/
├── tests/                   10 file test + conftest.py
├── docs/                    9 tài liệu
├── config/settings.example.json
├── requirements.txt, pytest.ini, .gitignore, README.md
```

Không có file nào được sửa hay xóa từ trạng thái ban đầu vì thư mục dự án trống; tất cả file trên đều là file mới.

## 5. Detection rules

Số lượng: **4**.

| Rule ID | Tên | Điều kiện mặc định | Severity |
|---|---|---|---|
| SOC-001 | SSH Brute Force | >= 5 lần thất bại, cùng IP và host, trong 60 giây | 3; 4 nếu khóa tài khoản; 5 nếu sau đó đăng nhập thành công |
| SOC-002 | Internal Port Scan | >= 15 cổng đích khác nhau, cùng IP nguồn và đích, trong 30 giây | 3 |
| SOC-003 | Suspicious Process Execution | Điểm dấu hiệu >= 2 (vị trí, command line, parent) | 2-5 theo điểm |
| SOC-004 | Network-to-Host Pivot | Suricata alert HIGH vào IP nội bộ, sau đó IP đó kết nối tới máy nội bộ khác (Sysmon Event ID 3) trong <= 300 giây | 4; 5 nếu >= 3 máy |

## 6. Kết quả test

Lệnh: `python -m pytest` — **375 passed, 5 skipped, 0 failed** (khoảng 7 giây). Trên Python 3.11 và 3.12, 237 test không cần pandas cũng đạt.

| File | Passed | Skipped |
|---|---:|---:|
| `test_ingest.py` | 45 | 0 |
| `test_normalizers.py` | 82 | 0 |
| `test_database.py` | 14 | 0 |
| `test_rules.py` | 75 | 0 |
| `test_incidents.py` | 21 | 0 |
| `test_pipeline_e2e.py` | 19 | 0 |
| `test_security.py` | 33 | 0 |
| `test_audit_regression.py` | 26 | 0 |
| `test_dashboard.py` | 16 | 5 |
| `test_config_cli.py` | 44 | 0 |

5 test bị bỏ qua là `test_pages_with_real_streamlit_apptest` (một test cho mỗi trang); chúng cần `streamlit` và `plotly`.

End-to-end với dữ liệu mẫu (`python main.py run-sample`): 931 dòng -> 921 event, 10 dòng bị từ chối, 7 alert (SOC-001: 3, SOC-002: 1, SOC-003: 2, SOC-004: 1), 7 incident; đúng với `datasets/ground_truth/scenarios.json` ở cả 17 kịch bản. `PRAGMA integrity_check` = ok, `foreign_key_check` không có vi phạm.

## 7. Kết quả benchmark

Chi tiết và phương pháp: [benchmark_report.md](benchmark_report.md).

| Events | Tổng thời gian (s) | Events/s | Detection (s) | Peak RSS (MB) | Alerts | Incidents | Errors |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10.000 | 0,357 | 28.013 | 0,022 | 41,3 | 4 | 4 | 0 |
| 100.000 | 3,883 | 25.756 | 0,273 | 121,4 | 40 | 40 | 0 |
| 500.000 | 23,637 | 21.153 | 1,297 | 162,1 | 200 | 200 | 0 |

Độ chính xác trên ma trận 255 kịch bản tổng hợp:

| Rule | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SOC-001 | 30 | 5 | 10 | 30 | 0,857 | 0,750 | 0,800 | 0,143 |
| SOC-002 | 25 | 5 | 5 | 20 | 0,833 | 0,833 | 0,833 | 0,200 |
| SOC-003 | 30 | 10 | 10 | 25 | 0,750 | 0,750 | 0,750 | 0,286 |
| SOC-004 | 20 | 5 | 10 | 15 | 0,800 | 0,667 | 0,727 | 0,250 |

Các tỷ lệ này phụ thuộc vào tỷ lệ kịch bản khó trong ma trận và không phải độ chính xác trên dữ liệu thực tế.

## 8. Mức độ kiểm chứng của dashboard

| Hạng mục | Trạng thái |
|---|---|
| Truy vấn dữ liệu của cả 5 trang (`ui/data_access.py`) | PASS |
| Số liệu dashboard khớp database | PASS |
| Script 5 trang chạy với module thay thế Streamlit: DB thiếu, DB hỏng, DB rỗng, có dữ liệu, gửi form | PASS (không kiểm tra hiển thị thật) |
| Chạy bằng Streamlit thật (AppTest) | SKIPPED |
| `streamlit run ui/dashboard.py` và kiểm tra trên trình duyệt | NOT TESTED |
| Biểu đồ Plotly | NOT TESTED |

Rủi ro cụ thể: lời gọi API Streamlit hoặc Plotly có thể sai tham số ở phiên bản bạn cài (ví dụ tham số độ rộng `use_container_width` / `width="stretch"` đã được xử lý theo phiên bản nhưng chưa được chạy thử).

## 9. Lỗi đã phát hiện và sửa trong quá trình phát triển

Danh sách đầy đủ, gồm cả 9 lỗi tìm thấy trong hai đợt audit (AUD-01 đến AUD-09, trong đó AUD-08 và AUD-09 là HIGH): `docs/BUG_FIX_LOG.md`.

| # | Vấn đề | Mức độ | Nguyên nhân | Cách sửa | Kiểm chứng |
|---|---|---|---|---|---|
| 1 | Tốc độ ghi DB giảm mạnh theo kích thước (500K event: 64 giây, 7,8 nghìn event/giây) | MEDIUM | Khóa hash và index phụ làm mỗi transaction nhỏ phải ghi lại phần lớn trang index; có thêm một index UNIQUE thừa | Bỏ cột/index thừa `events.raw_id`, đặt cache 64 MB, tăng `batch_size` lên 20.000 | Benchmark trước/sau: 64,2 -> 34,3 giây cùng điều kiện |
| 2 | Database bị khóa gây lỗi `sqlite3.OperationalError` thô, CLI in traceback | MEDIUM | Không bắt lỗi tại `BEGIN IMMEDIATE` | Chuyển thành `DatabaseError` với thông báo rõ | `test_locked_database_gives_clear_error_and_recovers` |
| 3 | Khi ingest lỗi giữa chừng, việc ghi trạng thái `failed` có thể tự gây lỗi và che mất lỗi gốc | LOW | Ghi trạng thái trong khối `except` không được bảo vệ | Bắt `DatabaseError` riêng, luôn ném lại lỗi gốc | `test_failure_in_the_middle_of_ingestion_keeps_database_consistent` |
| 4 | Dòng từng bị từ chối, sau đó hợp lệ khi nhập lại với cấu hình khác: bộ đếm `new_rejected` âm và `raw_events.status` vẫn là `rejected` | LOW | Bộ đếm suy ra từ hiệu hai số; trạng thái raw không được cập nhật | Chặn bộ đếm ở 0 và đồng bộ lại trạng thái raw sau mỗi lần nhập | `test_line_rejected_under_one_config_can_be_accepted_later` |
| 5 | Tham số `use_container_width` của Streamlit đang bị loại bỏ dần ở phiên bản mới | LOW | Thay đổi API giữa các phiên bản | Chọn tham số theo phiên bản Streamlit (`ui/common.py`) | Chưa kiểm chứng bằng Streamlit thật |
| 6 | In JSON có ký tự ngoài ASCII có thể lỗi trên console Windows | LOW | Console Windows không mặc định UTF-8 | Đặt lại encoding của stdout/stderr trong `main.py` | Chưa kiểm chứng trên Windows |

Ngoài ra có 2 lỗi trong chính code test (một assertion nhắm sai vị trí, một dữ liệu test chứa ký tự xuống dòng) đã được sửa; chúng không phải lỗi của sản phẩm.

## 10. Kiểm tra bảo mật đã thực hiện

| Hạng mục | Kết quả |
|---|---|
| SQL injection qua dữ liệu log (username, signature) và qua bộ lọc tìm kiếm, ghi chú, trạng thái | PASS: mọi truy vấn tham số hóa; tên cột/bảng nội suy đều thuộc danh sách cho phép (có test tĩnh) |
| Ký tự đại diện `%`, `_` trong tìm kiếm | PASS: được so khớp nguyên văn |
| Path traversal (`..`, đường dẫn tuyệt đối, symlink, null byte) | PASS: chỉ đọc trong `allowed_input_dirs` |
| Dữ liệu sai kiểu, JSON lồng sâu, dòng 500.000 ký tự, command line 2 triệu ký tự | PASS: từ chối hoặc cắt ngắn, không treo |
| Secret trong source (mật khẩu, API key, token, private key, URL có thông tin đăng nhập) | PASS: không tìm thấy |
| Log của ứng dụng có chứa nội dung log gốc không | PASS: không chứa |
| Xác thực / phân quyền của dashboard | Không có (ngoài phạm vi). Dashboard chỉ lắng nghe trên 127.0.0.1 (AUD-06) |

## 11. Hạn chế còn tồn tại

1. Dashboard chưa chạy bằng Streamlit thật; biểu đồ chưa được hiển thị thử.
2. Chưa kiểm thử trên Windows. Python 3.11 và 3.12 chỉ chạy được các test không cần pandas (237 test, đạt).
3. Detection chạy theo lô và quét lại toàn bộ event; không có chế độ thời gian thực hay tăng dần.
4. Chống trùng theo hash dòng: các dòng log giống hệt nhau chỉ lưu một lần.
5. Rule dựa trên ngưỡng bỏ sót tấn công chậm, password spraying, kết nối qua NAT, malware ở vị trí bình thường; báo nhầm một số hoạt động quản trị hợp lệ (xem `detection_rules.md`).
6. Đổi ngưỡng rule không tự xóa alert cũ.
7. Incident gộp theo IP nguồn hoặc hostname; chưa có bảng ánh xạ IP - hostname nên alert về cùng một máy nhưng một bên chỉ có IP, một bên chỉ có hostname sẽ không được gộp.
8. Sysmon chỉ nhận JSON/JSONL (không EVTX), Event ID 1, 3, 11. Suricata chỉ nhận 4 loại event.
9. Syslog không có năm và múi giờ phải dựa vào cấu hình.
10. Tìm kiếm văn bản quét toàn bảng. SQLite chỉ có một tiến trình ghi tại một thời điểm.
11. Dashboard không có đăng nhập; mặc định chỉ lắng nghe trên 127.0.0.1.
12. Soak test đã chạy 10 phút và 30 phút trên Linux; chưa chạy 60 phút và chưa chạy trên Windows.
13. Độ chính xác chỉ đo trên dữ liệu tổng hợp.
14. Chưa khởi tạo Git repository (đã có `.gitignore`).

**Phân loại:** ổn định cho mục đích trình diễn học thuật cục bộ trong phạm vi các workload đã test trên Linux; cần kiểm chứng dashboard và Windows trước khi demo; không sẵn sàng cho production.

## 12. Hướng phát triển tiếp theo

- Chạy và sửa dashboard trên máy đích; thêm ảnh chụp màn hình vào tài liệu.
- Detection tăng dần theo watermark thời gian.
- Rule cho password spraying và quét chậm (cửa sổ dài, đếm theo host đích).
- Đọc EVTX trực tiếp; thêm Event ID Sysmon (7, 8, 10, 22).
- Bảng tài sản (IP - hostname) để gộp incident chính xác hơn.
- FTS5 cho tìm kiếm văn bản.
- Xác thực cho dashboard.
- Thử nghiệm với bộ dữ liệu công khai có nhãn.

## 13. Hướng dẫn chạy

```bash
cd DoAnSOC
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python -m pytest                 # 380 test; khi đã cài Streamlit, 5 test AppTest sẽ chạy thay vì skipped
python main.py run-sample        # tạo DB, nhập dữ liệu mẫu, chạy detection
python main.py incidents
python main.py dashboard         # hoặc: streamlit run ui/dashboard.py
python -m benchmarks.run_benchmark
python -m benchmarks.evaluate_accuracy
```

Việc cần làm đầu tiên trên máy của bạn: chạy `python -m pytest` rồi mở dashboard, vì đây là hai phần chưa được kiểm chứng trong môi trường phát triển.
