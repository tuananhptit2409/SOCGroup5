# Chiến lược kiểm thử

## 1. Nguyên tắc

- Mỗi test dùng database tạm và thư mục đầu vào tạm riêng (`tests/conftest.py`); không test nào đụng tới `data/soc.db`.
- Dữ liệu test được sinh bằng `datasets/synth.py` (IP private hoặc dải tài liệu RFC5737). Không có kết nối mạng, không chạy mã độc.
- Rule được test cả trường hợp phải phát hiện, không được phát hiện, và giá trị biên.
- Kết quả pipeline được so với ground truth, không chỉ kiểm tra "chạy không lỗi".

## 2. Chạy test

```bash
python -m pytest                      # toàn bộ
python -m pytest tests/test_rules.py  # một file
python -m pytest -k pivot -v          # theo từ khóa
```

## 3. Phân loại

| File | Loại | Số test | Nội dung |
|---|---|---:|---|
| `test_ingest.py` | Unit | 53 | 3 parser (cả sudo / PAM); file rỗng, CRLF, BOM, UTF-8 hỏng, dòng quá dài; kiểm tra đường dẫn (traversal, symlink, null byte) |
| `test_normalizers.py` | Unit | 92 | Timestamp nhiều định dạng và múi giờ, năm của syslog, IP/port hợp lệ và không hợp lệ, trường bắt buộc / tùy chọn, ánh xạ severity |
| `test_database.py` | Integration | 14 | Schema, PRAGMA, khóa ngoại, CHECK, UNIQUE, rollback, tìm kiếm và phân trang, index (`EXPLAIN QUERY PLAN`), mở lại DB, cascade |
| `test_rules.py` | Unit + integration | 101 | 5 rule (SOC-005: từng loại payload, mã hóa 2 lớp, Log4Shell trong User-Agent, duyệt web bình thường không báo, biên 20 lỗi / 60 giây, chia đợt + cooldown, gộp incident với SSH), 4 rule của đề (SOC-004 theo nghĩa lateral movement, SSH chế độ đúng đề, AppData): ngưỡng 4/5/6 và 14/15/16, biên cửa sổ thời gian, nhiều IP, nhiều host, sai thứ tự, trùng lặp, cấu hình ngưỡng, thiếu trường |
| `test_incidents.py` | Integration | 30 | Dedup (cả cooldown 600 giây, `occurrence_count` không tăng khi chạy lại), chỉ số giảm nhiễu, giao analyst, migration, alert cập nhật, hợp nhất alert, alert liên quan, vòng đời, mở lại, đợt mới sau khi đóng, ghi chú, timeline, báo cáo |
| `test_pipeline_e2e.py` | End-to-end | 21 | So với ground truth, chế độ watch (chỉ đọc phần mới, dòng ghi dở, logrotate), quan hệ alert-incident-evidence, nhập hai lần, nhập sai thứ tự, nhập từng phần, DB bị khóa, lỗi giữa chừng, rule lỗi, khởi động lại |
| `test_security.py` | Security | 33 | SQL injection (dữ liệu log và bộ lọc tìm kiếm), path traversal, kiểu dữ liệu bất thường, giá trị quá dài, quét secret trong source, log không chứa dữ liệu gốc |
| `test_dashboard.py` | Integration + smoke | 22 (+6 cần Streamlit) | Lớp truy vấn của dashboard (chỉ số dedup, Top Attacked Assets, Gantt, timeline, giao analyst, upload log); chạy 6 trang với stand-in của Streamlit; 6 test AppTest chạy khi có Streamlit |
| `test_config_cli.py` | Smoke + integration | 46 | Cấu hình hợp lệ / lỗi, import mọi module, CLI đầy đủ (cả `assign`, `stats` dedup, `ingest --trust-path --detect`), chạy `run-sample` trong tiến trình con hai lần |
| `test_audit_regression.py` | Regression | 26 | Lỗi tìm thấy trong hai đợt audit (29/2, IPv4-mapped, tham số Streamlit, localhost, thông báo thiếu Streamlit, `NaN`/`Infinity`, surrogate lẻ, lỗi bất ngờ của parser), 3 tiến trình ghi đồng thời, fuzz rút gọn |
| **Tổng** | | **438 (+6)** | |

## 4. Ground truth

`datasets/generate_dataset.py` sinh dữ liệu mẫu cố định (seed 42) và `datasets/ground_truth/scenarios.json`. Mỗi kịch bản có: Scenario ID, mô tả, số event đầu vào, hành vi mong đợi, alert mong đợi (rule), severity mong đợi, incident mong đợi, thực thể.

| ID | Kịch bản | Mong đợi |
|---|---|---|
| S01 | 6 lần SSH thất bại trong 40 giây | SOC-001, severity 3 |
| S02 | 8 lần thất bại rồi đăng nhập thành công | SOC-001, severity 5 |
| S03 | 6 lần thất bại rồi khóa tài khoản | SOC-001, severity 4 |
| S04 | 4 lần thất bại (dưới ngưỡng) | Không alert |
| S05 | 5 lần thất bại trong 10 phút (ngoài cửa sổ) | Không alert |
| S06 | Một lần đăng nhập thành công | Không alert |
| S07 | 25 cổng trong 20 giây | SOC-002, severity 3 |
| S08 | 14 cổng (dưới ngưỡng) | Không alert |
| S09 | 20 cổng, mỗi 40 giây một cổng | Không alert |
| S10 | Office sinh PowerShell ẩn, mã hóa | SOC-003, severity 5 |
| S11 | File lạ chạy từ AppData Temp | SOC-003, severity 2 (xem xét) |
| S12 | Trình cài đặt trong Temp do msiexec chạy | Không alert |
| S13 | Tiến trình bình thường trong Program Files | Không alert |
| S14 | Suricata alert HIGH vào 10.0.0.30, sau đó WS02 (10.0.0.30) kết nối 10.0.0.40:445 và 10.0.0.41:3389 | SOC-004, severity 4 |
| S15 | Suricata alert HIGH, host không có kết nối nội bộ | Không alert |
| S16 | Alert HIGH, kết nối nội bộ sau 20 phút | Không alert |
| S17 | 12 dòng lỗi / không hỗ trợ ở cả bốn nguồn | Bị từ chối kèm lý do; pipeline vẫn chạy |
| S18 | Alert severity thấp rồi kết nối nội bộ | Không alert |
| S19 | 4 đợt SSH brute force (6 lần mỗi đợt), cách nhau 3 phút | **1** alert SOC-001, `occurrence_count = 4` (cooldown dedup) |
| S20 + S21 | 10.0.0.61 quét 20 cổng của 10.0.0.25, rồi brute force SSH vào db02 | 2 alert (SOC-002, SOC-001) gộp vào **một** incident |
| S22 | `updater.exe` chạy từ `AppData\Roaming` trên WS07 và beacon đều đặn tới 198.51.100.66:443 | SOC-003, severity 2 |
| S23 | Dòng sudo hợp lệ trên web01 | Parse thành `sudo_command`, không alert |

| S24 | sqlmap thử SQL injection vào web01, một payload được trả 200 | SOC-005, severity 4 |
| S25 | Dò thư mục: 40 request trong 40 giây, 38 lỗi 404 | SOC-005, severity 3 |
| S26 | Một bot dò `/.env`, một người dùng gặp 5 ảnh lỗi 404 | Không alert |
| S27 | Kẻ dò SSH của S01 thử path traversal trên website | SOC-005, severity 3, **cùng incident với S01** |

Tổng mong đợi: 1224 dòng (4 file), 1212 event, 12 dòng bị từ chối, 14 alert (SOC-001: 5, SOC-002: 2, SOC-003: 3, SOC-004: 1, SOC-005: 3), 12 incident; 17 detection thô + 4 Suricata alert = 21 raw alerts, giảm 42,9%. `test_full_pipeline_matches_ground_truth` kiểm tra từng con số, từng kịch bản, `occurrence_count` và nhóm incident (`incident_group`).

## 5. Kiểm thử dashboard: ba mức

| Mức | Cách làm | Trạng thái |
|---|---|---|
| 1. Lớp dữ liệu (`ui/data_access.py`) | Gọi trực tiếp các hàm mà trang dùng, so với database | Đã chạy, PASS |
| 2. Script của 6 trang | Chạy bằng `runpy` với module `streamlit`/`plotly` thay thế (ghi lại lời gọi, trả giá trị mặc định cho widget). Bao gồm: DB thiếu, DB hỏng, DB rỗng, có dữ liệu, gửi form | Đã chạy, PASS. Mức này **không** kiểm tra việc hiển thị thật |
| 3. Streamlit thật | `streamlit.testing.v1.AppTest` cho từng trang | **SKIPPED** trong môi trường phát triển (không có Streamlit). Chạy được sau `pip install -r requirements.txt` |
| 4. Kiểm tra bằng mắt trên trình duyệt | Thủ công | **CHƯA THỰC HIỆN** |

## 6. Fuzz testing

`python -m benchmarks.fuzz_test` lấy dòng hợp lệ trong `datasets/raw`, làm hỏng ngẫu nhiên (sửa ký tự, cắt, lặp; với JSON thì thay giá trị bằng `NaN`, `Infinity`, surrogate lẻ, số rất lớn, cấu trúc lồng nhau, ...) và kiểm tra:

- parser và normalizer chỉ ném `ParseError` / `NormalizationError`, không lời gọi nào chậm hơn 0,2 giây;
- 12 đầu vào đối kháng dài 65.536 ký tự không làm regex chậm (ReDoS);
- nhập cả file dòng đột biến luôn hoàn tất, detection không lỗi, database qua integrity check.

Fuzz testing tìm ra AUD-08 và AUD-09, hai lỗi HIGH mà 361 test viết tay không phát hiện. Một bản rút gọn chạy trong mỗi lần `pytest`.

## 7. Benchmark và độ chính xác

- `python -m benchmarks.run_benchmark`: sinh 10.000 / 100.000 / 500.000 event tổng hợp, đo thời gian từng giai đoạn, tốc độ, bộ nhớ, và tự kiểm tra số alert/incident so với số tấn công đã chèn.
- `python -m benchmarks.evaluate_accuracy`: ma trận 345 kịch bản có nhãn, tính TP/FP/FN/TN, precision, recall, F1, FPR cho từng rule.

Kết quả: `docs/benchmark_report.md` và `benchmarks/results/`.

## 8. Chưa được kiểm thử

- Bộ test đầy đủ trên Windows (dashboard đã chạy thật trên Windows; test tự động chạy trên Linux, Python 3.13).
- Hiển thị bằng trình duyệt các tính năng dashboard mới (Upload Logs, Gantt, timeline tương tác, giao analyst).
- Soak test 60 phút (đã chạy 10 và 30 phút: `python -m benchmarks.soak_test --minutes 30`).
- Ghi đồng thời với tải lớn (đã test 3 tiến trình, 12.000 event).
- Dữ liệu log thật từ hệ thống thật.
- File EVTX (không hỗ trợ).
