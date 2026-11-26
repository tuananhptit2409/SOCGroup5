# Bug fix log

Mọi lỗi tìm thấy trong quá trình phát triển (DEV) và trong đợt audit độ ổn định (AUD), kể cả lỗi chỉ nằm trong code test. Mức độ theo thang của audit: CRITICAL / HIGH / MEDIUM / LOW.

Tổng: 15 mục DEV/AUD gồm **2 HIGH** (AUD-08, AUD-09, tìm thấy trong lần audit lại ngày 2026-11-14 bằng fuzz testing), 3 MEDIUM (DEV-01, DEV-02, AUD-06) và 10 LOW; trong đó AUD-01 và AUD-02 chỉ ảnh hưởng bộ test. Ngoài ra có 3 lỗi do chính code test viết sai (TST-01 đến TST-03). Không có lỗi CRITICAL.

Lần audit đầu (2026-11-13) đã kết luận "không có lỗi HIGH". Kết luận đó sai: AUD-08 và AUD-09 đã tồn tại từ đầu nhưng các test viết tay không chạm tới loại đầu vào này.

## Tóm tắt

| ID | Mức độ | Phần | Tóm tắt | Trạng thái |
|---|---|---|---|---|
| DEV-01 | MEDIUM | Storage | Tốc độ ghi DB giảm mạnh khi dữ liệu lớn | Đã sửa, đã đo lại |
| DEV-02 | MEDIUM | Storage | DB bị khóa trả về lỗi SQLite thô và traceback | Đã sửa, có test |
| DEV-03 | LOW | Pipeline | Lỗi khi ghi trạng thái `failed` có thể che lỗi gốc | Đã sửa, có test |
| DEV-04 | LOW | Pipeline | Bộ đếm `new_rejected` âm, trạng thái raw sai khi nhập lại | Đã sửa, có test |
| DEV-05 | LOW | Dashboard | Tham số `use_container_width` của Streamlit bị loại bỏ dần | Thay bằng AUD-03 |
| DEV-06 | LOW | CLI | In JSON tiếng Việt có thể lỗi trên console Windows | Đã sửa, chưa kiểm chứng trên Windows |
| AUD-01 | LOW (test) | Tests | Một test chắc chắn fail khi project nằm trong `C:\Users\PC\...` | Đã sửa |
| AUD-02 | LOW (test) | Tests | Hai test quét source quét luôn `.venv` trong project | Đã sửa, có test |
| AUD-03 | LOW | Dashboard | Chọn tham số độ rộng theo số phiên bản đoán | Đã sửa, có test |
| AUD-04 | LOW | Normalization | Log syslog ngày 29/2 bị từ chối khi suy ra năm | Đã sửa, có test |
| AUD-05 | LOW | Normalization / SOC-004 | Địa chỉ IPv4-mapped IPv6 không khớp với IPv4 khi correlate | Đã sửa, có test |
| AUD-06 | MEDIUM | Dashboard / Security | Dashboard không có đăng nhập nhưng lắng nghe trên mọi network interface | Đã sửa, có test |
| AUD-07 | LOW | CLI | `main.py dashboard` khi chưa cài Streamlit chỉ in `No module named streamlit` | Đã sửa, có test |
| AUD-08 | HIGH | Ingestion | Một dòng JSON chứa `NaN`/`Infinity` làm hủy cả lần import | Đã sửa, có test |
| AUD-09 | HIGH | Ingestion / Storage | Một dòng JSON chứa escape surrogate lẻ (`\ud800`) làm hủy cả lần import | Đã sửa, có test |
| TST-01 | - | Tests | Assertion của test báo cáo kiểm tra sai vùng văn bản | Đã sửa test |
| TST-02 | - | Tests | Dữ liệu test chứa ký tự xuống dòng làm parser từ chối | Đã sửa test |
| TST-03 | - | Tests | Test mới cho AUD-09 truy vấn cột `events.raw_id` đã bị bỏ ở DEV-01 | Đã sửa test |

## Chi tiết

### DEV-01 — Ghi DB chậm dần theo kích thước (MEDIUM, Performance)

- **Hiện tượng:** benchmark đầu tiên: 10K event 24,6 nghìn event/s nhưng 500K event chỉ còn 7,8 nghìn event/s; ghi DB chiếm 84% thời gian (53,7/64,2 giây).
- **Nguyên nhân:** khóa chính là hash (thứ tự ngẫu nhiên) cộng 7 index phụ; với transaction 5.000 dòng, mỗi lần commit phải ghi lại phần lớn trang lá của các index. Ngoài ra bảng `events` có thêm cột `raw_id` UNIQUE trùng giá trị với `event_id`.
- **Sửa:** bỏ cột và index thừa (`event_id` trở thành khóa ngoại tới `raw_events`), `cache_size` 64 MB, `temp_store = MEMORY`, `batch_size` mặc định 20.000. Đã thử và loại bỏ các phương án không hiệu quả (cache 256 MB, checkpoint WAL lớn) hoặc làm yếu ràng buộc (tắt khóa ngoại).
- **Kiểm chứng:** benchmark lại cùng điều kiện, 500K event: 64,2 -> 34,3 giây. Đánh đổi: peak RSS 45 -> 161 MB. Chi tiết: `docs/benchmark_report.md` mục 4.

### DEV-02 — DB bị khóa trả về lỗi thô (MEDIUM, Reliability)

- **Hiện tượng:** khi một tiến trình khác giữ khóa ghi lâu hơn `busy_timeout`, `BEGIN IMMEDIATE` ném `sqlite3.OperationalError: database is locked`, CLI in traceback.
- **Sửa:** `Database.transaction()` chuyển lỗi này thành `DatabaseError("... database busy or locked ...")`; CLI in một dòng `ERROR:` và trả mã 2.
- **Kiểm chứng:** `tests/test_pipeline_e2e.py::test_locked_database_gives_clear_error_and_recovers` (lỗi rõ ràng, người đọc vẫn đọc được trong lúc khóa, ghi lại thành công sau khi khóa được nhả, integrity ok).

### DEV-03 — Lỗi gốc của ingest có thể bị che (LOW)

- **Hiện tượng:** khi ingest lỗi giữa chừng, khối `except` ghi trạng thái batch `failed`; nếu chính thao tác này lỗi (DB bị khóa) thì lỗi mới thay thế lỗi gốc.
- **Sửa:** bọc việc ghi trạng thái, ghi log nếu thất bại, luôn ném lại lỗi gốc.
- **Kiểm chứng:** `test_failure_in_the_middle_of_ingestion_keeps_database_consistent` (giả lập lỗi I/O ở lô thứ 3: lô lỗi rollback trọn vẹn, 2 lô trước giữ nguyên, nhập lại bổ sung đúng 15 event còn thiếu).

### DEV-04 — Bộ đếm âm khi nhập lại với cấu hình khác (LOW)

- **Hiện tượng:** dòng từng bị từ chối (ví dụ 29/2 với năm cấu hình 2026) được chấp nhận khi nhập lại với năm 2028: `new_rejected` = -1 và `raw_events.status` vẫn là `rejected`.
- **Sửa:** chặn bộ đếm ở 0; sau mỗi lần nhập, đồng bộ `status = 'accepted'` cho các dòng đã có event.
- **Kiểm chứng:** `test_line_rejected_under_one_config_can_be_accepted_later`.

### DEV-05 — Tham số độ rộng Streamlit (LOW)

Bản sửa ban đầu chọn theo số phiên bản (>= 1.52). Được thay thế bằng AUD-03.

### DEV-06 — Encoding console Windows (LOW)

- **Hiện tượng (dự đoán):** console Windows mặc định không phải UTF-8; in JSON có ký tự ngoài ASCII có thể gây `UnicodeEncodeError`.
- **Sửa:** `main.py` đặt lại encoding của stdout/stderr thành UTF-8 (`errors="replace"`).
- **Kiểm chứng:** chỉ trên Linux. **Chưa kiểm chứng trên Windows.**

### AUD-01 — Test fail chắc chắn trên máy người dùng (LOW, chỉ ở test)

- **Hiện tượng:** `test_defaults_match_the_specification` khẳng định đường dẫn DB không chứa `Users\PC`. Project của người dùng nằm ở `C:\Users\PC\Desktop\DoAnSOC`, nên test sẽ fail ngay lần chạy đầu trên máy đích, dù sản phẩm đúng.
- **Nguyên nhân:** test kiểm tra một chuỗi cụ thể thay vì kiểm tra đường dẫn có tương đối với thư mục project hay không.
- **Sửa:** kiểm tra `db_path == PROJECT_ROOT / "data" / "soc.db"` và thư mục đầu vào mặc định.

### AUD-02 — Test quét source đọc cả virtualenv (LOW, chỉ ở test)

- **Hiện tượng:** `test_no_string_built_sql_with_external_values` và `test_no_hardcoded_secrets_in_source` dùng `PROJECT_ROOT.rglob`. README hướng dẫn tạo `.venv` trong project, nên hai test sẽ quét hàng nghìn file của thư viện, chạy rất lâu và gần như chắc chắn fail (thư viện có chuỗi kiểu `password = "..."`).
- **Sửa:** chỉ quét các thư mục của project (`project_files()` trong `tests/test_security.py`).
- **Kiểm chứng:** `test_source_scans_ignore_a_virtualenv_inside_the_project`.

### AUD-03 — Tham số độ rộng của dashboard (LOW)

- **Hiện tượng:** `use_container_width` đã bị Streamlit đánh dấu deprecated và thay bằng `width="stretch"`; trong khi đó ở bản cũ `st.dataframe(width=...)` chỉ nhận số. Chọn theo số phiên bản đoán có thể truyền sai kiểu tham số cho một số phiên bản.
- **Sửa:** `ui/common.full_width()` đọc chữ ký hàm thật: nếu tham số `width` có giá trị mặc định là chuỗi (API mới) thì dùng `width="stretch"`, ngược lại dùng `use_container_width=True`. Tính riêng cho `st.dataframe` (`TABLE`) và `st.plotly_chart` (`CHART`).
- **Kiểm chứng:** `test_full_width_keyword_is_chosen_from_signature` (với API cũ và mới giả lập), `test_dashboard_pages_only_use_width_keywords_from_common`. **Chưa kiểm chứng với Streamlit thật.**

### AUD-04 — Syslog ngày 29/2 bị từ chối (LOW, Data processing)

- **Hiện tượng:** khi không cấu hình năm, năm được suy ra là năm hiện tại. Dòng `Feb 29 ...` đọc vào năm 2029 tạo ngày 29/2/2029 không tồn tại, dòng bị từ chối `invalid_timestamp` (dòng gốc vẫn nằm trong `raw_events`, không mất).
- **Sửa:** thử lần lượt năm hiện tại rồi các năm trước, chọn năm gần nhất mà ngày tồn tại và không nằm quá một ngày trong tương lai. Khi năm được cấu hình rõ ràng thì vẫn dùng đúng năm đó.
- **Kiểm chứng:** `test_feb_29_year_is_inferred_from_last_leap_year` (3 trường hợp), `test_feb_29_with_configured_non_leap_year_is_still_rejected`, `test_impossible_date_is_rejected_when_year_is_inferred`.

### AUD-05 — IPv4-mapped IPv6 không correlate (LOW, Detection)

- **Hiện tượng:** nếu một nguồn ghi `::ffff:10.0.0.30` và nguồn khác ghi `10.0.0.30`, rule SOC-004 coi đây là hai địa chỉ khác nhau và bỏ sót. Chưa quan sát thấy trong dữ liệu mẫu; đây là gia cố cho một dạng đầu vào có thể gặp với socket dual-stack.
- **Sửa:** `normalize_ip` chuyển địa chỉ IPv4-mapped về IPv4.
- **Kiểm chứng:** `test_ipv4_mapped_ipv6_is_normalized_to_ipv4`, `test_pivot_matches_when_sysmon_logs_ipv4_mapped_addresses`.

### AUD-06 — Dashboard mở ra mạng (MEDIUM, Security)

- **Hiện tượng:** Streamlit mặc định lắng nghe trên mọi network interface (in ra cả "Network URL"). Dashboard không có đăng nhập và cho phép đổi trạng thái incident, thêm ghi chú. Trên mạng dùng chung (Wi-Fi trường, quán cà phê), máy khác có thể mở dashboard, đọc log và sửa incident.
- **Sửa:** `python main.py dashboard` thêm `--server.address 127.0.0.1` và chạy từ thư mục project; thêm `.streamlit/config.toml` với `address = "127.0.0.1"` (có hiệu lực khi `streamlit run` được gọi từ thư mục project); tắt gửi thống kê sử dụng. README ghi rõ cách chạy an toàn.
- **Kiểm chứng:** `test_dashboard_command_binds_to_localhost`, `test_project_streamlit_config_binds_to_localhost`. Chưa khởi động Streamlit thật để quan sát địa chỉ lắng nghe.
- **Còn lại:** nếu người dùng chạy `streamlit run` từ thư mục khác mà không có tham số, Streamlit vẫn dùng mặc định.

### AUD-07 — Thông báo khó hiểu khi thiếu Streamlit (LOW, CLI)

- **Hiện tượng:** `python main.py dashboard` khi Python đang dùng chưa cài `streamlit` chỉ in dòng `No module named streamlit` từ tiến trình con, không nói phải làm gì. Dấu vết trên máy người dùng (file `.pyc` của `main.py` và các module backend, không có `.pyc` của `ui/`, không có `data/soc.db`) phù hợp với việc gặp đúng tình huống này.
- **Sửa:** kiểm tra `streamlit`, `plotly`, `pandas` trước khi khởi động; nếu thiếu thì in `ERROR: the dashboard needs ...` kèm lệnh `python -m pip install -r requirements.txt` cho đúng trình thông dịch đang chạy, trả mã 2.
- **Kiểm chứng:** `test_dashboard_command_explains_missing_packages`; chạy thật trong môi trường không có Streamlit.

### AUD-08 — `NaN`/`Infinity` trong JSON làm dừng import (HIGH, Ingestion)

- **Tìm thấy bằng:** fuzz testing (137 / 120.000 dòng đột biến).
- **Hiện tượng:** module `json` của Python chấp nhận các hằng không chuẩn `NaN`, `Infinity`, `-Infinity`. Dòng Sysmon `{"EventID": Infinity, ...}` làm `int(raw_id)` ném `OverflowError`, không được bắt. Ngoại lệ thoát khỏi `ingest_file`: lô hiện tại (tối đa 20.000 dòng) bị rollback, phần còn lại của file không được xử lý, CLI in traceback. Nhập lại vẫn lỗi ở đúng dòng đó. Tái hiện: file 7 dòng (6 hợp lệ + 1 dòng `Infinity`) lưu được **0/6** event.
- **Nguyên nhân gốc:** (1) chấp nhận JSON không chuẩn; (2) bắt thiếu `OverflowError`; (3) pipeline giả định parser chỉ ném `ParseError`/`NormalizationError`, nên mọi lỗi lập trình trong parser đều làm hỏng cả lần import, trái với yêu cầu "một dòng lỗi không được làm dừng pipeline".
- **Sửa (3 lớp):** `ingest/base.load_json_line` từ chối `NaN`/`Infinity` theo RFC 8259 (`malformed_json`); bắt thêm `OverflowError` khi đọc `EventID`; `pipeline.ingest_file` chuyển mọi ngoại lệ không mong đợi của parser/normalizer thành dòng bị từ chối với lý do `unexpected_error: <Kiểu>` và ghi log cảnh báo (không ghi nội dung dòng).
- **Kiểm chứng:** 9 test (`test_sysmon_non_standard_json_constants_are_rejected` x4, `test_suricata_non_standard_json_constants_are_rejected`, `test_sysmon_huge_event_id_is_rejected_not_crashing`, `test_one_bad_line_does_not_stop_the_import`, `test_unexpected_parser_exception_rejects_only_that_line`, `test_unexpected_normalizer_exception_rejects_only_that_line`); fuzz parser lại 570.000 dòng (3 seed): 0 crash.

### AUD-09 — Surrogate lẻ trong JSON làm dừng import (HIGH, Ingestion / Storage)

- **Tìm thấy bằng:** fuzz toàn pipeline (ghi file đột biến rồi import), sau khi đã sửa AUD-08.
- **Hiện tượng:** escape `"\ud800"` là cú pháp JSON hợp lệ nhưng giải mã thành chuỗi Python chứa surrogate lẻ. Chuỗi này đi qua parser và normalizer bình thường (ví dụ vào thông báo lỗi `invalid_ip: src_ip=...`, hostname, đường dẫn) rồi làm `sqlite3` ném `UnicodeEncodeError` khi ghi **cả lô**. Kết quả giống AUD-08: lô bị rollback, import dừng. Tên file trên Windows có thể chứa surrogate lẻ (UTF-16 không kiểm tra cặp), nên log Sysmon thật có thể gặp trường hợp này.
- **Nguyên nhân gốc:** dữ liệu sau khi giải mã JSON chưa được chuẩn hóa thành Unicode hợp lệ trước khi vào database; lỗi xảy ra ở bước ghi lô nên lớp bảo vệ theo từng dòng của AUD-08 không bắt được.
- **Sửa:** `load_json_line` thay surrogate lẻ bằng U+FFFD trong mọi chuỗi (khóa và giá trị) sau khi giải mã; chỉ chạy khi dòng có escape `\uD8..`-`\uDF..` nên không ảnh hưởng hiệu năng thông thường. Cặp surrogate hợp lệ (emoji) giữ nguyên. Dòng gốc trong `raw_events` vẫn giữ escape ban đầu làm bằng chứng.
- **Kiểm chứng:** `test_lone_surrogates_do_not_stop_the_import` (Suricata, Sysmon), `test_valid_surrogate_pairs_are_kept`; fuzz toàn pipeline 4 lần (2 seed x 90.000 dòng, 1 x 150.000 dòng, 1 x 4.500 dòng trong pytest): mọi lần import đều `completed`, integrity ok.
- **Đối chứng:** 12 test mới fail khi chạy với `ingest/` và `pipeline.py` gốc, đều pass sau khi sửa.

### TST-01, TST-02, TST-03 — Lỗi trong code test

- TST-01: test về escape báo cáo tìm `<script>` trong cả phần code block, nơi log gốc được giữ nguyên có chủ đích. Sửa: chỉ kiểm tra bảng và danh sách; thêm kiểm tra không thể đóng code block bằng dữ liệu log.
- TST-02: dữ liệu test chứa `\n` trong username làm một dòng log tách thành hai, parser từ chối đúng, incident không được tạo. Sửa dữ liệu test.
- TST-03: test mới của AUD-09 truy vấn `events.raw_id`, cột đã bị bỏ khi tối ưu (DEV-01). Sửa thành `event_id`.

## Đợt 3 (2026-11-14): sai lệch so với đề bài

Đây không phải lỗi làm chương trình hỏng mà là chỗ cài đặt khác ý của đề. Chi tiết: `docs/SPEC_COMPLIANCE.md`.

| ID | Sai lệch | Sửa | Test |
|---|---|---|---|
| SPEC-01 | SOC-004 ghép Suricata alert với Sysmon cùng cặp IP, không phải "IP bị cảnh báo sau đó kết nối tới host nội bộ khác" | Viết lại `network_host_pivot.py` theo nghĩa lateral movement | `test_rules.py::test_pivot_*` |
| SPEC-02 | SOC-001 theo dõi thành công/khóa trong 300 giây; không có chế độ chỉ báo khi có thành công/khóa | `followup_seconds` = 60, thêm `require_followup` | `test_ssh_strict_assignment_mode_requires_success_or_lockout`, `test_ssh_default_followup_is_60_seconds` |
| SPEC-03 | SOC-003 chỉ xét `AppData\Local\Temp`, bỏ sót AppData khác | Thêm `exec_from_appdata` | `test_process_scoring` |
| SPEC-04 | Không có analyst phụ trách incident | Cột `assigned_analyst` + migration, `assign` | `test_assign_reassign_and_unassign_incident`, `test_old_database_without_assigned_analyst_is_migrated` |
| SPEC-05 | Dedup chỉ gộp alert giao thời gian, không có số liệu giảm nhiễu | Cooldown 600 giây, `occurrence_count` chính xác, `dedup_summary` | `test_cooldown_boundary_is_inclusive`, `test_dedup_summary_counts_raw_alerts_against_incidents` |
| SPEC-06 | Thiếu upload log, incident timeline tương tác, top attacked assets trên dashboard | Trang Upload Logs, Gantt, timeline Plotly, biểu đồ asset | `test_dashboard.py` (6 test mới) |
| SPEC-07 | Cấu trúc khác đề: `ingest/` thay vì `ingestors/`, thiếu `storage/models.py` | Đổi tên thư mục, thêm `models.py` | Toàn bộ suite |
| SPEC-08 | Dataset thiếu beaconing, sudo, kịch bản dedup/gộp incident | Kịch bản S18-S23 | `test_full_pipeline_matches_ground_truth` |
| TST-04 | `test_pivot_ipv4_mapped...` dùng đích bên ngoài, sai với nghĩa mới của SOC-004 | Dùng đích nội bộ `::ffff:10.0.0.40` | `test_audit_regression.py` |

## Đợt 4 (2026-11-16): nguồn access log web và rule SOC-005

| ID | Lỗi | Phát hiện bằng | Sửa | Test |
|---|---|---|---|---|
| WEB-01 | Dòng access log có số khổng lồ trong thời gian (`02:111111111111111150:05`, năm 33 chữ số) gây `OverflowError` chưa được bắt trong `parse_access_time`; pipeline vẫn chạy tiếp (lỗi bất ngờ bị ghi nhận cho dòng đó) nhưng dòng bị ghi lý do `unexpected_error` | `benchmarks/fuzz_test.py` (3 crash) | Bắt thêm `OverflowError`, trả `invalid_timestamp` | `test_normalizers.py::test_web_access_bad_timestamps_rejected` |
| WEB-02 | Regex SQL injection `union(\s|/\*.{0,20}\*/)+select` bị ReDoS với URL `union/**//**/...` (treo hơn 2 phút) | Ca ReDoS mới trong fuzz test, khi phát triển | Dùng `/\*[^*]{0,20}\*/` để mỗi chú thích chỉ khớp một cách | Fuzz ReDoS: tối đa 0,011 giây |

## Quy trình xác minh sau khi sửa

1. Viết test tái hiện (fail trên code cũ với AUD-04, AUD-05, DEV-04; AUD-01/02 là lỗi chỉ biểu hiện trên máy đích).
2. Chạy toàn bộ `python -m pytest` trên Python 3.13.
3. Chạy các file test không cần pandas trên Python 3.11 và 3.12.
4. Chạy lại `run-sample` và so ground truth.
5. Chạy soak test trên code đã sửa (xem `docs/stability_test_report.md`).
