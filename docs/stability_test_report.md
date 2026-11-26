# Stability, Reliability & Security Audit Report

Hệ thống: Multi-Source SOC Analyst Toolkit.
Audit lần 2: **2026-11-14** (audit lại toàn bộ theo cùng prompt; lần 1 ngày 2026-11-13).
Mọi con số dưới đây lấy từ các lần chạy thật; file kết quả gốc nằm trong `benchmarks/results/`.

Quy ước trạng thái: **PASS** (có bằng chứng chạy thật), **PARTIAL** (chạy một phần), **FAIL**, **NOT TESTED**.

## A. Executive Summary

**Kết luận chung: PARTIAL.**

Lần audit này chạy trên đúng mã nguồn lấy từ máy người dùng (`C:\Users\PC\Desktop\DoAnSOC`, 65 file, giống hệt bản đã bàn giao hôm trước). Ngoài việc lặp lại toàn bộ các bài kiểm tra, lần này thêm **fuzz testing** (đưa hàng trăm nghìn dòng log bị làm hỏng ngẫu nhiên vào parser và vào toàn pipeline) và kiểm tra dashboard trên database lớn.

**Fuzz testing tìm ra 2 lỗi HIGH mà lần audit trước đã bỏ sót** (và kết luận sai là "không có lỗi HIGH"):

- **AUD-08:** một dòng JSON chứa `NaN`/`Infinity` (ví dụ `"EventID": Infinity`) làm hủy cả lần import. Lô hiện tại (tối đa 20.000 dòng) bị rollback và phần còn lại của file không được xử lý; tái hiện: 0/6 event hợp lệ được lưu.
- **AUD-09:** một dòng JSON chứa escape surrogate lẻ (`"\ud800"`), dạng có thể xuất hiện với tên file Windows, gây lỗi y hệt ở bước ghi database.

Cả hai vi phạm trực tiếp yêu cầu "một dòng log lỗi không được làm dừng pipeline", và cho phép nội dung log làm mất dữ liệu của các dòng khác. Cả hai **đã được sửa** theo nguyên nhân gốc, có test tái hiện (fail trên code cũ, pass trên code mới), và pipeline giờ chuyển mọi lỗi bất ngờ của parser thành một dòng bị từ chối thay vì dừng import.

Sau khi sửa: 375 test đạt, fuzz 570.000 dòng không crash, 4 lần fuzz toàn pipeline đều hoàn tất, soak 10 và 30 phút không lỗi.

Kết luận vẫn là PARTIAL vì:

1. **Dashboard chưa chạy bằng Streamlit thật.** Môi trường audit vẫn không cài được package (mạng bị chặn). Logic 5 trang đã chạy được với database 300.000 event; phần hiển thị và biểu đồ chưa kiểm chứng.
2. **Chưa chạy trên Windows.**
3. **Detection quét lại toàn bộ dữ liệu mỗi lần chạy**: thời gian và RAM tăng tuyến tính theo tổng số event.

## B. Environment

| Mục | Giá trị |
|---|---|
| Mã nguồn được audit | 65 file sao chép từ máy người dùng ngày 2026-11-14; so byte-by-byte với bản đã bàn giao: 0 khác biệt |
| OS | Linux 6.18.44 x86_64 (máy ảo trên cloud), glibc 2.39 |
| CPU / RAM | 2 vCPU / 7,8 GB |
| Python | 3.13.18 (chính); 3.11 và 3.12 cho các test không cần pandas |
| SQLite | 3.53.1 |
| pandas / numpy / pytest / psutil | 3.0.5 / 2.5.3 / 9.1.1 / 7.2.2 |
| streamlit / plotly | **Không cài đặt**, không cài được (không truy cập được pypi.org) |
| Database | SQLite, WAL, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000 ms`, cache 64 MB, `temp_store=MEMORY`; 10 bảng, 21 index |
| Cấu hình | Mặc định (`config/settings.json` không có); không đặt biến `SOC_*` |
| Sao lưu DB | Máy người dùng không có `data/soc.db` nên không có dữ liệu thật cần sao lưu. Mọi test dùng DB tạm |

Dấu vết trên máy người dùng: có file `.pyc` Python 3.13 của `main.py` và các module backend tạo lúc 08:57 sáng 14/11, không có `.pyc` của `ui/`, `tests/`, không có `data/`. Điều này phù hợp với việc đã thử `python main.py dashboard` khi chưa cài Streamlit (xem AUD-07); `pytest` chưa được chạy trên máy đó.

## C. Test Results

| Test Category | Total | Passed | Failed | Status | Nguồn |
|---|---:|---:|---:|---|---|
| Smoke Tests | 44 | 44 | 0 | PARTIAL | `test_config_cli.py`; import 33 module; `init-db` tạo đủ 10 bảng; khởi động Streamlit: NOT TESTED |
| Unit Tests | 202 | 202 | 0 | PASS | `test_ingest.py` (45), `test_normalizers.py` (82), `test_rules.py` (75) |
| Integration Tests | 61 | 61 | 0 | PASS | `test_database.py` (14), `test_incidents.py` (21), `test_audit_regression.py` (26) |
| E2E Tests | 19 | 19 | 0 | PASS | `test_pipeline_e2e.py`; thêm kiểm tra E2E qua CLI ở mục F |
| Accuracy Tests | 255 | 195 | 60 | PASS theo đặc tả (xem D) | `benchmarks/evaluate_accuracy.py` |
| Stress Tests | 6 | 6 | 0 | PASS (Linux) | Benchmark 10K / 100K / 500K, soak 10 và 30 phút, fuzz |
| Security Tests | 33 | 33 | 0 | PASS | `test_security.py` |
| Dashboard Tests | 21 | 16 | 0 | PARTIAL | `test_dashboard.py`: 16 passed, **5 skipped** (AppTest cần Streamlit) |

`python -m pytest`:

| Mã nguồn | Passed | Skipped | Failed | Errors |
|---|---:|---:|---:|---:|
| Mã gốc của người dùng | 361 | 5 | 0 | 0 |
| Sau khi sửa lỗi lần audit này | 375 | 5 | 0 | 0 |

Lý do skip (cả 5): `streamlit is not installed in this environment`. Trên Python 3.11 và 3.12: 237 test của 5 file không cần pandas đều đạt, cả trước và sau khi sửa.

Điểm đáng chú ý: **toàn bộ 361 test cũ đều đạt trên mã có 2 lỗi HIGH**. Các test viết tay không có đầu vào kiểu `Infinity` hay surrogate lẻ; chỉ fuzz testing mới tìm ra.

## D. Detection Accuracy

255 kịch bản tổng hợp có nhãn (51 loại x 5 biến thể). Kết quả giống hệt lần 1, cả trước và sau khi sửa lỗi.

| Rule | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| SSH Brute Force | 30 | 5 | 10 | 30 | 0,857 | 0,750 | 0,800 | 0,143 |
| Port Scan | 25 | 5 | 5 | 20 | 0,833 | 0,833 | 0,833 | 0,200 |
| Suspicious Process | 30 | 10 | 10 | 25 | 0,750 | 0,750 | 0,750 | 0,286 |
| Network-to-Host Pivot | 20 | 5 | 10 | 15 | 0,800 | 0,667 | 0,727 | 0,250 |

Mọi 195 kịch bản thường được phân loại đúng (gồm các biên 4/5/6 lần đăng nhập, 14/15/16 cổng, đúng 60 giây, đúng 300 giây). 60 kịch bản sai đều thuộc nhóm `HARD_` được cố ý đưa vào: tấn công chậm, password spraying, NAT, malware ở thư mục bình thường, công cụ quản trị hợp lệ. Dữ liệu tổng hợp do cùng tác giả với rule viết ra; **không đủ dữ liệu** (không có log thật có nhãn) để ước lượng độ chính xác thực tế.

## E. Performance

Benchmark trên mã gốc của người dùng, 2026-11-14 02:57 UTC, mỗi kích thước một tiến trình và DB mới:

| Events | Processing Time | Events/sec | Memory (peak RSS) | Errors |
|---|---:|---:|---:|---:|
| 10K | 0,361 s | 27.680 | 41,3 MB | 0 |
| 100K | 3,908 s | 25.588 | 120,9 MB | 0 |
| 500K | 26,982 s | 18.531 | 161,8 MB | 0 |

Ở 500K: parse 2,33 s; normalize 5,00 s; ghi DB 17,17 s; detection 1,35 s (SOC-002 chiếm 0,81 s); correlation 0,03 s; detection latency 1,38 s. Tìm theo IP 0,2 ms; tìm văn bản `LIKE` 0,11 s; timeline 0,11 s. "Errors" gồm cả việc tự đối chiếu số alert/incident với số tấn công đã chèn và integrity check.

Sau khi sửa lỗi (cùng máy, sau soak test): 

| Events | Processing Time | Events/sec | Memory (peak RSS) | Errors |
|---|---:|---:|---:|---:|
| 10K | 0,410 s | 24.409 | 41,5 MB | 0 |
| 100K | 4,294 s | 23.286 | 120,8 MB | 0 |
| 500K | 26,410 s | 18.932 | 161,5 MB | 0 |

Tổng thời gian không đổi trong phạm vi dao động giữa các lần chạy (khoảng 15%). Riêng bước parse ở 500K tăng 2,33 -> 2,96 s; một phần có thể do bản sửa AUD-09 (thêm một lần tìm regex trên mỗi dòng JSON), nhưng chênh lệch này nằm trong mức nhiễu nên không kết luận được. Nguồn: `benchmarks/results/benchmark_results_after_fix.json`.

| Câu hỏi | Kết quả |
|---|---|
| RAM tăng bất thường? | Trong một lần chạy: không; RSS dừng khi cache SQLite (64 MB) đầy. Khi chạy lâu: tăng theo tổng dữ liệu do detection quét toàn bộ (mục Soak) |
| Memory leak? | Không phát hiện. `tracemalloc` (lần 1): heap Python giữ lại 0,11 -> 0,12 MB qua 30 chu kỳ trên DB cố định |
| Nạp dữ liệu vào RAM không cần thiết? | Ingest đọc từng dòng. Detection nạp mọi `failed_login` (SOC-001) và mọi `ids_alert` (SOC-004) |
| SQLite nghẽn ghi? | Ghi DB là phần chậm nhất (64% thời gian ở 500K), đã được tối ưu ở lần 1 (DEV-01) |
| Query chậm? | Không với truy vấn có index; tìm văn bản và timeline quét toàn bảng |
| Thiếu index? | Không (`EXPLAIN QUERY PLAN` trong test) |
| Code chạy lặp không cần thiết? | Có: detection quét lại toàn bộ event mỗi lần, kể cả khi không có dữ liệu mới (1,46 s ở 500K). Chưa sửa |
| Regex chậm (ReDoS)? | Không: 12 đầu vào đối kháng dài 65.536 ký tự, chậm nhất 0,008 s |

## F. Database Integrity

Kiểm tra qua CLI thật, mỗi bước là một tiến trình riêng (tương đương khởi động lại ứng dụng), trên mã gốc và lặp lại trên mã đã sửa:

| Kiểm tra | Kết quả |
|---|---|
| E2E so với ground truth | PASS: 931 dòng thô, 921 event, 10 dòng bị từ chối (mỗi dòng có lý do cụ thể), 7 alert, 7 incident; 17/17 kịch bản đúng rule, severity và số event; 7/7 alert gắn incident; 52 dòng bằng chứng |
| `PRAGMA integrity_check` | PASS: `ok` trên mọi DB (E2E, shuffled, ordered, benchmark, soak, fuzz) |
| `PRAGMA foreign_key_check` | PASS: không vi phạm |
| Nhập trùng | PASS: nhập lại cả 3 file: 0 event / 0 alert / 0 incident mới (921/7/7/52 trước và sau); 931 dòng được tính là `duplicates`; mỗi lần nhập vẫn có batch riêng (6 batch) |
| Event sai thứ tự | PASS: nhập file đã xáo trộn cho alert giống hệt từng byte (cả fingerprint) so với file đúng thứ tự |
| Khởi động lại | PASS: đổi trạng thái 2 incident (IN_PROGRESS, FALSE_POSITIVE) qua CLI, chạy lại `run-sample` trong tiến trình mới: trạng thái và lịch sử giữ nguyên, số liệu không đổi. Khởi động lại Streamlit: NOT TESTED |
| Transaction | PASS: test rollback lô lỗi, rollback toàn bộ detection khi lỗi, ràng buộc CHECK/UNIQUE/FK |
| WAL và đóng kết nối | PASS: đọc được khi có tiến trình khác giữ khóa ghi; 3.864 lượt đọc đồng thời trong hai lần soak, 0 lỗi |

## G. Security Findings

| Vulnerability | Severity | Location | Evidence | Remediation | Fix status |
|---|---|---|---|---|---|
| Nội dung log có thể chặn import (log poisoning): `NaN`/`Infinity` | HIGH | `ingest/sysmon.py`, `ingest/suricata.py`, `pipeline.py` | Một dòng `"EventID": Infinity` làm 0/6 event hợp lệ được lưu, import dừng, lặp lại mỗi lần nhập | Từ chối hằng JSON không chuẩn; bắt `OverflowError`; pipeline chuyển mọi lỗi bất ngờ thành dòng bị từ chối | **Đã sửa** (AUD-08), 9 test |
| Nội dung log có thể chặn import: surrogate lẻ | HIGH | `ingest/*` -> `storage/repository.py` | `"\ud800"` trong bất kỳ trường nào làm hỏng cả lô khi ghi DB. Kẻ tấn công kiểm soát được tên file trên máy Windows có thể tạo sự kiện Sysmon như vậy để che các sự kiện khác cùng lô | Chuẩn hóa chuỗi sau khi giải mã JSON (U+FFFD), giữ dòng gốc làm bằng chứng | **Đã sửa** (AUD-09), 3 test + fuzz |
| Dashboard không xác thực, lắng nghe mọi interface | MEDIUM | `main.py dashboard` | (Lần 1) | Bind `127.0.0.1` | Đã sửa lần 1 (AUD-06) |
| SQL injection | Không phát hiện | `storage/repository.py` | 9 payload qua log, tìm kiếm, ghi chú, trạng thái; test tĩnh | SQL tham số hóa | Không cần sửa |
| Path traversal | Không phát hiện | `ingest/base.py` | `..`, đường dẫn tuyệt đối, symlink, null byte, tên thiết bị, qua cả test và CLI (`../../../etc/passwd` bị chặn) | `allowed_input_dirs` | Không cần sửa |
| Input validation | PASS sau sửa | `ingest/`, `normalizer/` | 570.000 dòng fuzz: chỉ có `ParseError`/`NormalizationError` | - | - |
| Hardcoded secrets | Không phát hiện | Toàn bộ source | Quét mật khẩu, API key, token, private key, URL chứa thông tin đăng nhập | - | Không cần sửa |
| Dữ liệu nhạy cảm trong log ứng dụng | Không phát hiện | `logging` | Log không chứa nội dung dòng log, kể cả log cảnh báo mới của AUD-08 (có test) | - | Không cần sửa |
| Chèn markup | Không phát hiện | `reporting.py`, `ui/` | Escape trong báo cáo; UI không dùng HTML thô | - | Không cần sửa |

Ứng dụng SOC mô phỏng phục vụ học tập; không có phân quyền và không được dùng để bảo vệ SOC thật.

## H. Bugs Fixed

Chi tiết: `docs/BUG_FIX_LOG.md`.

| ID | Mức độ | Lần | Tóm tắt | Xác minh |
|---|---|---|---|---|
| AUD-08 | HIGH | 2 | `NaN`/`Infinity` trong JSON làm hủy cả lần import | 9 test; 12 test mới fail trên mã gốc, pass trên mã sửa; fuzz 570.000 dòng |
| AUD-09 | HIGH | 2 | Surrogate lẻ trong JSON làm hủy cả lần import | 3 test; fuzz toàn pipeline 4 lần |
| AUD-07 | LOW | 2 | `main.py dashboard` thiếu Streamlit không hướng dẫn cách cài | 1 test; chạy thật |
| AUD-06 | MEDIUM | 1 | Dashboard lắng nghe mọi interface | 2 test |
| AUD-01 đến AUD-05 | LOW | 1 | Test không chạy được trên máy đích, ngày 29/2, IPv4-mapped, tham số Streamlit | Xem BUG_FIX_LOG |
| DEV-01 đến DEV-06 | 2 MEDIUM, 4 LOW | phát triển | Hiệu năng ghi DB, DB bị khóa, ... | Xem BUG_FIX_LOG |

Sau khi sửa: toàn bộ test (375 passed), E2E qua CLI, ground truth và accuracy chạy lại cho kết quả như trước sửa. Benchmark sau sửa ở mục E.

## Soak test và recovery test

### Soak test

Chạy trên **mã gốc của người dùng** (bản sao tách riêng, trước khi sửa AUD-07..09; các dòng sinh ra không chứa `NaN` hay surrogate nên không gặp hai lỗi đó). Mỗi chu kỳ: sinh 4.000 event mới ở một khoảng thời gian riêng (1 tấn công mỗi rule), nhập, nhập lại lô trước, detection, truy vấn dashboard, mở chi tiết và báo cáo một incident, đổi trạng thái, thêm ghi chú. Một luồng khác đọc dữ liệu dashboard liên tục; mỗi 10 chu kỳ một tiến trình riêng chạy `main.py stats`.

| Chỉ số | Quick soak | Extended soak |
|---|---:|---:|
| Thời lượng | 611,7 s (10 phút) | 1.827,0 s (30 phút) |
| Chu kỳ | 183 | 328 |
| Event lưu / mong đợi | 732.000 / 732.000 | 1.312.000 / 1.312.000 |
| Alert lưu / mong đợi | 732 / 732 | 1.312 / 1.312 |
| Incident lưu / mong đợi | 732 / 732 | 1.312 / 1.312 |
| Dòng nhập lại (phải bị bỏ qua) | 728.000, 0 dòng mới | 1.308.000, 0 dòng mới |
| Fingerprint trùng / alert chồng lấn | 0 / 0 | 0 / 0 |
| Alert không có incident / event_count sai | 0 / 0 | 0 / 0 |
| Lượt đọc đồng thời / lỗi | 1.331 / 0 | 2.533 / 0 |
| Kiểm tra từ tiến trình riêng | 19 / 19 ok | 33 / 33 ok |
| Exception, crash, batch dở dang | 0 | 0 |
| integrity / foreign key | ok / 0 | ok / 0 |
| Kích thước DB cuối | 548 MB | 981 MB |
| RSS đầu -> cuối | 79,1 -> 280,4 MB | 79,3 -> 338,1 MB |
| Detection mỗi chu kỳ đầu -> cuối | 0,02 -> 4,42 s | 0,03 -> 8,55 s |

**Kết quả: PASS cho tính đúng đắn và độ ổn định trong 30 phút**, giống lần 1 (lần 1: 1.312.000 event, RSS 338,0 MB, detection cuối 7,06 s). Thời gian detection và RSS tăng tuyến tính theo tổng số event đã lưu; kiểm tra `tracemalloc` ở lần 1 cho thấy đây là khối lượng dữ liệu detection phải quét mỗi lần, không phải rò rỉ.

Soak 60 phút và soak trên Windows: NOT TESTED.

### Fuzz testing (mới trong lần 2)

| Bài | Đầu vào | Mã gốc | Sau sửa |
|---|---|---|---|
| Parser + normalizer | 120.000 dòng đột biến (seed 1234) | **FAIL**: 137 crash `OverflowError` (AUD-08) | PASS: 0 crash |
| Parser + normalizer | 300.000 dòng (seed 98765) + 150.000 (seed 2026) | - | PASS: 0 crash, không lời gọi nào > 0,2 s |
| Toàn pipeline (ghi file, import, detection) | 90.000 dòng/seed | **FAIL**: import dừng vì `UnicodeEncodeError` (AUD-09) | PASS: 2 seed x 90.000 + 150.000 dòng; mọi batch `completed`, 0 `unexpected_error`, 0 rule error, integrity ok |
| ReDoS | 12 đầu vào đối kháng 65.536 ký tự | PASS (0,008 s) | PASS |

Công cụ: `python -m benchmarks.fuzz_test`. Một bản nhỏ chạy trong mỗi lần `pytest` (`test_fuzz_smoke_parsers_never_crash_and_imports_complete`).

### Recovery test

| Tình huống | Kết quả |
|---|---|
| Khởi động lại ứng dụng | PASS (tiến trình CLI); Streamlit: NOT TESTED |
| DB bị tiến trình khác khóa | PASS: `ERROR: cannot start a write transaction ... (database busy or locked)`, mã 2; chạy lại sau khi nhả khóa thành công, integrity ok |
| DB chưa khởi tạo / đường dẫn là thư mục / file không phải DB | PASS: thông báo rõ, mã 2, không tạo file rỗng |
| Cấu hình sai giá trị / JSON hỏng / file cấu hình không tồn tại | PASS: `port_scan.threshold must be >= 1`, `cannot read configuration file`, `configuration file not found` |
| File đầu vào không tồn tại / ngoài thư mục cho phép | PASS: `input file not found`, `outside the allowed input folders` |
| Malformed event | PASS sau sửa: kể cả dòng `Infinity` và surrogate lẻ chỉ bị từ chối; trước sửa: **FAIL** (AUD-08, AUD-09) |
| Lỗi I/O giữa lô, lỗi trong rule, lỗi trong bước incident | PASS (test): rollback đúng phạm vi, nhập lại bổ sung phần thiếu |
| Dashboard khi thiếu Streamlit | PASS sau sửa (AUD-07): hướng dẫn cài đặt rõ ràng |

## Dashboard (Phase 9)

| Trang / chức năng | Lớp dữ liệu | Script trang với Streamlit giả lập | Streamlit thật |
|---|---|---|---|
| Overview: DB rỗng / 921 event / 300.000 event | PASS | PASS (300K: 0,12 s) | NOT TESTED |
| Overview: DB thiếu / DB hỏng | PASS | PASS (báo lỗi và dừng) | NOT TESTED |
| Events: IP, thời gian, severity, nguồn, phân trang, raw viewer | PASS | PASS, cả với bộ lọc thời gian bật, ở 300K | NOT TESTED |
| Alerts: số lượng, severity, evidence, không trùng | PASS | PASS ở 300K | NOT TESTED |
| Incidents: chi tiết, đổi trạng thái, liên kết, timeline | PASS | PASS ở 300K, form ghi thật vào SQLite | NOT TESTED |
| Investigation: evidence, raw log, tìm kiếm, export | PASS | PASS ở 300K; ghi chú rỗng bị từ chối | NOT TESTED |
| Biểu đồ Plotly | - | Thay bằng stub | NOT TESTED |

Streamlit giả lập chỉ kiểm tra logic và xử lý lỗi của trang, **không** kiểm tra hiển thị.

## I. Remaining Risks

1. **Dashboard chưa chạy thật** (Streamlit, Plotly, trình duyệt).
2. **Chưa chạy trên Windows.** Các điểm rủi ro đã biết: encoding console, symlink trong test (tự skip), file WAL của SQLite nếu Desktop được đồng bộ OneDrive.
3. **Detection quét toàn bộ dữ liệu mỗi lần** (MEDIUM): 8,55 giây ở 1,31 triệu event ở cuối soak 30 phút và tiếp tục tăng.
4. RSS tăng theo tổng dữ liệu khi chạy lâu.
5. **Test viết tay không đủ**: 361 test cũ đều đạt trên mã có 2 lỗi HIGH. Fuzz testing đã được thêm vào, nhưng có thể còn loại đầu vào chưa được thử.
6. Độ chính xác chỉ đo trên dữ liệu tổng hợp.
7. Chống trùng theo hash dòng: hai dòng giống hệt nhau được lưu một lần.
8. Không xác thực dashboard; chỉ giới hạn bằng địa chỉ lắng nghe.
9. SQLite một tiến trình ghi; detection rất lớn có thể làm tiến trình khác nhận lỗi `busy or locked`.

## J. Final Conclusion

| Phân loại | Áp dụng? |
|---|---|
| Stable for local academic demonstration | **Có, có điều kiện**: backend có đủ bằng chứng sau khi sửa AUD-08/09; cần cài requirements, chạy `pytest` và mở dashboard trên máy Windows trước khi demo |
| Stable under tested workloads | **Có, trên Linux**: 500K event mỗi lần nhập, 1,31 triệu event trong soak 30 phút, 570.000 dòng fuzz |
| Requires further optimization | **Có**: detection tăng dần, tìm kiếm văn bản (FTS5) |
| Not ready for deployment | **Có** |

Hệ thống **không** sẵn sàng cho production.

### Việc cần làm trên máy Windows

```bash
cd C:\Users\PC\Desktop\DoAnSOC
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pytest                       # kỳ vọng 380 test, 0 failed (5 test AppTest sẽ chạy; test symlink có thể bị skip)
python main.py run-sample
python main.py dashboard               # http://127.0.0.1:8501
python -m benchmarks.fuzz_test --iterations 5000 --pipeline-lines 5000
```
