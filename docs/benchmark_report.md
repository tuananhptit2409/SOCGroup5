# Báo cáo benchmark và độ chính xác

Mọi con số trong tài liệu này lấy từ các lần chạy thật, lưu trong `benchmarks/results/*.json`. Chạy lại:

```bash
python -m benchmarks.run_benchmark
python -m benchmarks.evaluate_accuracy
```

## 1. Môi trường đo

| Mục | Giá trị |
|---|---|
| Ngày đo | 2026-11-13 (lần chạy cuối 16:31 UTC, sau các bản sửa của audit) |
| Hệ điều hành | Linux 6.18 x86_64 (máy ảo) |
| CPU | 2 vCPU |
| RAM | 7,8 GB |
| Python | 3.13.18 |
| SQLite | 3.53.1 |
| pandas / pytest / psutil | 3.0.5 / 9.1.1 / 7.2.2 |
| streamlit / plotly | không cài đặt |
| Cấu hình DB | WAL, synchronous NORMAL, cache 64 MB, `batch_size` 20.000 |

**Lưu ý:** đây không phải máy Windows của người dùng. Con số trên máy khác sẽ khác; cần chạy lại benchmark trên máy đích.

## 2. Dữ liệu benchmark

`benchmarks/run_benchmark.py` sinh dữ liệu tổng hợp: 40% Linux auth, 35% Suricata, 25% Sysmon. Lưu lượng nền được dựng sao cho không rule nào có thể kích hoạt. Cứ 10.000 event thì chèn một tấn công cho mỗi rule (thực thể riêng), ghi ở **cuối file** (tức là sai thứ tự thời gian). Sau khi chạy, script tự so số alert và incident với số tấn công đã chèn, chạy detection lần hai để kiểm tra không sinh trùng, và chạy `PRAGMA integrity_check`; bất kỳ sai lệch nào được tính vào cột Errors.

Mỗi kích thước chạy trong một tiến trình riêng với database tạm mới.

## 3. Kết quả (sau tối ưu, event nền theo thứ tự thời gian như file log thật)

> **Cập nhật 2026-11-14, sau khi sửa đồ án cho khớp đề bài** (SOC-004 theo nghĩa lateral movement, cooldown dedup, AppData, sudo/PAM): bộ sinh benchmark nay chèn tấn công pivot đúng nghĩa mới (alert HIGH vào máy nội bộ, 2 giây sau máy đó kết nối SMB tới một máy nội bộ khác). Chạy lại `python -m benchmarks.run_benchmark`: 10K 0,29 s (34.464 event/s), 100K 3,29 s (30.420 event/s), 500K 21,09 s (23.704 event/s, RSS đỉnh 168 MB), số alert/incident đúng bằng số tấn công chèn vào (4 / 40 / 200), 0 lỗi. Soak test 2 phút (`soak_after_spec_2min.json`): 74 vòng, 296.000 event, 296 alert, 296 incident, khớp kỳ vọng. Fuzz test: 0 crash, ReDoS tối đa 0,007 giây.

> **Audit lại 2026-11-14:** `benchmark_results.json` đã được chạy lại trên mã của người dùng: 10K 0,361 s, 100K 3,908 s, 500K 26,982 s (18.531 event/s), 0 lỗi. Sau khi sửa AUD-08/09: `benchmark_results_after_fix.json`, 500K 26,410 s, 0 lỗi. Bảng dưới là lần chạy ngày 2026-11-13; chênh lệch giữa các lần nằm trong khoảng 15%. Soak test lần 2: `soak_quick.json`, `soak_extended.json`; fuzz: `fuzz_results.json`.

Nguồn: `benchmarks/results/benchmark_results.json`.

| Events | Ingest (s) | Parse (s) | Normalize (s) | DB insert (s) | Detection (s) | Correlation (s) | Tổng (s) | Events/s | Peak RSS (MB) | DB (MB) | Alerts | Incidents | Errors |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10.000 | 0,330 | 0,050 | 0,096 | 0,154 | 0,022 | 0,001 | 0,357 | 28.013 | 41,3 | 7,5 | 4 | 4 | 0 |
| 100.000 | 3,599 | 0,425 | 1,007 | 1,961 | 0,273 | 0,005 | 3,883 | 25.756 | 121,4 | 74,3 | 40 | 40 | 0 |
| 500.000 | 22,304 | 2,180 | 4,676 | 14,444 | 1,297 | 0,025 | 23,637 | 21.153 | 162,1 | 374,1 | 200 | 200 | 0 |

Một lần chạy trước đó với cùng cấu hình (trước các bản sửa của audit, có tác vụ khác chạy song song) cho 500K là 27,3 giây; chênh lệch giữa các lần chạy khoảng 15%.

- "Ingest" là thời gian thực (wall clock) của cả ba file, gồm đọc file, băm, parse, normalize và ghi DB.
- "Events/s" = số event / tổng thời gian xử lý (ingest + detection + correlation).
- Số dòng bị từ chối: 0 ở cả ba mức (dữ liệu benchmark không chứa dòng lỗi).

### Detection latency

Detection chạy theo lô, nên "độ trễ phát hiện" ở đây là thời gian từ lúc gọi `run_detection` đến khi alert và incident được commit.

| Events | Lần đầu (s) | Chạy lại, không có dữ liệu mới (s) | SOC-001 | SOC-002 | SOC-003 | SOC-004 |
|---:|---:|---:|---:|---:|---:|---:|
| 10.000 | 0,026 | 0,024 | 0,001 | 0,013 | 0,005 | 0,002 |
| 100.000 | 0,283 | 0,285 | 0,018 | 0,173 | 0,059 | 0,023 |
| 500.000 | 1,333 | 1,246 | 0,071 | 0,835 | 0,271 | 0,120 |

Độ trễ thực tế từ lúc sự kiện xảy ra đến lúc có alert còn phụ thuộc vào việc người dùng chạy ingest và detect khi nào; hệ thống không có chế độ thời gian thực.

### Thời gian truy vấn của dashboard (giây)

| Truy vấn | 10K | 100K | 500K |
|---|---:|---:|---:|
| Tìm theo IP (50 dòng) | 0,0002 | 0,0002 | 0,0002 |
| Trang theo khoảng thời gian | 0,0002 | 0,0002 | 0,0002 |
| Lọc severity >= 4 | <0,0001 | 0,0001 | 0,0002 |
| Trang theo nguồn | 0,0002 | 0,0002 | 0,0002 |
| Danh sách incident | 0,0002 | 0,0003 | 0,0013 |
| Đếm tổng (Overview) | 0,0001 | 0,0001 | 0,0057 |
| Top IP nguồn | 0,0016 | 0,0121 | 0,0671 |
| Timeline event | 0,0020 | 0,0169 | 0,1117 |
| Tìm văn bản (`LIKE`, quét toàn bảng) | 0,0022 | 0,0189 | 0,0991 |

Các truy vấn có index gần như không đổi theo kích thước. Ba truy vấn cuối tăng tuyến tính vì phải duyệt toàn bộ bảng hoặc index.

## 4. Bottleneck và tối ưu

### Phát hiện

Lần đo đầu tiên (`baseline.json`, event nền thứ tự ngẫu nhiên, `batch_size` 5.000):

| Events | DB insert (s) | Tổng (s) | Events/s | Peak RSS (MB) |
|---:|---:|---:|---:|---:|
| 10.000 | 0,202 | 0,406 | 24.649 | 39,1 |
| 100.000 | 4,872 | 7,019 | 14.246 | 45,1 |
| 500.000 | 53,723 | 64,205 | 7.788 | 45,3 |

Parse và normalize tăng tuyến tính, nhưng thời gian ghi DB tăng nhanh hơn tuyến tính (84% tổng thời gian ở 500K) và tốc độ giảm từ 24,6 nghìn xuống 7,8 nghìn event/giây.

### Nguyên nhân

Thử nghiệm ở mức 500K, event nền thứ tự ngẫu nhiên. Mốc so sánh là 40,8 giây ghi DB (sau thay đổi 1-2 bên dưới, `batch_size` 5.000):

| Thử nghiệm | DB insert (s) | Kết luận |
|---|---:|---|
| Tăng cache 64 -> 256 MB | 39,9 | Không cải thiện: không phải do thiếu cache |
| Tăng `wal_autocheckpoint` lên 20.000 trang | 39,5 | Không cải thiện |
| Tắt kiểm tra khóa ngoại | ~37,0 | Cải thiện nhỏ; không áp dụng (mất ràng buộc) |
| Bỏ 7 index phụ của `events` | 18,6 | Index chiếm khoảng một nửa chi phí |
| `batch_size` 20.000 | 23,0 | Cải thiện rõ |
| `batch_size` 50.000 | 18,5 | Nhanh hơn nữa nhưng peak RSS 279 MB |

Khóa chính là hash (ngẫu nhiên) và các index phụ khiến mỗi dòng chèn vào chạm một trang B-tree khác nhau. Khi index lớn, mỗi transaction 5.000 dòng làm bẩn gần như toàn bộ trang lá của index và phải ghi lại chúng. Gom nhiều dòng hơn vào một transaction làm giảm số lần ghi lại.

### Thay đổi đã áp dụng

1. Bỏ cột `events.raw_id` và index UNIQUE của nó (trùng với `event_id`); `event_id` trở thành khóa ngoại trực tiếp tới `raw_events`.
2. `PRAGMA cache_size` 64 MB và `temp_store = MEMORY`.
3. `batch_size` mặc định 5.000 -> 20.000.

Các index phụ được giữ lại vì truy vấn tìm kiếm cần chúng.

### So sánh trước và sau (cùng điều kiện: event nền thứ tự ngẫu nhiên)

| Events | Trước: tổng (s) | Sau bước 1-2 (s) | Sau bước 1-3 (s) | Trước: events/s | Sau: events/s | Trước: peak RSS | Sau: peak RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 10.000 | 0,406 | 0,402 | 0,376 | 24.649 | 26.566 | 39,1 MB | 41,3 MB |
| 100.000 | 7,019 | 5,509 | 4,752 | 14.246 | 21.045 | 45,1 MB | 121,8 MB |
| 500.000 | 64,205 | 51,157 | 34,290 | 7.788 | 14.582 | 45,3 MB | 161,4 MB |

Nguồn: `baseline.json`, `optimized_step1.json`, `optimized_random_order.json`.

Ở 500K, thời gian giảm 47% và tốc độ tăng 1,87 lần. **Cái giá phải trả là bộ nhớ**: peak RSS tăng từ 45 MB lên 161 MB (do cache 64 MB và lô lớn hơn). Nếu cần ít RAM hơn, giảm `batch_size` trong cấu hình.

Với file log đúng thứ tự thời gian (trường hợp thường gặp, bảng ở mục 3), 500K event mất 23,6 giây vì các index theo thời gian được chèn nối tiếp.

### Phân tích bộ nhớ

- Trước tối ưu, peak RSS gần như không đổi (39 -> 45 MB) từ 10K đến 500K: pipeline xử lý theo dòng, không nạp cả file vào RAM.
- Sau tối ưu, RSS tăng theo kích thước dữ liệu cho đến khi cache SQLite đầy rồi dừng (121 MB ở 100K, 162 MB ở 500K).
- Kiểm tra rò rỉ (`benchmarks/leak_check.py`): 30 chu kỳ trên database cố định 100K event, đo bằng `tracemalloc`: heap Python còn giữ sau mỗi chu kỳ 0,11 -> 0,12 MB (không tăng); RSS 189 -> 196 MB rồi đứng yên. Không phát hiện rò rỉ. Một thử nghiệm 40 chu kỳ trước đó cũng cho RSS ổn định quanh 244 MB.
- Rule SOC-002 nạp từng nhóm (IP nguồn, IP đích) vào RAM; một cặp IP có hàng triệu kết nối liên tục sẽ tốn nhiều bộ nhớ. Rule SOC-001 nạp toàn bộ event `failed_login` vào RAM (chỉ 5 cột).

### Còn lại chưa tối ưu

- Detection quét lại toàn bộ event mỗi lần (1,3 giây ở 500K, 7,1 giây ở 1,3 triệu trong soak test); chưa có chế độ tăng dần. Đây là giới hạn chính khi chạy lâu dài.
- Tìm văn bản dùng `LIKE '%...%'` (quét toàn bảng); có thể thay bằng FTS5.
- Kích thước database khoảng 0,75 MB cho mỗi 1.000 event.

## 5. Kiểm tra ổn định

Soak test 10 phút và 30 phút: xem `docs/stability_test_report.md` (mục Soak test). Tóm tắt: không lỗi, không dữ liệu trùng, số đếm khớp ground truth sau 1.312.000 event; thời gian detection mỗi lần chạy tăng tuyến tính theo tổng số event (0,05 -> 7,1 giây).

Kiểm tra ngắn trước đó, 60 giây: 19 chu kỳ liên tiếp, mỗi chu kỳ sinh 20.000 event mới, nhập và chạy detection, trong khi một luồng khác liên tục truy vấn dữ liệu dashboard.

| Chỉ số | Kết quả |
|---|---|
| Chu kỳ ghi | 19 |
| Lượt đọc đồng thời (Overview + Events + Incidents) | 404 |
| Exception | 0 |
| Event lưu được | 378.921, bằng đúng số dòng khác nhau trong 380.000 dòng sinh ra (phần còn lại là dòng trùng từng ký tự) |
| `integrity_check` / `foreign_key_check` | ok / không vi phạm |

## 6. Độ chính xác của detection

Nguồn: `benchmarks/results/accuracy_results.json`. Ma trận gồm 345 kịch bản tổng hợp có nhãn (69 loại kịch bản x 5 biến thể), mỗi kịch bản có thực thể riêng. Nhãn phản ánh **ý định của kịch bản** (là tấn công hay không), không phải việc rule có được kỳ vọng kích hoạt hay không. Ma trận cố ý chứa các tấn công mà rule dựa trên ngưỡng không bắt được và các hoạt động hợp lệ mà rule sẽ báo nhầm (các loại có tiền tố `HARD_`).

| Rule | Kịch bản | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SOC-001 SSH Brute Force | 75 | 30 | 5 | 10 | 30 | 0,857 | 0,750 | 0,800 | 0,143 |
| SOC-002 Port Scan | 55 | 25 | 5 | 5 | 20 | 0,833 | 0,833 | 0,833 | 0,200 |
| SOC-003 Suspicious Process | 85 | 35 | 15 | 10 | 25 | 0,700 | 0,778 | 0,737 | 0,375 |
| SOC-004 Network-to-Host Pivot | 60 | 20 | 5 | 15 | 20 | 0,800 | 0,571 | 0,667 | 0,200 |
| SOC-005 Web Attack | 70 | 35 | 10 | 10 | 15 | 0,778 | 0,778 | 0,778 | 0,400 |

SOC-005 (thêm 16/11/2026): đo riêng 200.000 request web bình thường (ngẫu nhiên, 3% lỗi 404) trên cùng máy: nhập 8,4 giây, rule SOC-005 chạy 1,47 giây, 0 alert báo nhầm. Benchmark 10K/100K/500K ở trên không có access log.

SOC-003 có thêm cặp kịch bản AppData (payload trong `AppData\Roaming` = tấn công; ứng dụng người dùng cài trong `AppData\Local\Programs` = báo nhầm có chủ đích). SOC-004 được viết lại hoàn toàn theo nghĩa của đề: alert HIGH vào máy nội bộ rồi máy đó kết nối tới máy nội bộ khác trong 5 phút.

Công thức: Precision = TP/(TP+FP); Recall = TP/(TP+FN); F1 = 2PR/(P+R); FPR = FP/(FP+TN).

Nguyên nhân sai:

| Rule | Bỏ sót (FN) | Báo nhầm (FP) |
|---|---|---|
| SOC-001 | Tấn công chậm 1 lần / 30 giây (5); password spraying từ 20 IP (5) | Script cấu hình sai thử 6 lần (5) |
| SOC-002 | Quét chậm 1 cổng / 5 giây (5) | Máy giám sát kiểm tra 20 cổng (5) |
| SOC-003 | Malware trong Program Files (5); payload trong Temp chạy qua msiexec (5) | Ứng dụng người dùng trong AppData\Local (5); công cụ portable từ Downloads (5); agent quản trị dùng PowerShell `-enc` (5) |
| SOC-004 | Kết nối nội bộ sau alert 6 phút (5); kẻ tấn công di chuyển trước khi IDS báo (5); NAT làm IP trong alert khác IP host (5) | IDS báo nhầm mức cao rồi máy truy cập file share bình thường (5) |
| SOC-005 | Dò thư mục chậm 1 request / 10 giây (5); SQL injection trong body của POST (5) | Tìm kiếm chữ "union select" (5); công cụ kiểm tra link chết gặp 30 lỗi 404 (5) |

Mọi kịch bản không thuộc nhóm `HARD_` (kể cả các giá trị biên 4/5/6 lần đăng nhập, 14/15/16 cổng, đúng 60 giây, đúng 300 giây) đều được phân loại đúng.

### Cách hiểu các con số này

- Dữ liệu là tổng hợp và do cùng một tác giả với các rule viết ra. Các tỷ lệ trên **phụ thuộc trực tiếp vào tỷ lệ kịch bản khó được đưa vào ma trận**; thêm hay bớt kịch bản `HARD_` sẽ làm thay đổi precision và recall. Chúng cho biết rule làm đúng theo đặc tả và chỉ ra rule sai ở loại tình huống nào, **không** phải độ chính xác trên dữ liệu thực tế.
- Việc đánh giá ở mức kịch bản (một kịch bản = một quyết định), không phải mức event.
- Chưa có dữ liệu log thật có nhãn, nên **không đủ dữ liệu** để ước lượng precision/recall trong môi trường thật.
