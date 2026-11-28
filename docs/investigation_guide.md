# Hướng dẫn điều tra

Tài liệu dành cho người đóng vai SOC Analyst sử dụng toolkit.

## 1. Chuẩn bị dữ liệu

```bash
python main.py init-db
python main.py run-sample        # hoặc: ingest từng file rồi `python main.py detect`
python main.py dashboard
```

Sau mỗi lần nhập thêm log, chạy lại `python main.py detect`. Chạy lại không tạo alert hay incident trùng.

## 2. Quy trình gợi ý

| Bước | Trang | Việc cần làm |
|---|---|---|
| 1. Nắm tình hình | Overview | Xem số incident đang mở, chỉ số giảm nhiễu (raw alerts -> incident), alert theo severity, Top Attacked Assets, Incident Timeline (Gantt) |
| 2. Chọn vụ việc | Incidents | Lọc theo status `NEW`, sắp theo severity; chọn incident, đọc mô tả |
| 3. Nhận xử lý | Incidents | Giao incident cho analyst ("Assign analyst", hoặc `python main.py assign --id N --analyst <tên>`), đổi status sang `IN_PROGRESS` kèm ghi chú |
| 4. Xem bằng chứng | Investigation | Đọc timeline tương tác (rê chuột xem chi tiết, kéo để zoom, lọc theo loại), mở từng alert để xem lý do (rationale) và evidence |
| 5. Đối chiếu log gốc | Investigation | Xem "Related events" và "Raw log evidence"; dùng ô tìm kiếm để lọc |
| 6. Mở rộng phạm vi | Events | Tìm theo IP nguồn / IP đích của incident trong khoảng thời gian liên quan để xem hoạt động khác của cùng IP |
| 7. Ghi nhận | Investigation | Thêm analyst note cho từng phát hiện |
| 8. Kết luận | Incidents | Đổi status sang `CLOSED` hoặc `FALSE_POSITIVE` kèm ghi chú lý do |
| 9. Báo cáo | Investigation | "Download incident report" (hoặc `python main.py report --id <N>`) |

## 3. Ý nghĩa trạng thái

| Status | Ý nghĩa |
|---|---|
| `NEW` | Mới tạo, chưa ai xử lý |
| `IN_PROGRESS` | Đang điều tra |
| `CLOSED` | Đã xử lý xong |
| `FALSE_POSITIVE` | Xác định không phải sự cố |

Mọi thay đổi trạng thái được lưu trong lịch sử (thời gian, người thực hiện, trạng thái cũ và mới, ghi chú). Hành vi tự động:

- Có alert liên quan mới trong khi incident đang mở: alert được gắn vào incident đó.
- Incident `CLOSED` nhận thêm event mới cho cùng một alert (đợt tấn công chưa dứt): tự mở lại thành `NEW`, lịch sử ghi `system`.
- Incident `FALSE_POSITIVE` nhận thêm event: giữ nguyên trạng thái, chỉ thêm ghi chú hệ thống.
- Đợt sự kiện mới sau khi incident đã đóng: tạo incident mới.

## 4. Cách đọc từng loại alert

### SOC-001 SSH Brute Force

- `evidence.pattern`: `failed_login_burst` (chỉ thất bại), `account_lockout`, `success_after_failures`.
- Với `success_after_failures` (CRITICAL): coi như tài khoản có thể đã bị lộ. Kiểm tra `successful_logins` để biết tài khoản và thời điểm; tìm trong trang Events mọi hoạt động của IP đó và của tài khoản đó sau thời điểm đăng nhập.
- Câu hỏi cần trả lời: IP nguồn có phải của tổ chức không? Tài khoản bị thử là tài khoản thật hay tên phổ biến (`root`, `admin`)? Có host nào khác bị cùng IP thử không?

### SOC-002 Internal Port Scan

- `evidence.ports` cho biết các cổng bị dò; `max_ports_in_window` cho biết tốc độ.
- Câu hỏi: máy nguồn có phải máy quét lỗ hổng / giám sát hợp lệ không? Nếu không, máy nguồn có thể đã bị chiếm quyền: tìm alert SOC-003 hoặc SOC-004 trên máy đó.

### SOC-003 Suspicious Process Execution

- `evidence.indicators` liệt kê dấu hiệu, `score` quyết định severity.
- Alert LOW chỉ có dấu hiệu vị trí là để **xem xét**, không phải kết luận malware. Kiểm tra `parent_process`, `command_line`, người dùng.
- Với PowerShell `-enc`: giải mã base64 (UTF-16LE) trong môi trường cô lập để xem nội dung. Không chạy lệnh đó.
- `notes` có `parent_unknown` / `command_line_unknown` nghĩa là log thiếu trường, cần lấy thêm dữ liệu từ máy.

### SOC-004 Network-to-Host Pivot

- `pivot_ip`: máy nội bộ bị IDS cảnh báo; `remote_ips`: đầu bên kia của alert; `alert_direction`: `inbound` (bị tấn công từ ngoài vào) hoặc `outbound` (ví dụ C2 đi ra).
- `internal_targets` (`ip:port`): các máy nội bộ mà máy pivot kết nối tới sau alert; `first_delay_seconds`: bao lâu sau alert thì bắt đầu. Cổng 445 (SMB), 3389 (RDP), 5985/5986 (WinRM), 22 (SSH) là các cổng lateral movement điển hình.
- `processes`: tiến trình trên máy pivot tạo kết nối. `rundll32.exe`, `powershell.exe`, `wmic.exe` kết nối SMB/RDP là dấu hiệu mạnh.
- CRITICAL khi máy pivot chạm từ 3 máy nội bộ trở lên.
- Câu hỏi: signature của IDS là gì? Các máy trong `internal_targets` có alert SOC-001/SOC-003 nào sau đó không (tìm theo IP trong trang Events/Incidents)? Cách ly máy pivot nếu xác nhận.

## 5. Dòng log bị từ chối

Overview hiển thị "Rejected Lines". Dòng bị từ chối nằm trong bảng `raw_events` với `status = 'rejected'` và cột `error` (ví dụ `invalid_ip: src_ip=999.1.1.1`). Số lượng lớn bất thường có thể do chọn sai `--source` cho file, sai định dạng export, hoặc log bị hỏng.

## 6. Lưu ý an toàn

- Dữ liệu trong log do bên ngoài kiểm soát (username, URL, command line). Dashboard hiển thị chúng dạng văn bản thuần và báo cáo Markdown đã escape ký tự đặc biệt, nhưng không nên dán nội dung log vào công cụ khác mà không kiểm tra.
- Không kết nối tới IP đáng ngờ từ máy làm việc để "kiểm tra thử".
- Dashboard không có xác thực; chỉ chạy trên máy cá nhân.
