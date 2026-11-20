# Unified Event Schema (phiên bản 2)

Phiên bản 2 (16/11/2026) thêm `url`, `http_status`, `user_agent` cho access log web; database cũ được thêm cột tự động khi chạy `init-db`.

Mọi event từ bốn nguồn được đưa về cùng một cấu trúc (`normalizer/models.py::UnifiedEvent`).

```json
{
  "event_id": "9f2c1a7b3d4e5f60718293a4b5c6d7e8",
  "schema_version": 2,
  "timestamp_utc": "2026-11-13T10:00:01Z",
  "source_type": "linux_auth",
  "hostname": "server",
  "username": "root",
  "src_ip": "192.168.1.100",
  "dst_ip": null,
  "src_port": 2222,
  "dst_port": null,
  "protocol": null,
  "action": "failed_login",
  "severity": 2,
  "message": "Failed SSH login",
  "process_name": "sshd",
  "process_path": null,
  "command_line": null,
  "parent_process": null,
  "raw_event": {"raw": "Nov 13 10:00:01 server sshd[1234]: Failed password for root from 192.168.1.100 port 2222 ssh2"}
}
```

## Các trường

| Trường | Kiểu | Bắt buộc | Mô tả |
|---|---|---|---|
| `event_id` | chuỗi 32 hex | Có | 32 ký tự đầu SHA-256 của `source_type + "\n" + dòng log` |
| `schema_version` | số nguyên | Có | Hiện là 1 |
| `timestamp_utc` | ISO-8601, đuôi `Z` | Có | Luôn là UTC; có phần thập phân khi nguồn có |
| `source_type` | chuỗi | Có | `linux_auth`, `suricata`, `sysmon` |
| `action` | chuỗi | Có | Xem bảng action |
| `severity` | 1-5 | Có | 1 INFO, 2 LOW, 3 MEDIUM, 4 HIGH, 5 CRITICAL |
| `message` | chuỗi | Có | Mô tả ngắn |
| `hostname`, `username` | chuỗi | Không | |
| `src_ip`, `dst_ip` | chuỗi IP chuẩn | Không | IPv4/IPv6, đã chuẩn hóa bằng `ipaddress` |
| `src_port`, `dst_port` | 0-65535 | Không | |
| `protocol` | chuỗi in hoa | Không | `TCP`, `UDP`, ... |
| `process_name`, `process_path`, `command_line`, `parent_process` | chuỗi | Không | Chủ yếu từ Sysmon |
| `url`, `http_status`, `user_agent` | chuỗi / số / chuỗi | Không | Chỉ access log web: đường dẫn + query string (chưa giải mã), mã trả về 100-599, User-Agent |
| `raw_event` | object | Có | Linux: `{"raw": "<dòng gốc>"}`; Suricata/Sysmon: object JSON gốc |

Trong SQLite còn cột `ts_epoch` (số thực, giây) để lọc và sắp xếp theo thời gian.

## Action theo nguồn

| Nguồn | Điều kiện | `action` | Severity |
|---|---|---|---|
| linux_auth | `Failed <method> for ...` (sshd) | `failed_login` | 2 |
| linux_auth | `Accepted <method> for ...` (sshd) | `successful_login` | 1 |
| linux_auth | `Invalid user ...` (sshd) | `invalid_user` | 2 |
| linux_auth | pam_faillock / pam_tally khóa tài khoản | `account_lockout` | 3 |
| linux_auth | `sudo: <user> : ... USER=<target> ; COMMAND=<cmd>` (sudo thành công) | `sudo_command` (`command_line` = lệnh, message ghi user đích) | 1 |
| linux_auth | `sudo: <user> : N incorrect password attempts ; ...` | `sudo_auth_failure` | 2 |
| linux_auth | `pam_unix(<service>:auth): authentication failure; ...` | `auth_failure` (không tính là SSH failed login) | 2 |
| linux_auth | Dòng syslog hợp lệ khác | `other` | 1 |
| web_access | Mọi dòng access log nginx/Apache (combined hoặc common) | `web_request` (`protocol` = `HTTP`, `hostname` = `web_server_name` trong cấu hình, message dạng `GET /path -> 404`) | 1; 2 khi mã 5xx |
| suricata | `event_type = alert` | `ids_alert` | Suricata 1/2/3 -> 4/3/2; thiếu -> 2 |
| suricata | `dns` / `http` / `flow` | `dns_query` / `http_request` / `network_flow` | 1 |
| sysmon | Event ID 1 / 3 / 11 | `process_creation` / `network_connection` / `file_create` | 1 |

## Ánh xạ trường

| Unified | Linux auth | Suricata EVE | Sysmon |
|---|---|---|---|
| `timestamp_utc` | Tiêu đề syslog | `timestamp` | `UtcTime` (hoặc `TimeCreated`, `@timestamp`) |
| `hostname` | Hostname syslog | `host` (tên sensor, nếu có) | `Computer` |
| `username` | Tên trong thông điệp | - | `User` |
| `src_ip` / `src_port` | `from <ip> port <n>` | `src_ip` / `src_port` | `SourceIp` / `SourcePort` |
| `dst_ip` / `dst_port` | - | `dest_ip` / `dest_port` | `DestinationIp` / `DestinationPort` |
| `protocol` | - | `proto` | `Protocol` |
| `process_name` | Tên tiến trình syslog | - | Tên file của `Image` |
| `process_path` | - | - | `Image` |
| `command_line` | - | - | `CommandLine` |
| `parent_process` | - | - | `ParentImage` |
| `message` | Theo action | `alert.signature`, tên DNS, URL | Theo Event ID |

## Quy tắc validate

Phân biệt hai trường hợp:

| Trường hợp | Xử lý |
|---|---|
| Trường **tùy chọn bị thiếu** (hoặc rỗng, `-`) | Lưu `null`; event vẫn hợp lệ |
| Trường **bắt buộc bị thiếu** (timestamp, `event_type`, `EventID`, `Image` của Event ID 1, hostname của syslog) | Từ chối: `missing_required_field` |
| Giá trị **có mặt nhưng sai** | Từ chối: `invalid_timestamp`, `invalid_ip`, `invalid_port`, `unexpected_field_type` |
| Dòng không parse được | Từ chối: `malformed_syslog_line`, `malformed_json`, `not_a_json_object` |
| Loại event không hỗ trợ | Từ chối: `unsupported_event_type` |
| Dòng dài hơn `max_line_length` | Từ chối: `line_too_long` |

Dòng bị từ chối vẫn nằm trong `raw_events` cùng lý do, nên không mất dấu vết. Hệ thống không bao giờ tự điền giá trị thay cho dữ liệu thiếu.

## Timestamp

- ISO-8601 có offset (`+07:00`, `+0000`, `Z`) được đổi về UTC.
- Không có offset: coi là UTC.
- Syslog cổ điển (`Nov 13 10:00:01`) không có năm: dùng `syslog_default_year`; nếu không cấu hình thì lấy năm hiện tại và lùi một năm khi kết quả nằm trong tương lai hơn một ngày. Múi giờ lấy từ `syslog_utc_offset_minutes`.
- Số (epoch giây hoặc mili giây) cũng được chấp nhận.
- Năm ngoài khoảng 1970-2100 bị từ chối.

## Giới hạn độ dài

Chuỗi văn bản bị cắt ở 8192 ký tự (`command_line`, `process_path`), 500 ký tự (`message`), 255 ký tự (hostname, username).
