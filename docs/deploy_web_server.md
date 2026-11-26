# Dùng SOC Toolkit để giám sát một website mở cổng 80 ra Internet

## 1. Toolkit đứng ở đâu so với website?

Toolkit **không chạy bên trong trang web** và **không chặn** request nào. Nó chạy bên cạnh máy chủ web: đọc các file log mà máy chủ và cảm biến mạng ghi ra, phát hiện dấu hiệu tấn công, rồi tạo alert/incident cho bạn xem trên dashboard.

```
 Internet ──► router / NAT (mở cổng 80) ──► MÁY CHỦ WEB (nginx / Apache / IIS / XAMPP)
                                              │  Suricata nghe card mạng   -> /var/log/suricata/eve.json
                                              │  sshd ghi đăng nhập         -> /var/log/auth.log      (Linux)
                                              │  Sysmon ghi tiến trình/kết nối -> file JSON export   (Windows)
                                              │  nginx/Apache ghi từng request -> /var/log/nginx/access.log
                                              ▼
                                   python main.py watch   (mỗi 60 giây đọc phần log mới + chạy 4 rule)
                                              ▼
                                   data/soc.db  ──►  dashboard Streamlit (chỉ 127.0.0.1:8501)
```

Muốn **chặn** tấn công thì cần thêm tường lửa / WAF (ufw, fail2ban, ModSecurity, Suricata chế độ IPS). Đó là việc khác, nằm ngoài đề tài.

## 2. Mở website ra cổng 80 thì toolkit thấy được gì?

| Chuyện xảy ra với website | Ai ghi log | Rule nào báo | Ghi chú |
|---|---|---|---|
| Bot trên Internet dò mật khẩu SSH của máy chủ (rất phổ biến khi máy có IP công khai) | `auth.log` | **SOC-001** | Chạy được ngay. Bật `require_followup` nếu chỉ muốn báo khi bị đăng nhập được |
| Request HTTP chứa SQL injection, XSS, path traversal, command injection / Log4Shell | **access log** của nginx/Apache | **SOC-005** Web Attack: MEDIUM; HIGH khi server trả 2xx cho request tấn công | Chạy được cả khi website dùng HTTPS (access log ghi request sau khi giải mã). Suricata cũng có thể báo (`ids_alert`), nhưng một alert Suricata đứng riêng không tự tạo incident |
| Công cụ quét website (sqlmap, nikto, gobuster...), dò thư mục (nhiều lỗi 404), dò file nhạy cảm (`/.env`, `/.git/`) | access log | **SOC-005**: LOW (dò thám) hoặc MEDIUM (≥ 20 lỗi 4xx trong 60 giây) | Một bot dò `/.env` lẻ tẻ không bị báo (cần ≥ 3 lần) |
| Ai đó quét cổng máy chủ (nmap) | Suricata flow | **SOC-002**, *chỉ khi máy quét ở mạng nội bộ* | Mặc định `port_scan.internal_only = true`. Muốn bắt cả máy quét trên Internet: đặt `false` (sẽ rất nhiều cảnh báo, vì Internet bị quét liên tục) |
| Kẻ tấn công khai thác lỗi web rồi cài **webshell**: `httpd.exe` / `w3wp.exe` / `php-cgi.exe` sinh ra `cmd.exe` / `powershell.exe` | Sysmon (máy chủ Windows) | **SOC-003** (`web_server_spawned_shell`, +3 điểm) | Có thêm từ bản này |
| Sau khi chiếm máy chủ web, kẻ tấn công từ đó kết nối sang máy khác trong mạng (SMB 445, RDP 3389...) | Suricata (alert mức cao vào máy chủ) + Sysmon (kết nối từ máy chủ) | **SOC-004** Pivot | Đúng kịch bản "máy chủ web bị chiếm rồi lây sang mạng trong". Cần Suricata thấy **IP nội bộ** của máy chủ (chạy Suricata ngay trên máy chủ, không đặt sau NAT) |
| Tải file độc vào thư mục Temp/AppData rồi chạy | Sysmon | **SOC-003** | |

Các bước gộp alert vẫn giữ nguyên: mọi alert cùng một IP trong 30 phút nhập vào **một incident**. Ví dụ IP 198.51.100.9 dò SSH (SOC-001) rồi gửi SQL injection vào website (SOC-005): hai alert, một incident để analyst xử lý (kịch bản S01 + S27 của dữ liệu mẫu).

## 3. Cài đặt trên máy chủ Linux (Ubuntu) — cách nên dùng

Các lệnh dưới đây là cấu hình tham khảo, chưa được chạy thử trên máy chủ thật trong dự án này.

**Bước 1. Suricata**

```bash
sudo apt install suricata
sudo suricata-update                      # tải bộ luật ET Open (có luật tấn công web)
```

Trong `/etc/suricata/suricata.yaml`:

- `HOME_NET`: dải mạng nội bộ của bạn, ví dụ `"[192.168.1.0/24]"`.
- `af-packet` → `interface`: card mạng nhận request web, ví dụ `eth0`.
- `outputs` → `eve-log` → `types`: **chỉ để** `alert`, `http`, `dns`, `flow`. Toolkit chỉ đọc 4 loại này. Các loại khác (stats, tls, fileinfo...) sẽ bị ghi là dòng `rejected` và làm database phình to.

```bash
sudo systemctl enable --now suricata
```

**Bước 2. Toolkit**

```bash
sudo mkdir -p /opt/soc && sudo chown $USER /opt/soc
cp -r DoAnSOC/* /opt/soc/ && cd /opt/soc
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python main.py init-db
sudo usermod -aG adm $USER                # nhóm adm được đọc /var/log/auth.log và log Suricata
```

Đặt tên máy chủ web (access log không ghi tên máy) trong `config/settings.json`, ví dụ `{"web_server_name": "web01"}`. Người dùng của dịch vụ cần đọc được `/var/log/nginx/access.log`; trên Ubuntu file này thuộc nhóm `adm`.

Toolkit đọc định dạng log mặc định của nginx (`combined`) và Apache (`combined` hoặc `common`). Nếu bạn đã đổi `log_format` thì giữ nguyên phần đầu `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`; phần thêm phía sau được bỏ qua.

Múi giờ: Ubuntu 24.04 ghi `auth.log` dạng `2026-11-16T07:41:00+07:00 ...` (có múi giờ), không cần chỉnh gì. Bản cũ ghi `Nov 16 07:41:00 ...` (không có múi giờ); khi đó tạo `config/settings.json` với `{"syslog_utc_offset_minutes": 420}` (UTC+7) để thời gian được đổi đúng sang UTC.

**Bước 3. Chạy giám sát liên tục**

Chạy thử:

```bash
python main.py watch --input linux_auth=/var/log/auth.log \
                     --input suricata=/var/log/suricata/eve.json \
                     --input web_access=/var/log/nginx/access.log --interval 60
```

Mỗi vòng in ra một dòng JSON, ví dụ `{"cycle": 3, "new_events": 120, "alerts_new": 1, ...}`. Lệnh `watch`:

- chỉ đọc phần log mới ghi thêm từ vòng trước;
- không nhận dòng đang ghi dở;
- tự đọc lại từ đầu khi logrotate tạo file mới;
- chỉ chạy rule khi có dữ liệu mới;
- gặp file lỗi hoặc chưa có thì ghi vào `errors` và thử lại ở vòng sau.

Để chạy nền như một dịch vụ, tạo `/etc/systemd/system/soc-watch.service`:

```ini
[Unit]
Description=SOC Toolkit log watcher
After=network.target suricata.service

[Service]
User=socuser
Group=adm
WorkingDirectory=/opt/soc
ExecStart=/opt/soc/.venv/bin/python main.py watch --input linux_auth=/var/log/auth.log --input suricata=/var/log/suricata/eve.json --input web_access=/var/log/nginx/access.log --interval 60
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now soc-watch
journalctl -u soc-watch -f                # xem từng vòng
```

**Bước 4. Xem dashboard — KHÔNG mở ra Internet**

Dashboard không có đăng nhập, ai vào được là đọc được toàn bộ log và đổi được trạng thái incident. Vì vậy `python main.py dashboard` chỉ nghe ở `127.0.0.1:8501`. Để xem từ máy của bạn, dùng đường hầm SSH:

```bash
# trên máy của bạn
ssh -L 8501:127.0.0.1:8501 user@ip-may-chu
# rồi mở http://localhost:8501
```

Tường lửa của máy chủ chỉ nên mở 80/443 cho mọi người, và 22 cho IP của bạn:

```bash
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw allow from <IP-cua-ban> to any port 22
sudo ufw enable
```

Nếu buộc phải xem dashboard qua chính website (ví dụ khi demo), đặt nó sau nginx với HTTPS và mật khẩu, ở một đường dẫn riêng. Không trỏ thẳng cổng 80 vào Streamlit:

```nginx
location /soc/ {
    auth_basic "SOC";
    auth_basic_user_file /etc/nginx/.htpasswd;      # tạo bằng: htpasswd -c /etc/nginx/.htpasswd admin
    proxy_pass http://127.0.0.1:8501/soc/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;          # Streamlit cần WebSocket
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

Khi đó chạy Streamlit với `--server.baseUrlPath soc`:

```bash
.venv/bin/python -m streamlit run ui/dashboard.py --server.address 127.0.0.1 --server.baseUrlPath soc
```

## 4. Nếu website chạy trên máy Windows (IIS, XAMPP)

- Windows không có `auth.log`, nên SOC-001 chỉ dùng được khi có máy Linux khác gửi log về.
- **Sysmon**: cài từ Microsoft Sysinternals với một file cấu hình (ví dụ cấu hình của SwiftOnSecurity). Sysmon ghi vào Event Log (EVTX), toolkit lại đọc JSON, nên cần xuất định kỳ. Đoạn PowerShell dưới đây tạo đúng dạng "flat" mà `ingestors/sysmon.py` đọc được. Dạng JSON đã được kiểm tra bằng parser, còn script thì chưa chạy thử trên Windows:

```powershell
# chạy bằng quyền Administrator, ví dụ mỗi phút bằng Task Scheduler
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5000 |
  Where-Object { $_.Id -in 1, 3, 11 } |
  ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = [ordered]@{ EventID = $_.Id; Computer = $_.MachineName }
    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    $data | ConvertTo-Json -Compress
  } | Out-File -Encoding utf8 C:\SOC\logs\sysmon.jsonl
```

  Mỗi lần chạy, script ghi đè file bằng 5000 event mới nhất. `watch` thấy file mới ngắn hơn thì đọc lại từ đầu, và event đã nhập bị bỏ qua nhờ mã băm của dòng.
- **Suricata cho Windows**: cài bản Windows cùng Npcap, cấu hình `eve-log` như mục 3.
- **Access log**: XAMPP (Apache) ghi `C:\xampp\apache\logs\access.log` theo định dạng combined, đọc được ngay. **IIS** mặc định ghi định dạng W3C (`#Fields: date time s-ip ...`), toolkit **chưa đọc được**. Hoặc đổi IIS sang định dạng NCSA (trong IIS Manager → Logging → Format: NCSA; đây là định dạng common, đọc được nhưng không có User-Agent), hoặc viết thêm một ingestor W3C.
- Chạy watch:

```powershell
python main.py watch --input sysmon=C:\SOC\logs\sysmon.jsonl --input suricata="C:\Program Files\Suricata\log\eve.json" --input web_access=C:\xampp\apache\logs\access.log
```

## 5. Thử nghiệm an toàn (chỉ trên máy của chính bạn hoặc phòng lab)

| Muốn thấy | Làm từ một máy khác **trong mạng nội bộ** | Kết quả mong đợi |
|---|---|---|
| SOC-001 | 6 lần `ssh wronguser@may-chu` gõ sai mật khẩu trong 1 phút | Alert SSH Brute Force (MEDIUM), lên CRITICAL nếu sau đó đăng nhập đúng |
| SOC-002 | `nmap -p 1-100 <ip-may-chu>` | Alert Internal Port Scan |
| SOC-005 (SQL injection) | `curl "http://<ip-may-chu>/?id=1%27%20OR%20%271%27=%271"` | Alert Web Attack (MEDIUM; HIGH nếu trang trả 200), và thường thêm `ids_alert` của Suricata (luật ET về SQL injection) |
| SOC-005 (dò thư mục) | `for i in $(seq 1 30); do curl -s -o /dev/null http://<ip-may-chu>/khong-co-$i; done` | Alert Web Attack, pattern `error_burst` |
| SOC-003 (Windows) | Trên máy chủ: chạy `powershell -w hidden -enc <base64>` | Alert Suspicious Process |

Không quét hay tấn công hệ thống không thuộc quyền của bạn.

## 6. Giới hạn cần nói rõ khi bảo vệ đồ án

- SOC-005 chỉ thấy những gì access log ghi: URL, mã trả về, User-Agent. **Nội dung POST (body) không có trong log**, nên SQL injection gửi qua form POST không bị thấy (cần WAF như ModSecurity). Dò thư mục chậm (dưới 20 lỗi / phút) cũng lọt.
- SOC-005 dựa trên mẫu chữ nên có báo nhầm: người dùng tìm kiếm chữ "union select", công cụ kiểm tra link chết gặp nhiều 404 (đo được trong `benchmarks/results/accuracy_results.md`).
- Chưa đọc log IIS định dạng W3C.
- Không thời gian thực tuyệt đối: độ trễ bằng `--interval` (mặc định 60 giây).
- SQLite phù hợp một máy chủ, lưu lượng vừa phải. Nhiều máy chủ gửi log về một chỗ thì nên dùng SIEM thật (Wazuh, Elastic, Splunk).
- Dashboard không có tài khoản người dùng (xem mục 3, bước 4).
