"""Generate the labelled synthetic sample dataset and its ground truth.

Usage:  python -m datasets.generate_dataset   (or: python main.py generate-dataset)

Output: datasets/raw/{linux_auth.log,suricata_eve.jsonl,sysmon.jsonl}
        datasets/ground_truth/scenarios.json
The data is SYNTHETIC. It is not the result of a real attack.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

from datasets import synth as s

DATASET_YEAR = 2026
WEB_SERVER_NAME = "web01"        # access log không ghi tên máy; run-sample gán tên này
SEED = 42
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def build() -> tuple[dict[str, list[str]], dict[str, Any]]:
    """Return ({file name: lines}, ground truth)."""
    rng = random.Random(SEED)
    linux: list[tuple[float, str]] = []
    suri: list[tuple[float, str]] = []
    sysm: list[tuple[float, str]] = []
    web: list[tuple[float, str]] = []
    scenarios: list[dict[str, Any]] = []
    counter = iter(range(1, 10_000_000))

    def scenario(sid: str, description: str, source: str, n_events: int, rule_id: str | None,
                 severity: int | None, entity: dict[str, Any], behavior: str, *, occurrences: int = 1,
                 incident_group: str | None = None, label: str | None = None) -> None:
        """Register one labelled scenario.

        occurrences    raw detections expected to be deduplicated into this one alert
        incident_group scenarios sharing a group are expected to end up in ONE incident
        label          "attack" / "benign" ground-truth label (default: attack if an alert is expected)
        """
        scenarios.append({
            "scenario_id": sid, "description": description, "input": {"source": source, "events": n_events},
            "label": label or ("attack" if rule_id else "benign"),
            "expected_behavior": behavior, "expected_alert": rule_id is not None, "expected_rule_id": rule_id,
            "expected_severity": severity, "expected_occurrences": occurrences if rule_id else 0,
            "expected_incident": rule_id is not None, "incident_group": incident_group or sid, "entity": entity})

    # ---------------------------------------------------------------- benign noise
    servers = ["web01", "db01", "app01"]
    for i in range(240):
        t = rng.uniform(0, 7200)
        host = rng.choice(servers)
        client = f"10.0.1.{rng.randint(10, 60)}"
        pid = 2000 + next(counter)
        kind = rng.random()
        if kind < 0.55:
            linux.append((t, s.linux_accepted(s.at(t), host, rng.choice(["deploy", "ops", "alice"]), client,
                                              rng.randint(30000, 60000), pid, "publickey")))
        elif kind < 0.65:
            linux.append((t, s.linux_failed(s.at(t), host, "ops", f"10.0.2.{i % 200 + 10}",
                                            rng.randint(30000, 60000), pid)))
        else:
            linux.append((t, s.linux_other(s.at(t), host, pid)))
    common_ports = [80, 443, 53, 22, 3389, 445, 8080]
    for i in range(320):
        t = rng.uniform(0, 7200)
        client = f"10.0.1.{rng.randint(10, 60)}"
        server = f"10.0.0.{rng.randint(2, 9)}"
        fid = next(counter)
        kind = rng.random()
        if kind < 0.6:
            suri.append((t, s.suricata_flow(s.at(t), client, rng.randint(30000, 60000), server,
                                            rng.choice(common_ports), fid)))
        elif kind < 0.8:
            suri.append((t, s.suricata_dns(s.at(t), client, "10.0.0.2", f"host{i}.corp.example", fid)))
        else:
            suri.append((t, s.suricata_http(s.at(t), client, server, "intranet.corp.example", f"/page/{i}", fid)))
    for i in range(260):
        t = rng.uniform(0, 7200)
        ws = f"WS{rng.randint(5, 20):02d}"
        pid = 5000 + next(counter)
        kind = rng.random()
        if kind < 0.45:
            sysm.append((t, s.sysmon_process(s.at(t), ws, r"C:\Program Files\Office\WINWORD.EXE",
                                             f"WINWORD.EXE /n report{i}.docx", r"C:\Windows\explorer.exe", pid=pid)))
        elif kind < 0.8:
            sysm.append((t, s.sysmon_network(s.at(t), ws, r"C:\Program Files\Browser\browser.exe",
                                             f"10.0.1.{rng.randint(10, 60)}", rng.randint(30000, 60000),
                                             f"10.0.0.{rng.randint(2, 9)}", rng.choice([80, 443]), pid=pid)))
        else:
            sysm.append((t, s.sysmon_file(s.at(t), ws, r"C:\Windows\explorer.exe",
                                          rf"C:\Users\user\Documents\file{i}.txt", pid)))

    # ------------------------------------------------------------ SSH scenarios
    for k in range(6):
        t = 600 + 8 * k
        linux.append((t, s.linux_failed(s.at(t), "web01", "root", "203.0.113.10", 41000 + k, 9100 + k)))
    scenario("S01", "6 failed SSH logins in 40s from one IP (no success)", "linux_auth", 6, "SOC-001", 3,
             {"src_ip": "203.0.113.10", "hostname": "web01"}, "Alert: brute force burst")
    for k in range(8):
        t = 1200 + 5 * k
        linux.append((t, s.linux_failed(s.at(t), "db01", "admin", "198.51.100.23", 42000 + k, 9200 + k)))
    linux.append((1245, s.linux_accepted(s.at(1245), "db01", "admin", "198.51.100.23", 42100, 9299)))
    scenario("S02", "8 failed SSH logins then a successful login from the same IP", "linux_auth", 9,
             "SOC-001", 5, {"src_ip": "198.51.100.23", "hostname": "db01"},
             "Alert escalated to CRITICAL: success after failures")
    for k in range(6):
        t = 1800 + 5 * k
        linux.append((t, s.linux_failed(s.at(t), "app01", "alice", "192.0.2.77", 43000 + k, 9300 + k)))
    linux.append((1827, s.linux_lockout(s.at(1827), "app01", "alice", 9399)))
    scenario("S03", "6 failed SSH logins followed by account lockout", "linux_auth", 7, "SOC-001", 4,
             {"src_ip": "192.0.2.77", "hostname": "app01"}, "Alert escalated to HIGH: account lockout")
    for k in range(4):
        t = 2400 + 7 * k
        linux.append((t, s.linux_failed(s.at(t), "web01", "root", "203.0.113.44", 44000 + k, 9400 + k)))
    scenario("S04", "4 failed SSH logins in 60s (below threshold)", "linux_auth", 4, None, None,
             {"src_ip": "203.0.113.44", "hostname": "web01"}, "No alert")
    for k in range(5):
        t = 3000 + 150 * k
        linux.append((t, s.linux_failed(s.at(t), "web01", "root", "203.0.113.55", 45000 + k, 9500 + k)))
    scenario("S05", "5 failed SSH logins spread over 10 minutes (outside window)", "linux_auth", 5, None, None,
             {"src_ip": "203.0.113.55", "hostname": "web01"}, "No alert")
    linux.append((3600, s.linux_accepted(s.at(3600), "web01", "ops", "10.0.3.15", 46000, 9600)))
    scenario("S06", "Single successful login without prior failures", "linux_auth", 1, None, None,
             {"src_ip": "10.0.3.15", "hostname": "web01"}, "No alert")

    # ------------------------------------------------------ port scan scenarios
    for k in range(25):
        t = 4200 + 0.8 * k
        suri.append((t, s.suricata_flow(s.at(t), "10.0.0.50", 50000 + k, "10.0.0.20", 20 + k, next(counter))))
    scenario("S07", "25 distinct destination ports in 20s", "suricata", 25, "SOC-002", 3,
             {"src_ip": "10.0.0.50", "dst_ip": "10.0.0.20"}, "Alert: port scan")
    for k in range(14):
        t = 4800 + 1.4 * k
        suri.append((t, s.suricata_flow(s.at(t), "10.0.0.51", 50000 + k, "10.0.0.21", 20 + k, next(counter))))
    scenario("S08", "14 distinct destination ports in 20s (below threshold)", "suricata", 14, None, None,
             {"src_ip": "10.0.0.51", "dst_ip": "10.0.0.21"}, "No alert")
    for k in range(20):
        t = 5000 + 40 * k
        suri.append((t, s.suricata_flow(s.at(t), "10.0.0.52", 50000 + k, "10.0.0.22", 20 + k, next(counter))))
    scenario("S09", "20 distinct ports, one every 40s (outside window)", "suricata", 20, None, None,
             {"src_ip": "10.0.0.52", "dst_ip": "10.0.0.22"}, "No alert")

    # ------------------------------------------------------- process scenarios
    sysm.append((5400, s.sysmon_process(s.at(5400), "WS01", PS, f"powershell.exe -nop -w hidden -enc {ENCODED}",
                                        r"C:\Program Files\Microsoft Office\WINWORD.EXE", pid=7001)))
    scenario("S10", "Office spawns hidden encoded PowerShell", "sysmon", 1, "SOC-003", 5,
             {"hostname": "WS01"}, "Alert: multiple suspicious indicators")
    sysm.append((5500, s.sysmon_process(s.at(5500), "WS03", r"C:\Users\bob\AppData\Local\Temp\invoice_viewer.exe",
                                        "invoice_viewer.exe", r"C:\Windows\explorer.exe", pid=7002)))
    scenario("S11", "Unknown executable started from AppData Temp (location only)", "sysmon", 1, "SOC-003", 2,
             {"hostname": "WS03"}, "LOW alert for review (not declared malware)")
    sysm.append((5600, s.sysmon_process(s.at(5600), "WS04", r"C:\Users\carol\AppData\Local\Temp\7zS4F2\setup.exe",
                                        "setup.exe /quiet", r"C:\Windows\System32\msiexec.exe", pid=7003)))
    scenario("S12", "Installer in Temp started by msiexec (trusted parent)", "sysmon", 1, None, None,
             {"hostname": "WS04"}, "No alert (false-positive reduction)")
    sysm.append((5700, s.sysmon_process(s.at(5700), "WS21", r"C:\Program Files\App\app.exe", "app.exe --start",
                                        r"C:\Windows\explorer.exe", pid=7004)))
    scenario("S13", "Normal process from Program Files", "sysmon", 1, None, None, {"hostname": "WS21"}, "No alert")

    # --------------------------------------------------------- pivot scenarios
    rundll = r"C:\Windows\System32\rundll32.exe"
    suri.append((6000, s.suricata_alert(s.at(6000), "203.0.113.99", 51515, "10.0.0.30", 445,
                                        "SYNTHETIC EXPLOIT SMB remote code execution attempt", 1, next(counter))))
    sysm.append((6002, s.sysmon_network(s.at(6002), "WS02", "System", "203.0.113.99", 51515, "10.0.0.30", 445,
                                        initiated=False, pid=4)))          # the exploit itself, seen on the host
    sysm.append((6060, s.sysmon_network(s.at(6060), "WS02", rundll, "10.0.0.30", 49777, "10.0.0.40", 445,
                                        initiated=True, pid=7010)))
    sysm.append((6075, s.sysmon_network(s.at(6075), "WS02", rundll, "10.0.0.30", 49778, "10.0.0.41", 3389,
                                        initiated=True, pid=7010)))
    scenario("S14", "High-severity Suricata alert on 10.0.0.30, which then opens SMB/RDP connections to two "
             "other internal hosts (lateral movement)", "suricata+sysmon", 3, "SOC-004", 4,
             {"src_ip": "10.0.0.30", "hostname": "WS02"}, "Alert: network-to-host pivot")
    suri.append((6300, s.suricata_alert(s.at(6300), "203.0.113.120", 51616, "10.0.0.31", 80,
                                        "SYNTHETIC WEB suspicious user-agent", 2, next(counter))))
    scenario("S15", "Suricata alert without any Sysmon connection", "suricata", 1, None, None,
             {"src_ip": "10.0.0.31"}, "No pivot alert", label="attack")
    suri.append((6600, s.suricata_alert(s.at(6600), "203.0.113.130", 51717, "10.0.0.32", 445,
                                        "SYNTHETIC EXPLOIT SMB overflow attempt", 1, next(counter))))
    sysm.append((7800, s.sysmon_network(s.at(7800), "WS22", rundll, "10.0.0.32", 49888, "10.0.0.45", 445,
                                        initiated=True, pid=7020)))
    scenario("S16", "High-severity alert, internal connection only 20 minutes later (outside the 300 s window)",
             "suricata+sysmon", 2, None, None, {"src_ip": "10.0.0.32"}, "No pivot alert", label="attack")
    suri.append((6700, s.suricata_alert(s.at(6700), "203.0.113.140", 51818, "10.0.0.33", 80,
                                        "SYNTHETIC POLICY outdated browser", 3, next(counter))))
    sysm.append((6730, s.sysmon_network(s.at(6730), "WS23", r"C:\Program Files\Backup\agent.exe", "10.0.0.33",
                                        49900, "10.0.0.46", 445, initiated=True, pid=7030)))
    scenario("S18", "Low-severity Suricata alert followed by a normal internal connection", "suricata+sysmon", 2,
             None, None, {"src_ip": "10.0.0.33"}, "No pivot alert (alert is not high severity)")

    # ------------------------------------------------ deduplication and correlation
    for k in range(4):                     # one attacker repeats the brute force every 3 minutes
        for j in range(6):
            t = 2600 + 180 * k + 5 * j
            linux.append((t, s.linux_failed(s.at(t), "web02", "root", "198.51.100.77", 47000 + 10 * k + j,
                                            9700 + 10 * k + j)))
    scenario("S19", "Same IP repeats a 6-failure SSH burst 4 times, 3 minutes apart", "linux_auth", 24, "SOC-001", 3,
             {"src_ip": "198.51.100.77", "hostname": "web02"},
             "ONE deduplicated alert with 4 occurrences (cooldown 600 s), one incident", occurrences=4)
    for k in range(20):                    # a compromised internal host scans, then brute-forces a server
        t = 5200 + 0.5 * k
        suri.append((t, s.suricata_flow(s.at(t), "10.0.0.61", 52000 + k, "10.0.0.25", 1000 + k, next(counter))))
    scenario("S20", "Internal host 10.0.0.61 scans 20 ports of 10.0.0.25 ...", "suricata", 20, "SOC-002", 3,
             {"src_ip": "10.0.0.61", "dst_ip": "10.0.0.25"}, "Port-scan alert", incident_group="G-10.0.0.61")
    for k in range(6):
        t = 5250 + 4 * k
        linux.append((t, s.linux_failed(s.at(t), "db02", "postgres", "10.0.0.61", 53000 + k, 9800 + k)))
    scenario("S21", "... then the same host brute-forces SSH on db02", "linux_auth", 6, "SOC-001", 3,
             {"src_ip": "10.0.0.61", "hostname": "db02"}, "Brute-force alert in the SAME incident as S20",
             incident_group="G-10.0.0.61")

    # ------------------------------------------------------- beaconing and sudo
    beacon = r"C:\Users\carl\AppData\Roaming\Updater\updater.exe"
    sysm.append((6900, s.sysmon_process(s.at(6900), "WS07", beacon, "updater.exe --silent",
                                        r"C:\Windows\explorer.exe", user="CORP\\carl", pid=7040)))
    for k in range(10):                    # beacon to the same server every 60 s
        t = 6960 + 60 * k
        sysm.append((t, s.sysmon_network(s.at(t), "WS07", beacon, "10.0.1.70", 50100 + k, "198.51.100.66", 443,
                                         initiated=True, pid=7040)))
        suri.append((t + 0.2, s.suricata_flow(s.at(t + 0.2), "10.0.1.70", 50100 + k, "198.51.100.66", 443,
                                               next(counter))))
    scenario("S22", "Malware beaconing: unknown executable in AppData\\Roaming calls 198.51.100.66:443 every 60 s",
             "sysmon+suricata", 1, "SOC-003", 2, {"hostname": "WS07"},
             "LOW alert for the process in AppData (the 60 s periodicity itself is not a rule; it is visible "
             "in the Events page by searching 198.51.100.66)")
    linux.append((3700, "Nov 13 03:01:40 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
                        "COMMAND=/usr/bin/systemctl restart nginx"))
    linux.append((3710, "Nov 13 03:01:50 web01 sudo:    alice : 3 incorrect password attempts ; TTY=pts/0 ; "
                        "PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow"))
    scenario("S23", "sudo usage and a failed sudo password on web01", "linux_auth", 2, None, None,
             {"hostname": "web01", "username": "alice"},
             "Parsed as sudo_command / sudo_auth_failure; no alert (no sudo rule)")

    # ------------------------------------------------------------ web access log
    pages = ["/", "/products", "/about", "/contact", "/static/app.css", "/static/app.js", "/img/logo.png"]
    for i in range(160):                   # normal visitors
        t = rng.uniform(0, 7200)
        client = f"192.0.2.{rng.randint(100, 140)}"
        roll = rng.random()
        if roll < 0.15:
            line = s.web_access(s.at(t), client, f"/products?id={rng.randint(1, 300)}&sort=price")
        elif roll < 0.22:
            line = s.web_access(s.at(t), client, "/login", 302, method="POST")
        elif roll < 0.25:
            line = s.web_access(s.at(t), client, f"/img/old_banner{rng.randint(1, 9)}.png", 404)
        else:
            line = s.web_access(s.at(t), client, rng.choice(pages))
        web.append((t + i * 1e-6, line))
    sqlmap = "sqlmap/1.8#stable (https://sqlmap.org)"
    payloads = [("/item.php?id=1", 200), ("/item.php?id=1%27", 500),
                ("/item.php?id=1%27%20OR%20%271%27=%271", 200),
                ("/item.php?id=1%20UNION%20ALL%20SELECT%20username,password%20FROM%20users--", 500),
                ("/item.php?id=1%20AND%20SLEEP(5)", 500), ("/item.php?id=1;DROP%20TABLE%20users", 500)]
    for k, (path, status) in enumerate(payloads):
        web.append((3000 + 4 * k, s.web_access(s.at(3000 + 4 * k), "198.51.100.90", path, status, agent=sqlmap)))
    scenario("S24", "SQL injection with sqlmap against web01; one payload answered 200", "web_access", 6,
             "SOC-005", 4, {"src_ip": "198.51.100.90", "hostname": WEB_SERVER_NAME},
             "HIGH alert: attack payload answered 2xx")
    words = ["admin", "backup", "old", "test", "dev", "api", "uploads", "private", "db", "tmp"]
    for k in range(40):
        path = f"/{words[k % 10]}{k // 10 or ''}/"
        status = 200 if path in ("/api/", "/uploads/") else 404
        web.append((4000 + k, s.web_access(s.at(4000 + k), "198.51.100.91", path, status, agent="gobuster/3.6")))
    scenario("S25", "Directory brute force: 40 requests in 40 s, 38 answered 404", "web_access", 40, "SOC-005", 3,
             {"src_ip": "198.51.100.91", "hostname": WEB_SERVER_NAME}, "MEDIUM alert: burst of 4xx errors")
    web.append((4500, s.web_access(s.at(4500), "198.51.100.92", "/.env", 404, agent="Mozilla/5.0 (compatible; bot)")))
    web.append((4510, s.web_access(s.at(4510), "198.51.100.92", "/wp-login.php", 404)))
    for k in range(5):
        web.append((4600 + k, s.web_access(s.at(4600 + k), "192.0.2.150", f"/img/missing{k}.jpg", 404)))
    scenario("S26", "One /.env probe from an Internet bot and a visitor with 5 broken images", "web_access", 7,
             None, None, {"src_ip": "198.51.100.92"}, "No alert (single probes and a few 404s are normal noise)")
    web.append((900, s.web_access(s.at(900), "203.0.113.10", "/download.php?file=../../../../etc/passwd", 404)))
    web.append((905, s.web_access(s.at(905), "203.0.113.10", "/download.php?file=..%2f..%2f..%2fwin.ini", 404)))
    scenario("S27", "The SSH attacker of S01 also tries path traversal on the website", "web_access", 2, "SOC-005", 3,
             {"src_ip": "203.0.113.10", "hostname": WEB_SERVER_NAME},
             "MEDIUM alert; joins the incident of S01 (same source IP within 30 minutes)", incident_group="S01")

    # --------------------------------------------------------------- malformed
    bad = {
        "linux_auth.log": ["this is not a syslog line", "Nov 99 25:61:61 web01 sshd[1]: Failed password for root "
                           "from 203.0.113.200 port 22 ssh2",
                           "Nov 13 02:10:00 web01 sshd[77]: Failed password for root from 999.1.1.1 port 22 ssh2"],
        "suricata_eve.jsonl": ['{"timestamp": "2026-11-13T02:00:00.000000+0000", "event_type": "alert", "src_ip": ',
                               "not json at all",
                               json.dumps({"timestamp": s.eve_ts(s.at(10)), "event_type": "stats", "stats": {}}),
                               json.dumps({"timestamp": s.eve_ts(s.at(11)), "event_type": "flow",
                                           "src_ip": "300.1.1.1", "dest_ip": "10.0.0.2", "dest_port": 99999})],
        "sysmon.jsonl": ['{"EventID": 1, "UtcTime": ', json.dumps({"EventID": 5, "UtcTime": s.sysmon_ts(s.at(12)),
                                                                  "Computer": "WS05", "Image": "x.exe"}),
                         json.dumps({"EventID": 1, "Computer": "WS05", "Image": r"C:\a.exe"})],
        "web_access.log": ["GET / HTTP/1.1 200",
                           '192.0.2.5 - - [13/Nov/2026:02:00:00 +0000] "GET / HTTP/1.1" 999 10 "-" "-"'],
    }
    scenario("S17", "Malformed / unsupported / invalid lines in all four sources", "all",
             sum(len(v) for v in bad.values()), None, None, {},
             "Every line is rejected with a reason; the pipeline keeps running")

    files = {"linux_auth.log": [line for _, line in sorted(linux)],
             "suricata_eve.jsonl": [line for _, line in sorted(suri)],
             "sysmon.jsonl": [line for _, line in sorted(sysm)],
             "web_access.log": [line for _, line in sorted(web)]}
    for name, lines in files.items():
        if len(set(lines)) != len(lines):
            raise RuntimeError(f"generator produced duplicate lines in {name}")
        step = max(1, len(lines) // (len(bad[name]) + 1))
        for i, line in enumerate(bad[name]):
            lines.insert((i + 1) * step + i, line)

    expected_alerts = [sc for sc in scenarios if sc["expected_alert"]]
    raw_detections = sum(sc["expected_occurrences"] for sc in expected_alerts)
    incidents = len({sc["incident_group"] for sc in expected_alerts})
    ids_alerts = sum(1 for _, line in suri if '"event_type": "alert"' in line)
    truth = {
        "note": "SYNTHETIC dataset generated by datasets/generate_dataset.py; not real attack data.",
        "seed": SEED, "syslog_year": DATASET_YEAR, "web_server_name": WEB_SERVER_NAME,
        "files": {name: {"lines": len(lines), "rejected": len(bad[name]),
                         "valid_events": len(lines) - len(bad[name])} for name, lines in files.items()},
        "expected_totals": {
            "raw_events": sum(len(v) for v in files.values()),
            "events": sum(len(v) - len(bad[n]) for n, v in files.items()),
            "rejected": sum(len(v) for v in bad.values()),
            "alerts": len(expected_alerts), "incidents": incidents,
            "raw_detections": raw_detections, "ids_alerts": ids_alerts,
            "raw_alerts": raw_detections + ids_alerts,
            "alerts_per_rule": {rule: sum(1 for sc in expected_alerts if sc["expected_rule_id"] == rule)
                                for rule in ("SOC-001", "SOC-002", "SOC-003", "SOC-004", "SOC-005")}},
        "scenarios": scenarios,
    }
    return files, truth


def write_dataset(base_dir: Path) -> dict[str, Any]:
    """Write the dataset under ``base_dir`` and return a short summary."""
    files, truth = build()
    raw_dir = base_dir / "raw"
    truth_dir = base_dir / "ground_truth"
    raw_dir.mkdir(parents=True, exist_ok=True)
    truth_dir.mkdir(parents=True, exist_ok=True)
    for name, lines in files.items():
        (raw_dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    (truth_dir / "scenarios.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    return {"raw_dir": str(raw_dir), "ground_truth": str(truth_dir / "scenarios.json"),
            "expected_totals": truth["expected_totals"]}


if __name__ == "__main__":
    print(json.dumps(write_dataset(Path(__file__).resolve().parent), indent=2))
