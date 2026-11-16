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
SEED = 42
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def build() -> tuple[dict[str, list[str]], dict[str, Any]]:
    """Return ({file name: lines}, ground truth)."""
    rng = random.Random(SEED)
    linux: list[tuple[float, str]] = []
    suri: list[tuple[float, str]] = []
    sysm: list[tuple[float, str]] = []
    scenarios: list[dict[str, Any]] = []
    counter = iter(range(1, 10_000_000))

    def scenario(sid: str, description: str, source: str, n_events: int, rule_id: str | None,
                 severity: int | None, entity: dict[str, Any], behavior: str) -> None:
        scenarios.append({
            "scenario_id": sid, "description": description, "input": {"source": source, "events": n_events},
            "expected_behavior": behavior, "expected_alert": rule_id is not None, "expected_rule_id": rule_id,
            "expected_severity": severity, "expected_incident": rule_id is not None, "entity": entity})

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
    suri.append((6000, s.suricata_alert(s.at(6000), "203.0.113.99", 51515, "10.0.0.30", 445,
                                        "SYNTHETIC EXPLOIT SMB remote code execution attempt", 1, next(counter))))
    sysm.append((6002, s.sysmon_network(s.at(6002), "WS02", "System", "203.0.113.99", 51515, "10.0.0.30", 445,
                                        initiated=False, pid=4)))
    sysm.append((6060, s.sysmon_network(s.at(6060), "WS02", r"C:\Windows\System32\rundll32.exe", "10.0.0.30",
                                        49777, "203.0.113.99", 4444, initiated=True, pid=7010)))
    scenario("S14", "Suricata alert confirmed by Sysmon connections with the same peers", "suricata+sysmon", 3,
             "SOC-004", 4, {"src_ip": "203.0.113.99", "dst_ip": "10.0.0.30", "hostname": "WS02"},
             "Alert: network-to-host pivot")
    suri.append((6300, s.suricata_alert(s.at(6300), "203.0.113.120", 51616, "10.0.0.31", 80,
                                        "SYNTHETIC WEB suspicious user-agent", 2, next(counter))))
    scenario("S15", "Suricata alert without any Sysmon connection", "suricata", 1, None, None,
             {"src_ip": "203.0.113.120", "dst_ip": "10.0.0.31"}, "No pivot alert")
    suri.append((6600, s.suricata_alert(s.at(6600), "203.0.113.130", 51717, "10.0.0.32", 443,
                                        "SYNTHETIC TLS suspicious certificate", 2, next(counter))))
    sysm.append((7800, s.sysmon_network(s.at(7800), "WS22", r"C:\Program Files\Browser\browser.exe",
                                        "10.0.0.32", 49888, "203.0.113.130", 443, initiated=True, pid=7020)))
    scenario("S16", "Same peers but Sysmon connection 20 minutes later (outside window)", "suricata+sysmon", 2,
             None, None, {"src_ip": "203.0.113.130", "dst_ip": "10.0.0.32"}, "No pivot alert")

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
    }
    scenario("S17", "Malformed / unsupported / invalid lines in all three sources", "all",
             sum(len(v) for v in bad.values()), None, None, {},
             "Every line is rejected with a reason; the pipeline keeps running")

    files = {"linux_auth.log": [line for _, line in sorted(linux)],
             "suricata_eve.jsonl": [line for _, line in sorted(suri)],
             "sysmon.jsonl": [line for _, line in sorted(sysm)]}
    for name, lines in files.items():
        if len(set(lines)) != len(lines):
            raise RuntimeError(f"generator produced duplicate lines in {name}")
        step = max(1, len(lines) // (len(bad[name]) + 1))
        for i, line in enumerate(bad[name]):
            lines.insert((i + 1) * step + i, line)

    expected_alerts = [sc for sc in scenarios if sc["expected_alert"]]
    truth = {
        "note": "SYNTHETIC dataset generated by datasets/generate_dataset.py; not real attack data.",
        "seed": SEED, "syslog_year": DATASET_YEAR,
        "files": {name: {"lines": len(lines), "rejected": len(bad[name]),
                         "valid_events": len(lines) - len(bad[name])} for name, lines in files.items()},
        "expected_totals": {
            "raw_events": sum(len(v) for v in files.values()),
            "events": sum(len(v) - len(bad[n]) for n, v in files.items()),
            "rejected": sum(len(v) for v in bad.values()),
            "alerts": len(expected_alerts), "incidents": len(expected_alerts),
            "alerts_per_rule": {rule: sum(1 for sc in expected_alerts if sc["expected_rule_id"] == rule)
                                for rule in ("SOC-001", "SOC-002", "SOC-003", "SOC-004")}},
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
