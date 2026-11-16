"""Builders of synthetic log lines (used by the sample dataset, tests and benchmarks).

All IP addresses are private (RFC1918) or documentation ranges (RFC5737);
nothing here is captured from a real attack.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
BASE_TIME = datetime(2026, 11, 13, 2, 0, 0, tzinfo=timezone.utc)


def at(offset_seconds: float, base: datetime = BASE_TIME) -> datetime:
    return base + timedelta(seconds=offset_seconds)


def syslog_ts(dt: datetime) -> str:
    return f"{_MONTHS[dt.month - 1]} {dt.day:2d} {dt:%H:%M:%S}"


def linux_failed(dt: datetime, host: str, user: str, ip: str, port: int, pid: int = 1000,
                 invalid: bool = False) -> str:
    prefix = "invalid user " if invalid else ""
    return f"{syslog_ts(dt)} {host} sshd[{pid}]: Failed password for {prefix}{user} from {ip} port {port} ssh2"


def linux_accepted(dt: datetime, host: str, user: str, ip: str, port: int, pid: int = 1000,
                   method: str = "password") -> str:
    return f"{syslog_ts(dt)} {host} sshd[{pid}]: Accepted {method} for {user} from {ip} port {port} ssh2"


def linux_lockout(dt: datetime, host: str, user: str, pid: int = 1000) -> str:
    return (f"{syslog_ts(dt)} {host} sshd[{pid}]: pam_faillock(sshd:auth): Consecutive login failures "
            f"for user {user} account temporarily locked")


def linux_other(dt: datetime, host: str, pid: int = 1000) -> str:
    return f"{syslog_ts(dt)} {host} CRON[{pid}]: pam_unix(cron:session): session opened for user root by (uid=0)"


def eve_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def suricata_flow(dt: datetime, src: str, sport: int, dst: str, dport: int, flow_id: int = 1,
                  proto: str = "TCP") -> str:
    return json.dumps({"timestamp": eve_ts(dt), "flow_id": flow_id, "event_type": "flow", "src_ip": src,
                       "src_port": sport, "dest_ip": dst, "dest_port": dport, "proto": proto,
                       "flow": {"pkts_toserver": 2, "pkts_toclient": 1, "state": "closed"}})


def suricata_alert(dt: datetime, src: str, sport: int, dst: str, dport: int, signature: str,
                   severity: int = 1, flow_id: int = 1, category: str = "Attempted Administrator Privilege Gain") -> str:
    return json.dumps({"timestamp": eve_ts(dt), "flow_id": flow_id, "event_type": "alert", "src_ip": src,
                       "src_port": sport, "dest_ip": dst, "dest_port": dport, "proto": "TCP",
                       "alert": {"action": "allowed", "gid": 1, "signature_id": 2000000 + flow_id % 1000,
                                 "signature": signature, "category": category, "severity": severity}})


def suricata_dns(dt: datetime, src: str, dst: str, name: str, flow_id: int = 1) -> str:
    return json.dumps({"timestamp": eve_ts(dt), "flow_id": flow_id, "event_type": "dns", "src_ip": src,
                       "src_port": 40000 + flow_id % 20000, "dest_ip": dst, "dest_port": 53, "proto": "UDP",
                       "dns": {"type": "query", "rrname": name, "rrtype": "A"}})


def suricata_http(dt: datetime, src: str, dst: str, host: str, url: str, flow_id: int = 1) -> str:
    return json.dumps({"timestamp": eve_ts(dt), "flow_id": flow_id, "event_type": "http", "src_ip": src,
                       "src_port": 40000 + flow_id % 20000, "dest_ip": dst, "dest_port": 80, "proto": "TCP",
                       "http": {"hostname": host, "url": url, "http_method": "GET", "status": 200}})


def sysmon_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def sysmon_process(dt: datetime, computer: str, image: str, command_line: str | None,
                   parent: str | None, user: str = "CORP\\user", pid: int = 4000) -> str:
    record = {"EventID": 1, "UtcTime": sysmon_ts(dt), "Computer": computer, "User": user,
              "ProcessId": pid, "Image": image}
    if command_line is not None:
        record["CommandLine"] = command_line
    if parent is not None:
        record["ParentImage"] = parent
    return json.dumps(record)


def sysmon_network(dt: datetime, computer: str, image: str, src: str, sport: int, dst: str, dport: int,
                   initiated: bool | None = True, pid: int = 4000) -> str:
    record = {"EventID": 3, "UtcTime": sysmon_ts(dt), "Computer": computer, "User": "CORP\\user",
              "ProcessId": pid, "Image": image, "Protocol": "tcp", "SourceIp": src, "SourcePort": sport,
              "DestinationIp": dst, "DestinationPort": dport}
    if initiated is not None:
        record["Initiated"] = initiated
    return json.dumps(record)


def sysmon_file(dt: datetime, computer: str, image: str, target: str, pid: int = 4000) -> str:
    return json.dumps({"EventID": 11, "UtcTime": sysmon_ts(dt), "Computer": computer, "ProcessId": pid,
                       "Image": image, "TargetFilename": target})
