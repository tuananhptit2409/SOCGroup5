"""Pipeline performance benchmark on synthetic data.

Usage:
    python -m benchmarks.run_benchmark                      # 10,000 / 100,000 / 500,000 events
    python -m benchmarks.run_benchmark --sizes 10000 50000

Each size runs in its own process (clean memory numbers) against a fresh
temporary database. Results are written to benchmarks/results/.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import Settings  # noqa: E402
from datasets import synth as s  # noqa: E402
from pipeline import ingest_file, run_detection  # noqa: E402
from storage.database import Database  # noqa: E402
from storage.repository import Repository  # noqa: E402

try:
    import psutil
except ImportError:  # memory columns are reported as "not measured"
    psutil = None

RESULTS_DIR = Path(__file__).resolve().parent / "results"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


def generate(total: int, out_dir: Path, seed: int = 1, order: str = "chronological",
             time_offset: float = 0.0) -> dict[str, int]:
    """Write three log files with ``total`` lines in all; return the expected detections.

    Benign traffic is built so that no rule can fire on it; ``total // 10000``
    (at least 1) attacks of each of the four kinds are injected with unique entities.
    """
    rng = random.Random(seed)
    span = total * 0.5                       # seconds covered by the data
    if time_offset:                          # used by the soak test to place each batch in its own period
        def at(offset: float, _base=s.at) -> datetime:
            return _base(offset + time_offset)
    else:
        at = s.at

    def times(n: int) -> list[float]:
        """Benign event times: sorted like a real log file, or random (worst case for indexes)."""
        values = [rng.uniform(0, span) for _ in range(n)]
        return sorted(values) if order == "chronological" else values
    attacks = max(1, total // 10000)
    n_linux, n_suri = int(total * 0.40), int(total * 0.35)
    n_sysmon = total - n_linux - n_suri
    per_attack = {"linux": 6, "suri": 20 + 1, "sysmon": 1 + 1}
    hosts = [f"srv{i:02d}" for i in range(20)]
    ports = [80, 443, 53, 22, 3389, 445, 8080, 8443]

    with open(out_dir / "linux_auth.log", "w", encoding="utf-8", newline="\n") as f:
        for i, offset in enumerate(times(n_linux - attacks * per_attack["linux"])):
            t = at(offset)
            ip = f"10.{rng.randint(1, 20)}.{rng.randint(0, 250)}.{rng.randint(1, 250)}"
            kind = rng.random()
            if kind < 0.6:
                f.write(s.linux_accepted(t, rng.choice(hosts), "ops", ip, rng.randint(1024, 65000), i, "publickey") + "\n")
            elif kind < 0.7:
                f.write(s.linux_failed(t, rng.choice(hosts), "ops", ip, rng.randint(1024, 65000), i) + "\n")
            else:
                f.write(s.linux_other(t, rng.choice(hosts), i) + "\n")
        for a in range(attacks):
            base = (a + 0.5) * span / attacks
            ip = f"198.18.{a // 250}.{a % 250 + 1}"
            for k in range(6):
                f.write(s.linux_failed(at(base + k * 8), "bastion", "root", ip, 30000 + k, 900000 + a * 10 + k) + "\n")

    with open(out_dir / "suricata_eve.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for i, offset in enumerate(times(n_suri - attacks * per_attack["suri"])):
            t = at(offset)
            client = f"10.{rng.randint(1, 20)}.{rng.randint(0, 250)}.{rng.randint(1, 250)}"
            server = f"10.0.0.{rng.randint(2, 60)}"
            kind = rng.random()
            if kind < 0.7:
                f.write(s.suricata_flow(t, client, rng.randint(1024, 65000), server, rng.choice(ports), i) + "\n")
            elif kind < 0.85:
                f.write(s.suricata_dns(t, client, "10.0.0.2", f"h{i}.corp.example", i) + "\n")
            else:
                f.write(s.suricata_http(t, client, server, "intranet.corp.example", f"/p/{i}", i) + "\n")
        for a in range(attacks):
            base = (a + 0.5) * span / attacks
            scanner, victim = f"10.200.{a // 250}.{a % 250 + 1}", f"10.201.{a // 250}.{a % 250 + 1}"
            for k in range(20):
                f.write(s.suricata_flow(at(base + k * 0.5), scanner, 40000 + k, victim, 100 + k,
                                        10_000_000 + a * 100 + k) + "\n")
            remote, host_ip = f"198.19.{a // 250}.{a % 250 + 1}", f"10.202.{a // 250}.{a % 250 + 1}"
            f.write(s.suricata_alert(at(base + 100), remote, 50000, host_ip, 445, "SYNTHETIC EXPLOIT attempt",
                                     1, 20_000_000 + a) + "\n")

    with open(out_dir / "sysmon.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for i, offset in enumerate(times(n_sysmon - attacks * per_attack["sysmon"])):
            t = at(offset)
            ws = f"WS{rng.randint(1, 400):03d}"
            kind = rng.random()
            if kind < 0.4:
                f.write(s.sysmon_process(t, ws, r"C:\Program Files\App\app.exe", f"app.exe --job {i}",
                                         r"C:\Windows\explorer.exe", pid=i) + "\n")
            elif kind < 0.8:
                f.write(s.sysmon_network(t, ws, r"C:\Program Files\Browser\browser.exe",
                                         f"10.{rng.randint(1, 20)}.{rng.randint(0, 250)}.{rng.randint(1, 250)}",
                                         rng.randint(1024, 65000), f"10.0.0.{rng.randint(2, 60)}",
                                         rng.choice([80, 443]), pid=i) + "\n")
            else:
                f.write(s.sysmon_file(t, ws, r"C:\Windows\explorer.exe", rf"C:\Users\u\Documents\f{i}.txt", i) + "\n")
        for a in range(attacks):
            base = (a + 0.5) * span / attacks
            f.write(s.sysmon_process(at(base + 50), f"VICTIM{a:04d}", PS, f"powershell.exe -nop -w hidden -enc {B64}",
                                     r"C:\Program Files\Office\WINWORD.EXE", pid=7_000_000 + a) + "\n")
            host_ip = f"10.202.{a // 250}.{a % 250 + 1}"
            # lateral movement: the alerted host connects to another internal host 2 s after the alert
            f.write(s.sysmon_network(at(base + 102), f"PIVOT{a:04d}", r"C:\Windows\System32\rundll32.exe",
                                     host_ip, 49000, f"10.203.{a // 250}.{a % 250 + 1}", 445,
                                     pid=8_000_000 + a) + "\n")
    return {"lines": total, "attacks_per_rule": attacks, "expected_alerts": attacks * 4,
            "expected_incidents": attacks * 4}


class PeakRss(threading.Thread):
    """Samples the resident set size of this process every 20 ms."""

    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.process = psutil.Process() if psutil else None
        self.peak = self.process.memory_info().rss if self.process else 0
        self._running = threading.Event()
        self._running.set()

    def run(self) -> None:
        while self.process and self._running.is_set():
            self.peak = max(self.peak, self.process.memory_info().rss)
            time.sleep(0.02)

    def stop(self) -> int:
        self._running.clear()
        return self.peak


def timed(fn, *args):
    started = time.perf_counter()
    value = fn(*args)
    return value, time.perf_counter() - started


def run_single(total: int, order: str = "chronological", keep_dir: bool = False) -> dict:
    """Generate data, then measure ingest, detection and typical queries for one size."""
    work = Path(tempfile.mkdtemp(prefix=f"soc_bench_{total}_"))
    try:
        expected, generation_seconds = timed(generate, total, work, 1, order)
        settings = replace(Settings(), db_path=work / "bench.db", allowed_input_dirs=(work,),
                           syslog_default_year=2026)
        db = Database(settings.db_path)
        db.init_schema()
        mb = 1024 * 1024
        rss_start = psutil.Process().memory_info().rss if psutil else None
        sampler = PeakRss()
        sampler.start()

        wall_start = time.perf_counter()
        ingests = [ingest_file(db, settings, source, work / name) for source, name in (
            ("linux_auth", "linux_auth.log"), ("suricata", "suricata_eve.jsonl"), ("sysmon", "sysmon.jsonl"))]
        ingest_seconds = time.perf_counter() - wall_start
        rss_after_ingest = psutil.Process().memory_info().rss if psutil else None
        summary, detect_wall = timed(run_detection, db, settings)
        total_seconds = time.perf_counter() - wall_start
        rerun, rerun_wall = timed(run_detection, db, settings)
        peak = sampler.stop()

        with db.connection() as conn:
            repo = Repository(conn)
            counts = repo.counts()
            top_ip = conn.execute("SELECT src_ip FROM events WHERE src_ip IS NOT NULL GROUP BY src_ip "
                                  "ORDER BY COUNT(*) DESC LIMIT 1").fetchone()[0]
            lo, hi = repo.time_bounds()
            queries = {
                "search_by_ip": timed(lambda: repo.search_events(ip=top_ip, limit=50))[1],
                "count_by_ip": timed(lambda: repo.count_events(ip=top_ip))[1],
                "search_time_range_page": timed(lambda: repo.search_events(start_ts=lo, end_ts=lo + (hi - lo) / 100,
                                                                           limit=50))[1],
                "search_severity": timed(lambda: repo.search_events(min_severity=4, limit=50))[1],
                "search_source_page": timed(lambda: repo.search_events(source_type="sysmon", limit=50))[1],
                "text_search_like": timed(lambda: repo.count_events(text="powershell"))[1],
                "list_incidents": timed(lambda: repo.list_incidents(limit=200))[1],
                "overview_counts": timed(repo.counts)[1],
                "overview_top_ips": timed(lambda: repo.group_count("events", "src_ip", 10))[1],
                "overview_timeline": timed(lambda: repo.timeline("events", 3600))[1],
            }
        integrity = db.integrity_report()
        errors = []
        if counts["events"] != total:
            errors.append(f"events stored {counts['events']} != lines generated {total}")
        if counts["alerts"] != expected["expected_alerts"]:
            errors.append(f"alerts {counts['alerts']} != expected {expected['expected_alerts']}")
        if counts["incidents"] != expected["expected_incidents"]:
            errors.append(f"incidents {counts['incidents']} != expected {expected['expected_incidents']}")
        if summary.rule_errors:
            errors.append(f"rule errors: {summary.rule_errors}")
        if rerun.alerts_new or rerun.incidents_created:
            errors.append("second detection run created new alerts/incidents")
        if integrity["integrity_check"] != ["ok"] or integrity["foreign_key_violations"]:
            errors.append(f"integrity: {integrity}")
        return {
            "events": total, "order": order, "batch_size": settings.batch_size, "expected": expected,
            "counts": counts,
            "rejected_lines": sum(r.rejected for r in ingests),
            "generation_seconds": round(generation_seconds, 3),
            "ingest_wall_seconds": round(ingest_seconds, 3),
            "parse_seconds": round(sum(r.seconds_parse for r in ingests), 3),
            "normalize_seconds": round(sum(r.seconds_normalize for r in ingests), 3),
            "database_insert_seconds": round(sum(r.seconds_database for r in ingests), 3),
            "detection_seconds": round(summary.seconds_detection, 3),
            "detection_seconds_per_rule": {k: round(v, 3) for k, v in summary.seconds_per_rule.items()},
            "correlation_seconds": round(summary.seconds_correlation, 3),
            "detection_latency_seconds": round(detect_wall, 3),
            "detection_rerun_seconds": round(rerun_wall, 3),
            "total_processing_seconds": round(total_seconds, 3),
            "ingest_events_per_second": round(total / ingest_seconds, 1),
            "pipeline_events_per_second": round(total / total_seconds, 1),
            "rss_start_mb": round(rss_start / mb, 1) if rss_start else None,
            "rss_after_ingest_mb": round(rss_after_ingest / mb, 1) if rss_after_ingest else None,
            "rss_peak_mb": round(peak / mb, 1) if psutil else None,
            "database_size_mb": round(settings.db_path.stat().st_size / mb, 1),
            "query_seconds": {k: round(v, 4) for k, v in queries.items()},
            "integrity_check": integrity["integrity_check"], "error_count": len(errors), "errors": errors,
        }
    finally:
        if not keep_dir:
            shutil.rmtree(work, ignore_errors=True)


def environment() -> dict:
    info = {"timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "os": platform.platform(), "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version, "cpu_count": os.cpu_count(), "machine": platform.machine(),
            "processor": platform.processor() or "unknown"}
    if psutil:
        info["ram_total_gb"] = round(psutil.virtual_memory().total / 1024 ** 3, 1)
    for name in ("pandas", "streamlit", "plotly", "pytest", "psutil"):
        try:
            info[f"{name}_version"] = __import__(name).__version__
        except Exception:  # noqa: BLE001 - a missing optional package is reported, not fatal
            info[f"{name}_version"] = "not installed"
    return info


def to_markdown(env: dict, results: list[dict]) -> str:
    lines = ["# Benchmark results (generated by benchmarks/run_benchmark.py)", "",
             f"Run at {env['timestamp_utc']} on {env['os']}, Python {env['python']}, SQLite {env['sqlite']}, "
             f"{env['cpu_count']} CPU, {env.get('ram_total_gb', '?')} GB RAM. Event order inside files: "
             f"{env.get('event_order', '?')}.", "",
             "| Events | Ingest (s) | Parse (s) | Normalize (s) | DB insert (s) | Detection (s) | Correlation (s) "
             "| Total (s) | Events/s (pipeline) | Peak RSS (MB) | DB size (MB) | Alerts | Incidents | Errors |",
             "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in results:
        if "failed" in r:
            lines.append(f"| {r['events']:,} | NOT COMPLETED: {r['failed']} |" + " |" * 12)
            continue
        lines.append(
            f"| {r['events']:,} | {r['ingest_wall_seconds']} | {r['parse_seconds']} | {r['normalize_seconds']} | "
            f"{r['database_insert_seconds']} | {r['detection_seconds']} | {r['correlation_seconds']} | "
            f"{r['total_processing_seconds']} | {r['pipeline_events_per_second']:,} | {r['rss_peak_mb']} | "
            f"{r['database_size_mb']} | {r['counts']['alerts']} | {r['counts']['incidents']} | {r['error_count']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sizes", type=int, nargs="+", default=[10_000, 100_000, 500_000])
    parser.add_argument("--single", type=int, help="internal: run one size and print JSON")
    parser.add_argument("--order", choices=["chronological", "random"], default="chronological",
                        help="order of benign events inside each file (injected attacks are always appended "
                             "at the end, i.e. out of order)")
    parser.add_argument("--label", default="benchmark_results", help="output file name (without extension)")
    args = parser.parse_args()
    if args.single:
        print(json.dumps(run_single(args.single, args.order)))
        return 0
    results = []
    for size in args.sizes:
        print(f"running {size:,} events ...", file=sys.stderr)
        proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--single", str(size),
                               "--order", args.order],
                              capture_output=True, text=True, encoding="utf-8")
        if proc.returncode != 0:
            results.append({"events": size, "failed": (proc.stderr or "no output").strip().splitlines()[-1][:200]})
            continue
        results.append(json.loads(proc.stdout.strip().splitlines()[-1]))
    env = environment()
    env["event_order"] = args.order
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f"{args.label}.json").write_text(
        json.dumps({"environment": env, "results": results}, indent=2), encoding="utf-8")
    markdown = to_markdown(env, results)
    (RESULTS_DIR / f"{args.label}.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    return 1 if any(r.get("error_count") or "failed" in r for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
