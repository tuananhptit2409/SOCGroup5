"""Soak test: run the whole pipeline repeatedly for a fixed time on a temporary database.

Usage:
    python -m benchmarks.soak_test --minutes 10 --label soak_quick
    python -m benchmarks.soak_test --minutes 30 --label soak_extended

Each cycle:
  1. generates a new batch of synthetic events in its own time period (one
     injected attack per rule, so 4 new alerts and 4 new incidents are expected),
  2. ingests it, then RE-ingests the previous batch (must add nothing),
  3. runs detection (the full pipeline: rules, deduplication, incidents),
  4. runs the dashboard queries, opens an incident, updates a status, adds a note,
  5. records memory, timings and any exception.
A reader thread queries dashboard data continuously the whole time, and every
10 cycles a separate process (`main.py stats`) reads the database.
At the end: ground-truth checks (events, alerts, incidents), duplicate checks
and PRAGMA integrity_check / foreign_key_check. Never touches data/soc.db.
"""
from __future__ import annotations

import argparse
import gc
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.run_benchmark import RESULTS_DIR, environment, generate  # noqa: E402
from config import Settings  # noqa: E402
from engine.incident_manager import IncidentError, IncidentManager  # noqa: E402
from pipeline import ingest_file, run_detection  # noqa: E402
from storage.database import Database  # noqa: E402
from storage.repository import INCIDENT_STATUSES, Repository  # noqa: E402
from ui import data_access  # noqa: E402

import psutil  # noqa: E402

SOURCES = (("linux_auth", "linux_auth.log"), ("suricata", "suricata_eve.jsonl"), ("sysmon", "sysmon.jsonl"))
DAY = 86400.0


def run(minutes: float, batch_events: int, label: str) -> dict:
    work = Path(tempfile.mkdtemp(prefix=f"soc_{label}_"))
    settings = replace(Settings(), db_path=work / "soak.db", allowed_input_dirs=(work,), syslog_default_year=2026)
    db = Database(settings.db_path)
    db.init_schema()
    process = psutil.Process()
    rng = random.Random(7)
    errors: list[str] = []
    reader = {"reads": 0, "errors": [], "stop": threading.Event()}

    def read_loop() -> None:
        while not reader["stop"].is_set():
            try:
                data_access.overview(db)
                data_access.search_events(db, page=rng.randint(1, 20), page_size=50)
                data_access.list_alerts(db, limit=100)
                data_access.list_incidents(db, limit=100)
                reader["reads"] += 1
            except Exception as exc:  # noqa: BLE001 - every failure is recorded and reported
                reader["errors"].append(f"{type(exc).__name__}: {exc}")
            time.sleep(0.05)

    thread = threading.Thread(target=read_loop, daemon=True)
    thread.start()
    samples: list[dict] = []
    expected = {"events": 0, "alerts": 0, "incidents": 0}
    duplicates_seen = 0
    subprocess_checks: list[dict] = []
    started = time.time()
    deadline = started + minutes * 60
    cycle = 0
    previous: Path | None = None
    try:
        while time.time() < deadline:
            t0 = time.perf_counter()
            folder = work / f"batch_{cycle}"
            folder.mkdir()
            truth = generate(batch_events, folder, seed=1000 + cycle, time_offset=cycle * DAY)
            try:
                new_events = sum(ingest_file(db, settings, source, folder / name).new_events
                                 for source, name in SOURCES)
                expected["events"] += new_events
                if previous is not None:
                    again = [ingest_file(db, settings, source, previous / name) for source, name in SOURCES]
                    duplicates_seen += sum(r.duplicates for r in again)
                    if any(r.new_events for r in again):
                        errors.append(f"cycle {cycle}: re-import of previous batch added events")
                t_ingest = time.perf_counter()
                summary = run_detection(db, settings)
                t_detect = time.perf_counter()
                expected["alerts"] += truth["expected_alerts"]
                expected["incidents"] += truth["expected_incidents"]
                if summary.rule_errors:
                    errors.append(f"cycle {cycle}: rule errors {summary.rule_errors}")
                if summary.alerts_new != truth["expected_alerts"] or summary.incidents_created != truth["expected_incidents"]:
                    errors.append(f"cycle {cycle}: new alerts {summary.alerts_new}, new incidents "
                                  f"{summary.incidents_created}, expected {truth['expected_alerts']}")
                # analyst activity
                incidents = data_access.list_incidents(db, limit=200)
                if not incidents.empty:
                    target = int(incidents.sample(1, random_state=cycle)["incident_id"].iloc[0])
                    data_access.incident_detail(db, settings, target)
                    data_access.incident_report(db, target)
                    current = incidents.set_index("incident_id").loc[target, "status"]
                    choices = [st for st in INCIDENT_STATUSES if st != current]
                    data_access.update_incident_status(db, settings, target, rng.choice(choices), "soak", f"cycle {cycle}")
                    data_access.add_incident_note(db, settings, target, f"note {cycle}", "soak")
                data_access.search_events(db, ip="198.18.0.1")
                t_queries = time.perf_counter()
            except Exception as exc:  # noqa: BLE001
                errors.append(f"cycle {cycle}: {type(exc).__name__}: {exc}\n{traceback.format_exc(limit=3)}")
                t_ingest = t_detect = t_queries = time.perf_counter()
            if previous is not None:
                shutil.rmtree(previous, ignore_errors=True)
            previous = folder
            if cycle % 10 == 0:
                env = {**os.environ, "SOC_DB_PATH": str(settings.db_path), "PYTHONIOENCODING": "utf-8"}
                env.pop("SOC_CONFIG_FILE", None)
                proc = subprocess.run([sys.executable, str(ROOT / "main.py"), "stats"], env=env, capture_output=True,
                                      text=True, encoding="utf-8", timeout=300)
                ok = proc.returncode == 0
                counts = json.loads(proc.stdout)["counts"] if ok else None
                subprocess_checks.append({"cycle": cycle, "ok": ok, "events": counts and counts["events"],
                                          "integrity": ok and json.loads(proc.stdout)["database"]["integrity_check"]})
                if not ok:
                    errors.append(f"cycle {cycle}: stats subprocess failed: {proc.stderr[-300:]}")
            gc.collect()
            samples.append({"cycle": cycle, "elapsed_s": round(time.time() - started, 1),
                            "rss_mb": round(process.memory_info().rss / 2 ** 20, 1),
                            "events_total": expected["events"],
                            "ingest_s": round(t_ingest - t0, 3), "detect_s": round(t_detect - t_ingest, 3),
                            "queries_s": round(t_queries - t_detect, 3)})
            cycle += 1
    finally:
        reader["stop"].set()
        thread.join(timeout=30)

    with db.connection() as conn:
        repo = Repository(conn)
        counts = repo.counts()
        checks = {
            "duplicate_fingerprints": conn.execute(
                "SELECT COUNT(*) FROM (SELECT fingerprint FROM alerts GROUP BY fingerprint HAVING COUNT(*) > 1)").fetchone()[0],
            "overlapping_alerts_same_rule_entity": conn.execute(
                "SELECT COUNT(*) FROM alerts a JOIN alerts b ON a.rule_id = b.rule_id AND a.entity_key = b.entity_key "
                "AND a.alert_id < b.alert_id AND a.first_ts <= b.last_ts AND b.first_ts <= a.last_ts").fetchone()[0],
            "alerts_without_incident": conn.execute(
                "SELECT COUNT(*) FROM alerts a LEFT JOIN incident_alerts ia ON ia.alert_id = a.alert_id "
                "WHERE ia.alert_id IS NULL").fetchone()[0],
            "alert_event_count_mismatch": conn.execute(
                "SELECT COUNT(*) FROM alerts a WHERE a.event_count <> (SELECT COUNT(*) FROM alert_events ae "
                "WHERE ae.alert_id = a.alert_id)").fetchone()[0],
            "history_rows": conn.execute("SELECT COUNT(*) FROM incident_history").fetchone()[0],
            "notes": conn.execute("SELECT COUNT(*) FROM incident_notes").fetchone()[0],
            "running_batches": conn.execute("SELECT COUNT(*) FROM import_batches WHERE status <> 'completed'").fetchone()[0],
        }
    integrity = db.integrity_report()
    db_size = settings.db_path.stat().st_size / 2 ** 20
    shutil.rmtree(work, ignore_errors=True)

    mismatches = {k: (counts[k], v) for k, v in expected.items() if counts[k] != v}
    rss = [x["rss_mb"] for x in samples]
    third = max(1, len(rss) // 3)
    return {
        "label": label, "minutes_planned": minutes, "duration_s": round(time.time() - started, 1),
        "cycles": cycle, "batch_events": batch_events, "counts": counts, "expected": expected,
        "count_mismatches": mismatches, "duplicate_lines_reimported": duplicates_seen, "checks": checks,
        "integrity": integrity, "db_size_mb": round(db_size, 1),
        "reader_thread": {"reads": reader["reads"], "errors": len(reader["errors"]),
                          "first_errors": reader["errors"][:5]},
        "subprocess_checks": subprocess_checks,
        "errors": errors[:20], "error_count": len(errors),
        "rss_mb": {"first": rss[0] if rss else None, "max": max(rss) if rss else None,
                   "last": rss[-1] if rss else None,
                   "mean_first_third": round(sum(rss[:third]) / third, 1) if rss else None,
                   "mean_last_third": round(sum(rss[-third:]) / third, 1) if rss else None},
        "detect_seconds": {"first": samples[0]["detect_s"] if samples else None,
                           "last": samples[-1]["detect_s"] if samples else None},
        "samples": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--minutes", type=float, default=10)
    parser.add_argument("--batch-events", type=int, default=4000)
    parser.add_argument("--label", default="soak")
    args = parser.parse_args()
    result = run(args.minutes, args.batch_events, args.label)
    result["environment"] = environment()
    result["finished_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f"{args.label}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    summary = {k: v for k, v in result.items() if k not in ("samples", "environment", "subprocess_checks")}
    print(json.dumps(summary, indent=2))
    ok = (not result["error_count"] and not result["count_mismatches"] and not result["reader_thread"]["errors"]
          and result["integrity"]["integrity_check"] == ["ok"] and not result["integrity"]["foreign_key_violations"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
