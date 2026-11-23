"""Memory-leak check: repeat the full cycle on a database of FIXED size and track Python heap + RSS.

Usage:  python -m benchmarks.leak_check
If memory is retained per cycle, Python's traced heap keeps rising; growth that
follows the amount of stored data (as in the soak test) stays flat here.
"""
from __future__ import annotations

import gc
import json
import shutil
import sys
import tempfile
import tracemalloc
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import psutil  # noqa: E402

from benchmarks.run_benchmark import RESULTS_DIR, generate  # noqa: E402
from config import Settings  # noqa: E402
from pipeline import ingest_file, run_detection  # noqa: E402
from storage.database import Database  # noqa: E402
from ui import data_access  # noqa: E402

SOURCES = (("linux_auth", "linux_auth.log"), ("suricata", "suricata_eve.jsonl"), ("sysmon", "sysmon.jsonl"))


def main(events: int = 100_000, cycles: int = 30) -> int:
    work = Path(tempfile.mkdtemp(prefix="soc_leak_"))
    settings = replace(Settings(), db_path=work / "leak.db", allowed_input_dirs=(work,), syslog_default_year=2026)
    db = Database(settings.db_path)
    db.init_schema()
    generate(events, work)
    for source, name in SOURCES:
        ingest_file(db, settings, source, work / name)
    run_detection(db, settings)
    process = psutil.Process()
    tracemalloc.start()
    rows = []
    for cycle in range(cycles):
        for source, name in SOURCES:                     # re-import: same data, nothing new stored
            ingest_file(db, settings, source, work / name)
        run_detection(db, settings)
        data_access.overview(db)
        data_access.search_events(db, page_size=200)
        incidents = data_access.list_incidents(db)
        target = int(incidents["incident_id"].iloc[cycle % len(incidents)])
        data_access.incident_detail(db, settings, target)
        data_access.incident_report(db, target)
        gc.collect()
        current, peak = tracemalloc.get_traced_memory()
        rows.append({"cycle": cycle, "python_heap_mb": round(current / 2 ** 20, 2),
                     "python_peak_mb": round(peak / 2 ** 20, 1), "rss_mb": round(process.memory_info().rss / 2 ** 20, 1)})
    tracemalloc.stop()
    shutil.rmtree(work, ignore_errors=True)
    heap = [r["python_heap_mb"] for r in rows]
    half = len(heap) // 2
    result = {"events": events, "cycles": cycles, "rows": rows,
              "heap_first_mb": heap[0], "heap_last_mb": heap[-1],
              "heap_growth_second_half_mb": round(heap[-1] - heap[half], 2),
              "rss_first_mb": rows[0]["rss_mb"], "rss_last_mb": rows[-1]["rss_mb"]}
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "leak_check.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "rows"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
