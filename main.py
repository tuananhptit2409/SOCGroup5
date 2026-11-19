"""Command-line entry point of the SOC Analyst Toolkit.

Examples:
    python main.py init-db
    python main.py generate-dataset
    python main.py run-sample
    python main.py ingest --source linux_auth --file datasets/raw/linux_auth.log
    python main.py detect
    python main.py stats
    python main.py incidents
    python main.py update-status --id 1 --status IN_PROGRESS --note "investigating"
    python main.py report --id 1
    python main.py dashboard
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from dataclasses import asdict, replace
from pathlib import Path

from config import PROJECT_ROOT, ConfigError, Settings, load_settings
from engine.incident_manager import IncidentError, IncidentManager
from ingest.base import InputPathError
from logging_setup import configure_logging
from pipeline import SOURCES, PipelineError, ingest_file, run_detection
from reporting import build_incident_report
from storage.database import Database, DatabaseError
from storage.repository import INCIDENT_STATUSES, Repository

SAMPLE_FILES = {"linux_auth": "linux_auth.log", "suricata": "suricata_eve.jsonl", "sysmon": "sysmon.jsonl"}


def _print(data: object) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def cmd_init_db(settings: Settings, _args: argparse.Namespace) -> int:
    Database(settings.db_path).init_schema()
    print(f"Database initialized: {settings.db_path}")
    return 0


def cmd_generate_dataset(_settings: Settings, _args: argparse.Namespace) -> int:
    from datasets.generate_dataset import write_dataset
    _print(write_dataset(PROJECT_ROOT / "datasets"))
    return 0


def cmd_ingest(settings: Settings, args: argparse.Namespace) -> int:
    db = Database(settings.db_path)
    db.check_schema()
    _print(asdict(ingest_file(db, settings, args.source, args.file)))
    return 0


def cmd_detect(settings: Settings, _args: argparse.Namespace) -> int:
    db = Database(settings.db_path)
    db.check_schema()
    _print(asdict(run_detection(db, settings)))
    return 0


def cmd_run_sample(settings: Settings, _args: argparse.Namespace) -> int:
    """Initialize the database, import the bundled sample dataset and run detection."""
    from datasets.generate_dataset import DATASET_YEAR, write_dataset
    raw_dir = PROJECT_ROOT / "datasets" / "raw"
    if not all((raw_dir / name).is_file() for name in SAMPLE_FILES.values()):
        write_dataset(PROJECT_ROOT / "datasets")
    settings = replace(settings, syslog_default_year=DATASET_YEAR,
                       allowed_input_dirs=(*settings.allowed_input_dirs, PROJECT_ROOT / "datasets"))
    db = Database(settings.db_path)
    db.init_schema()
    output = {"ingest": [asdict(ingest_file(db, settings, source, raw_dir / name))
                         for source, name in SAMPLE_FILES.items()]}
    output["detection"] = asdict(run_detection(db, settings))
    with db.connection() as conn:
        output["counts"] = Repository(conn).counts()
    _print(output)
    return 0


def cmd_stats(settings: Settings, _args: argparse.Namespace) -> int:
    db = Database(settings.db_path)
    db.check_schema()
    with db.connection() as conn:
        counts = Repository(conn).counts()
    _print({"counts": counts, "database": db.integrity_report()})
    return 0


def cmd_incidents(settings: Settings, args: argparse.Namespace) -> int:
    db = Database(settings.db_path)
    db.check_schema()
    with db.connection() as conn:
        rows = Repository(conn).list_incidents(status=args.status, limit=args.limit)
    for row in rows:
        print(f"#{row['incident_id']:<4} sev={row['severity']} {row['status']:<14} "
              f"{row['first_seen']}  alerts={row['alert_count']} events={row['event_count']}  {row['title']}")
    if not rows:
        print("No incidents.")
    return 0


def cmd_update_status(settings: Settings, args: argparse.Namespace) -> int:
    db = Database(settings.db_path)
    db.check_schema()
    with db.transaction() as conn:
        IncidentManager(conn, settings.correlation).update_status(args.id, args.status, args.actor, args.note)
    print(f"Incident {args.id} -> {args.status}")
    return 0


def cmd_report(settings: Settings, args: argparse.Namespace) -> int:
    db = Database(settings.db_path)
    db.check_schema()
    with db.connection() as conn:
        report = build_incident_report(conn, args.id)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    target = settings.reports_dir / f"incident_{args.id}.md"
    target.write_text(report, encoding="utf-8")
    print(f"Report written: {target}")
    return 0


def cmd_dashboard(_settings: Settings, _args: argparse.Namespace) -> int:
    missing = [name for name in ("streamlit", "plotly", "pandas") if importlib.util.find_spec(name) is None]
    if missing:
        print(f"ERROR: the dashboard needs {', '.join(missing)}, which {'is' if len(missing) == 1 else 'are'} "
              f"not installed for {sys.executable}.\n"
              f"Install the requirements first:  {sys.executable} -m pip install -r requirements.txt",
              file=sys.stderr)
        return 2
    # The dashboard has no authentication: listen on this computer only.
    command = [sys.executable, "-m", "streamlit", "run", str(PROJECT_ROOT / "ui" / "dashboard.py"),
               "--server.address", "127.0.0.1", "--browser.gatherUsageStats", "false"]
    print("Starting:", " ".join(command))
    return subprocess.call(command, cwd=str(PROJECT_ROOT))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py", description="Multi-Source SOC Analyst Toolkit")
    parser.add_argument("--config", help="path to a JSON settings file")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="create the SQLite database and tables").set_defaults(func=cmd_init_db)
    sub.add_parser("generate-dataset", help="write the synthetic sample dataset").set_defaults(
        func=cmd_generate_dataset)
    sub.add_parser("run-sample", help="init + import sample dataset + detect").set_defaults(func=cmd_run_sample)
    ingest = sub.add_parser("ingest", help="import one log file")
    ingest.add_argument("--source", required=True, choices=sorted(SOURCES))
    ingest.add_argument("--file", required=True)
    ingest.set_defaults(func=cmd_ingest)
    sub.add_parser("detect", help="run detection, deduplication and incident sync").set_defaults(func=cmd_detect)
    sub.add_parser("stats", help="show row counts and database integrity").set_defaults(func=cmd_stats)
    incidents = sub.add_parser("incidents", help="list incidents")
    incidents.add_argument("--status", choices=INCIDENT_STATUSES)
    incidents.add_argument("--limit", type=int, default=50)
    incidents.set_defaults(func=cmd_incidents)
    update = sub.add_parser("update-status", help="change an incident status")
    update.add_argument("--id", type=int, required=True)
    update.add_argument("--status", required=True, choices=INCIDENT_STATUSES)
    update.add_argument("--actor", default="analyst")
    update.add_argument("--note")
    update.set_defaults(func=cmd_update_status)
    report = sub.add_parser("report", help="export an incident report (Markdown)")
    report.add_argument("--id", type=int, required=True)
    report.set_defaults(func=cmd_report)
    sub.add_parser("dashboard", help="start the Streamlit dashboard").set_defaults(func=cmd_dashboard)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):   # Windows consoles may not default to UTF-8
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    try:
        settings = load_settings(args.config)
        configure_logging(settings.log_level)
        return int(args.func(settings, args))
    except (ConfigError, DatabaseError, InputPathError, PipelineError, IncidentError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
