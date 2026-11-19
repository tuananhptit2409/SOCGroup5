"""Read/write helpers for the dashboard. No Streamlit imports: this module is unit-tested.

Every function opens a short-lived connection and reads live data from SQLite.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

import pandas as pd

from config import Settings
from engine.incident_manager import IncidentManager
from normalizer.models import NormalizationError, normalize_ip
from reporting import SEVERITY_LABELS, build_incident_report
from pipeline import SOURCES, ingest_file, run_detection
from storage.database import Database
from storage.repository import Repository

EVENT_COLUMNS = ["timestamp_utc", "source_type", "action", "severity", "hostname", "username", "src_ip",
                 "src_port", "dst_ip", "dst_port", "protocol", "message", "event_id"]
ALERT_COLUMNS = ["alert_id", "rule_id", "rule_name", "severity", "src_ip", "dst_ip", "hostname",
                 "event_count", "occurrence_count", "first_seen", "last_seen", "created_at", "incident_id"]
INCIDENT_COLUMNS = ["incident_id", "severity", "status", "title", "src_ip", "dst_ip", "affected_asset",
                    "rule_id", "assigned_analyst", "alert_count", "event_count", "first_seen", "last_seen",
                    "created_at", "updated_at"]
UPLOAD_DIR_NAME = "uploads"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
UPLOAD_SOURCES = tuple(SOURCES)


def get_database(settings: Settings) -> Database:
    """Return the configured database after checking it exists and is initialized."""
    db = Database(settings.db_path)
    db.check_schema()
    return db


def clean_ip_filter(value: str | None) -> str | None:
    """Validate an IP typed by the user; raise ValueError with a readable message."""
    if not value or not value.strip():
        return None
    try:
        return normalize_ip(value.strip())
    except NormalizationError as exc:
        raise ValueError(f"'{value.strip()[:45]}' is not a valid IP address") from exc


def to_epoch(value: datetime | None) -> float | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def _frame(rows: list[Any], columns: list[str]) -> pd.DataFrame:
    return pd.DataFrame([{c: row[c] for c in columns} for row in rows], columns=columns)


def overview(db: Database) -> dict[str, Any]:
    """Counts and chart data for the Overview page."""
    with db.connection() as conn:
        repo = Repository(conn)
        counts = repo.counts()
        start, end = repo.time_bounds()
        span = (end - start) if start is not None and end is not None else 0
        bucket = 60 if span <= 6 * 3600 else 3600 if span <= 14 * 86400 else 86400

        def series(pairs: list[tuple[Any, int]], key: str) -> pd.DataFrame:
            return pd.DataFrame(pairs, columns=[key, "count"])

        def timeline(table: str) -> pd.DataFrame:
            frame = pd.DataFrame(repo.timeline(table, bucket), columns=["epoch", "count"])
            frame["time"] = pd.to_datetime(frame["epoch"], unit="s", utc=True)
            return frame[["time", "count"]]

        severity = series(repo.group_count("alerts", "severity"), "severity")
        severity["label"] = severity["severity"].map(SEVERITY_LABELS)
        dedup = repo.dedup_summary()
        assets = pd.DataFrame([dict(r) for r in repo.top_attacked_assets(10)],
                              columns=["asset", "alerts", "detections", "max_severity"])
        gantt = pd.DataFrame([dict(r) for r in repo.list_incidents(limit=200)])
        return {
            "counts": counts,
            "dedup": dedup.to_dict(),
            "dedup_sentence": dedup.sentence(),
            "top_attacked_assets": assets,
            "incident_gantt": _incident_gantt(gantt),
            "alerts_by_severity": severity,
            "events_by_source": series(repo.group_count("events", "source_type"), "source_type"),
            "top_source_ips": series(repo.group_count("events", "src_ip", 10), "src_ip"),
            "top_target_hosts": series(repo.group_count("events", "hostname", 10), "hostname"),
            "event_timeline": timeline("events"),
            "incident_timeline": timeline("incidents"),
            "bucket_seconds": bucket,
        }


def _incident_gantt(frame: pd.DataFrame) -> pd.DataFrame:
    """One bar per incident from first to last seen (a zero-length incident still gets one second)."""
    columns = ["incident", "start", "end", "severity", "status", "title"]
    if frame.empty:
        return pd.DataFrame(columns=columns)
    start = pd.to_datetime(frame["first_seen"], utc=True, format="mixed")
    end = pd.to_datetime(frame["last_seen"], utc=True, format="mixed")
    end = end.where(end > start, start + pd.Timedelta(seconds=1))
    out = pd.DataFrame({"incident": "#" + frame["incident_id"].astype(str) + " " + frame["title"].str[:60],
                        "start": start, "end": end, "severity": frame["severity"].map(SEVERITY_LABELS),
                        "status": frame["status"], "title": frame["title"]})
    return out.sort_values("start").reset_index(drop=True)


def search_events(db: Database, *, ip: str | None = None, source_type: str | None = None,
                  min_severity: int | None = None, start: datetime | None = None,
                  end: datetime | None = None, text: str | None = None, page: int = 1,
                  page_size: int = 50) -> tuple[pd.DataFrame, int]:
    """Return (page of events, total matching rows)."""
    filters = {"ip": clean_ip_filter(ip), "source_type": source_type or None,
               "min_severity": min_severity, "start_ts": to_epoch(start), "end_ts": to_epoch(end),
               "text": (text or "").strip()[:200] or None}
    page_size = max(1, min(int(page_size), 500))
    page = max(1, int(page))
    with db.connection() as conn:
        repo = Repository(conn)
        total = repo.count_events(**filters)
        rows = repo.search_events(limit=page_size, offset=(page - 1) * page_size, **filters)
    return _frame(rows, EVENT_COLUMNS), total


def event_detail(db: Database, event_id: str) -> dict[str, Any] | None:
    with db.connection() as conn:
        return Repository(conn).get_event(event_id)


def source_types(db: Database) -> list[str]:
    with db.connection() as conn:
        return [k for k, _ in Repository(conn).group_count("events", "source_type", 50)]


def list_alerts(db: Database, *, rule_id: str | None = None, min_severity: int | None = None,
                src_ip: str | None = None, limit: int = 500) -> pd.DataFrame:
    with db.connection() as conn:
        rows = Repository(conn).list_alerts(rule_id=rule_id or None, min_severity=min_severity,
                                            src_ip=clean_ip_filter(src_ip), limit=limit)
    return _frame(rows, ALERT_COLUMNS)


def alert_detail(db: Database, alert_id: int) -> dict[str, Any] | None:
    """Return the alert, its parsed evidence and its linked events."""
    with db.connection() as conn:
        repo = Repository(conn)
        alert = repo.get_alert(int(alert_id))
        if alert is None:
            return None
        events = repo.alert_events(int(alert_id))
    data = dict(alert)
    try:
        data["evidence"] = json.loads(data["evidence"])
    except (TypeError, json.JSONDecodeError):
        data["evidence"] = {"unparsed": data["evidence"]}
    columns = ["timestamp_utc", "role", "source_type", "action", "src_ip", "dst_ip", "dst_port",
               "hostname", "username", "message", "event_id"]
    return {"alert": data, "events": _frame(events, columns)}


def list_incidents(db: Database, *, status: str | None = None, min_severity: int | None = None,
                   src_ip: str | None = None, text: str | None = None, analyst: str | None = None,
                   limit: int = 500) -> pd.DataFrame:
    with db.connection() as conn:
        rows = Repository(conn).list_incidents(status=status or None, min_severity=min_severity,
                                               src_ip=clean_ip_filter(src_ip),
                                               text=(text or "").strip()[:200] or None,
                                               analyst=(analyst or "").strip()[:100] or None, limit=limit)
    return _frame(rows, INCIDENT_COLUMNS)


def incident_detail(db: Database, settings: Settings, incident_id: int) -> dict[str, Any]:
    """Incident with alerts, events (with raw lines), timeline, notes and history as DataFrames."""
    with db.connection() as conn:
        manager = IncidentManager(conn, settings.correlation)
        data = manager.details(int(incident_id))
        timeline = manager.timeline(int(incident_id))
    events = pd.DataFrame(data["events"])
    frame = pd.DataFrame(timeline, columns=["time", "kind", "summary", "ref"])
    return {
        "incident": data["incident"],
        "alerts": pd.DataFrame(data["alerts"]),
        "events": events,
        "raw_lines": [str(e["raw_line"]) for e in data["events"]],
        "timeline": frame,
        "timeline_chart": timeline_chart(frame),
        "notes": pd.DataFrame(data["notes"], columns=["note_id", "incident_id", "created_at", "author", "note"]),
        "history": pd.DataFrame(data["history"], columns=["history_id", "incident_id", "changed_at", "actor",
                                                          "old_status", "new_status", "note"]),
    }


def update_incident_status(db: Database, settings: Settings, incident_id: int, status: str,
                           actor: str, note: str | None) -> None:
    with db.transaction() as conn:
        IncidentManager(conn, settings.correlation).update_status(int(incident_id), status, actor, note)


def add_incident_note(db: Database, settings: Settings, incident_id: int, note: str, author: str) -> None:
    with db.transaction() as conn:
        IncidentManager(conn, settings.correlation).add_note(int(incident_id), note, author)


def incident_report(db: Database, incident_id: int) -> str:
    with db.connection() as conn:
        return build_incident_report(conn, int(incident_id))


def timeline_chart(timeline: pd.DataFrame) -> pd.DataFrame:
    """Timeline entries with parsed times and a lane per kind, ready for an interactive scatter chart."""
    if timeline.empty:
        return pd.DataFrame(columns=["time", "lane", "summary", "ref"])
    lanes = {"event": "Log events", "alert": "Alerts", "history": "Status changes", "analyst_note": "Notes"}
    out = pd.DataFrame({"time": pd.to_datetime(timeline["time"], utc=True, format="mixed"),
                        "lane": timeline["kind"].map(lanes).fillna(timeline["kind"]),
                        "summary": timeline["summary"].astype(str).str[:200], "ref": timeline["ref"]})
    return out.sort_values("time").reset_index(drop=True)


def assign_incident(db: Database, settings: Settings, incident_id: int, analyst: str | None,
                    actor: str) -> None:
    """Assign (or with an empty name, unassign) an incident; errors are IncidentError."""
    with db.transaction() as conn:
        IncidentManager(conn, settings.correlation).assign(int(incident_id), analyst, actor)


def safe_upload_name(name: str) -> str:
    """A plain file name for an uploaded log: no folders, no odd characters, never empty."""
    base = re.split(r"[\\/]", str(name or ""))[-1]
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")[:100]
    return base or "upload.log"


def ingest_uploaded(db: Database, settings: Settings, source_type: str, file_name: str, content: bytes,
                    *, detect: bool = True, now: datetime | None = None) -> dict[str, Any]:
    """Save an uploaded log under datasets/uploads/, ingest it and (by default) run detection.

    The file is written inside the first allowed input folder, so the normal path checks still apply.
    """
    if source_type not in SOURCES:
        raise ValueError(f"unknown source type {source_type!r}")
    if not content:
        raise ValueError("the uploaded file is empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(f"the uploaded file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB; "
                         "import it with: python main.py ingest")
    folder = settings.allowed_input_dirs[0] / UPLOAD_DIR_NAME
    folder.mkdir(parents=True, exist_ok=True)
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%S")
    target = folder / f"{stamp}_{source_type}_{safe_upload_name(file_name)}"
    target.write_bytes(content)
    result = ingest_file(db, settings, source_type, target, now=now)
    output: dict[str, Any] = {"file": str(target), "ingest": result}
    if detect:
        output["detection"] = run_detection(db, settings)
    return output
