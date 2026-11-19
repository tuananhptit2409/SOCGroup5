"""Pipeline orchestration: ingest -> normalize -> store, then detect -> correlate -> incidents."""
from __future__ import annotations

import hashlib
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from config import Settings
from engine.correlation import AlertManager
from engine.incident_manager import IncidentManager
from engine.rule_engine import RuleEngine, build_default_rules
from ingest import linux_auth, suricata, sysmon
from ingest.base import LineRecord, ParseError, iter_lines, resolve_input_path
from normalizer import linux_normalizer, suricata_normalizer, sysmon_normalizer
from normalizer.models import NormalizationError, NormalizeContext, UnifiedEvent
from storage.database import Database, DatabaseError
from storage.repository import Repository

logger = logging.getLogger(__name__)

SOURCES: dict[str, tuple[Callable[[str], dict[str, Any]], Callable[..., UnifiedEvent]]] = {
    linux_auth.SOURCE_TYPE: (linux_auth.parse_line, linux_normalizer.normalize),
    suricata.SOURCE_TYPE: (suricata.parse_line, suricata_normalizer.normalize),
    sysmon.SOURCE_TYPE: (sysmon.parse_line, sysmon_normalizer.normalize),
}


class PipelineError(Exception):
    """Invalid pipeline request (for example an unknown source type)."""


@dataclass
class IngestResult:
    source_type: str
    file_path: str
    batch_id: int = 0
    total_lines: int = 0
    blank_lines: int = 0
    parsed_ok: int = 0          # lines of this file that normalized successfully
    rejected: int = 0           # lines of this file that were rejected
    new_events: int = 0         # events actually added to the database
    new_rejected: int = 0       # rejected raw lines actually added to the database
    duplicates: int = 0         # lines already stored earlier (or repeated in the file)
    reject_reasons: dict[str, int] = field(default_factory=dict)
    seconds_parse: float = 0.0
    seconds_normalize: float = 0.0
    seconds_database: float = 0.0
    seconds_total: float = 0.0


@dataclass
class DetectionSummary:
    detections: int = 0
    per_rule: dict[str, int] = field(default_factory=dict)
    alerts_new: int = 0
    alerts_updated: int = 0
    alerts_duplicate: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0
    rule_errors: dict[str, str] = field(default_factory=dict)
    seconds_detection: float = 0.0
    seconds_correlation: float = 0.0
    seconds_per_rule: dict[str, float] = field(default_factory=dict)


def raw_id_for(source_type: str, line: str) -> str:
    """Deterministic id of a raw line; it makes re-importing a file idempotent."""
    return hashlib.sha256(f"{source_type}\n{line}".encode("utf-8", errors="replace")).hexdigest()[:32]


def ingest_file(db: Database, settings: Settings, source_type: str, path: str | Path,
                now: datetime | None = None) -> IngestResult:
    """Ingest one log file: parse, normalize and store it batch by batch.

    A bad line never stops the run: it is stored in ``raw_events`` with
    status ``rejected`` and the reason. Re-importing the same content adds
    nothing (the raw line hash is the primary key).
    """
    if source_type not in SOURCES:
        raise PipelineError(f"unknown source type {source_type!r}; expected one of {', '.join(SOURCES)}")
    resolved = resolve_input_path(path, settings.allowed_input_dirs)
    parse_line, normalize = SOURCES[source_type]
    ctx = NormalizeContext(now=now or datetime.now(timezone.utc),
                           syslog_default_year=settings.syslog_default_year,
                           syslog_utc_offset_minutes=settings.syslog_utc_offset_minutes)
    result = IngestResult(source_type=source_type, file_path=str(resolved))
    reasons: Counter[str] = Counter()
    started = time.perf_counter()
    with db.transaction() as conn:
        result.batch_id = Repository(conn).create_batch(source_type, str(resolved))

    def flush(batch: list[LineRecord]) -> None:
        t0 = time.perf_counter()
        parsed: list[tuple[LineRecord, str, dict[str, Any] | None, str | None]] = []
        for record in batch:
            raw_id = raw_id_for(source_type, record.text)
            if record.too_long:
                parsed.append((record, raw_id, None, "line_too_long"))
                continue
            try:
                parsed.append((record, raw_id, parse_line(record.text), None))
            except ParseError as exc:
                parsed.append((record, raw_id, None, str(exc)))
            except Exception as exc:  # a parser bug must reject one line, never stop the import
                logger.warning("event=unexpected_parse_error source=%s line=%d error=%s",
                               source_type, record.line_no, type(exc).__name__)
                parsed.append((record, raw_id, None, f"unexpected_error: {type(exc).__name__}"))
        t1 = time.perf_counter()
        raw_rows, events = [], []
        for record, raw_id, fields, error in parsed:
            if fields is not None:
                try:
                    events.append(normalize(fields, record.text, raw_id, ctx))
                except NormalizationError as exc:
                    error = str(exc)
                except Exception as exc:  # same guarantee for the normalizers
                    logger.warning("event=unexpected_normalize_error source=%s line=%d error=%s",
                                   source_type, record.line_no, type(exc).__name__)
                    error = f"unexpected_error: {type(exc).__name__}"
            if error is not None:
                reasons[error.split(":", 1)[0]] += 1
                result.rejected += 1
                raw_rows.append((raw_id, result.batch_id, source_type, record.line_no, record.text,
                                 "rejected", error[:300]))
            else:
                result.parsed_ok += 1
                raw_rows.append((raw_id, result.batch_id, source_type, record.line_no, record.text,
                                 "accepted", None))
        t2 = time.perf_counter()
        with db.transaction() as conn:
            repo = Repository(conn)
            new_raw = repo.insert_raw_events(raw_rows)
            new_events = repo.insert_events(events)
        result.new_events += new_events
        result.new_rejected += max(0, new_raw - new_events)
        result.duplicates += len(raw_rows) - new_raw
        result.seconds_parse += t1 - t0
        result.seconds_normalize += t2 - t1
        result.seconds_database += time.perf_counter() - t2

    try:
        batch: list[LineRecord] = []
        for record in iter_lines(resolved, settings.max_line_length):
            result.total_lines += 1
            if not record.text.strip() and not record.too_long:
                result.blank_lines += 1
                continue
            batch.append(record)
            if len(batch) >= settings.batch_size:
                flush(batch)
                batch = []
        if batch:
            flush(batch)
    except Exception as exc:
        logger.error("event=ingest_failed source=%s file=%s error=%s", source_type, resolved.name, exc)
        try:
            with db.transaction() as conn:
                Repository(conn).finish_batch(result.batch_id, "failed", total_lines=result.total_lines,
                                              blank_lines=result.blank_lines, new_events=result.new_events,
                                              new_rejected=result.new_rejected,
                                              duplicates=result.duplicates, error=str(exc)[:300])
        except DatabaseError as status_exc:   # keep the original error; the batch stays 'running'
            logger.error("event=batch_status_not_saved batch_id=%d error=%s", result.batch_id, status_exc)
        raise
    result.reject_reasons = dict(reasons)
    result.seconds_total = time.perf_counter() - started
    with db.transaction() as conn:
        Repository(conn).reconcile_raw_status()
        Repository(conn).finish_batch(result.batch_id, "completed", total_lines=result.total_lines,
                                      blank_lines=result.blank_lines, new_events=result.new_events,
                                      new_rejected=result.new_rejected, duplicates=result.duplicates)
    logger.info("event=ingest_completed source=%s file=%s lines=%d new_events=%d rejected=%d "
                "duplicates=%d seconds=%.3f", source_type, resolved.name, result.total_lines,
                result.new_events, result.rejected, result.duplicates, result.seconds_total)
    return result


def run_detection(db: Database, settings: Settings) -> DetectionSummary:
    """Run all rules over the stored events, then deduplicate alerts and sync incidents.

    Everything happens in one transaction, so a failure leaves alerts and
    incidents exactly as they were. Running it again on unchanged data creates
    no new alerts or incidents.
    """
    summary = DetectionSummary()
    with db.transaction() as conn:
        started = time.perf_counter()
        engine_result = RuleEngine(build_default_rules(settings)).run(conn)
        summary.seconds_detection = time.perf_counter() - started
        summary.detections = len(engine_result.detections)
        summary.per_rule = engine_result.per_rule
        summary.rule_errors = engine_result.errors
        summary.seconds_per_rule = engine_result.seconds_per_rule

        started = time.perf_counter()
        alerts = AlertManager(conn)
        incidents = IncidentManager(conn, settings.correlation)
        for detection in sorted(engine_result.detections, key=lambda d: (d.first_ts, d.rule_id, d.entity_key)):
            alert_id, outcome = alerts.persist(detection)
            if outcome == "new":
                summary.alerts_new += 1
            elif outcome == "updated":
                summary.alerts_updated += 1
            else:
                summary.alerts_duplicate += 1
            _incident_id, action = incidents.sync_alert(alert_id, outcome)
            if action == "created":
                summary.incidents_created += 1
            elif action in ("linked", "updated"):
                summary.incidents_updated += 1
        summary.seconds_correlation = time.perf_counter() - started
    logger.info("event=detection_completed detections=%d alerts_new=%d alerts_updated=%d "
                "alerts_duplicate=%d incidents_created=%d", summary.detections, summary.alerts_new,
                summary.alerts_updated, summary.alerts_duplicate, summary.incidents_created)
    return summary
