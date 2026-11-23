"""Repository: every SQL statement of the toolkit lives here (all parameterized)."""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable, Sequence

from normalizer.models import UnifiedEvent
from storage.database import utc_now
from storage.models import INCIDENT_STATUSES, OPEN_STATUSES, DedupSummary

__all__ = ["Repository", "INCIDENT_STATUSES", "OPEN_STATUSES"]
_EVENT_COLUMNS = ("event_id", "schema_version", "timestamp_utc", "ts_epoch", "source_type",
                  "hostname", "username", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                  "action", "severity", "message", "process_name", "process_path", "command_line",
                  "parent_process", "url", "http_status", "user_agent")
_EVENT_SORT = {"time_desc": "ts_epoch DESC, event_id", "time_asc": "ts_epoch ASC, event_id",
               "severity_desc": "severity DESC, ts_epoch DESC"}


def _like(term: str) -> str:
    """Escape LIKE wildcards so user text is matched literally."""
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Repository:
    """Data access bound to one open connection (the caller owns the transaction)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # ------------------------------------------------------------------ batches
    def create_batch(self, source_type: str, file_path: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO import_batches (source_type, file_path, started_at) VALUES (?, ?, ?)",
            (source_type, file_path, utc_now()))
        return int(cur.lastrowid)

    def finish_batch(self, batch_id: int, status: str, *, total_lines: int = 0, blank_lines: int = 0,
                     new_events: int = 0, new_rejected: int = 0, duplicates: int = 0,
                     error: str | None = None) -> None:
        self.conn.execute(
            "UPDATE import_batches SET status = ?, finished_at = ?, total_lines = ?, blank_lines = ?, "
            "new_events = ?, new_rejected = ?, duplicates = ?, error = ? WHERE batch_id = ?",
            (status, utc_now(), total_lines, blank_lines, new_events, new_rejected, duplicates,
             error, batch_id))

    # ------------------------------------------------------------- raw + events
    def insert_raw_events(self, rows: Sequence[tuple[str, int, str, int, str, str, str | None]]) -> int:
        """Insert (raw_id, batch_id, source_type, line_no, raw_line, status, error); return new rows."""
        if not rows:
            return 0
        now = utc_now()
        cur = self.conn.executemany(
            "INSERT OR IGNORE INTO raw_events (raw_id, batch_id, source_type, line_no, raw_line, status, "
            "error, ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(*row, now) for row in rows])
        return cur.rowcount

    def insert_events(self, events: Sequence[UnifiedEvent]) -> int:
        """Insert normalized events (duplicates by event_id are ignored); return new rows."""
        if not events:
            return 0
        placeholders = ", ".join("?" for _ in _EVENT_COLUMNS)
        cur = self.conn.executemany(
            f"INSERT OR IGNORE INTO events ({', '.join(_EVENT_COLUMNS)}) VALUES ({placeholders})",
            [(e.event_id, e.schema_version, e.timestamp_utc, e.ts_epoch, e.source_type,
              e.hostname, e.username, e.src_ip, e.dst_ip, e.src_port, e.dst_port, e.protocol,
              e.action, e.severity, e.message, e.process_name, e.process_path, e.command_line,
              e.parent_process, e.url, e.http_status, e.user_agent) for e in events])
        return cur.rowcount

    def reconcile_raw_status(self) -> int:
        """Mark raw lines as accepted when they now have a normalized event.

        A line rejected in an earlier import (for example under a different
        syslog year setting) may normalize successfully when imported again.
        """
        cur = self.conn.execute(
            "UPDATE raw_events SET status = 'accepted', error = NULL WHERE status = 'rejected' "
            "AND raw_id IN (SELECT event_id FROM events)")
        return cur.rowcount

    def _event_filters(self, *, ip: str | None = None, source_type: str | None = None,
                       min_severity: int | None = None, start_ts: float | None = None,
                       end_ts: float | None = None, text: str | None = None,
                       action: str | None = None) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if ip:
            clauses.append("(src_ip = ? OR dst_ip = ?)")
            params += [ip, ip]
        if source_type:
            clauses.append("source_type = ?")
            params.append(source_type)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if min_severity is not None:
            clauses.append("severity >= ?")
            params.append(int(min_severity))
        if start_ts is not None:
            clauses.append("ts_epoch >= ?")
            params.append(float(start_ts))
        if end_ts is not None:
            clauses.append("ts_epoch <= ?")
            params.append(float(end_ts))
        if text:
            pattern = _like(text)
            clauses.append("(message LIKE ? ESCAPE '\\' OR username LIKE ? ESCAPE '\\' OR "
                           "hostname LIKE ? ESCAPE '\\' OR command_line LIKE ? ESCAPE '\\' OR "
                           "process_path LIKE ? ESCAPE '\\')")
            params += [pattern] * 5
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    # Tuần 7: Tối ưu hóa truy vấn qua Index, nạp log theo lô (batch insert) và phân trang LIMIT/OFFSET
    def search_events(self, *, limit: int = 100, offset: int = 0, sort: str = "time_desc",
                      **filters: Any) -> list[sqlite3.Row]:
        """Search normalized events. ``sort`` must be one of the whitelisted keys."""
        where, params = self._event_filters(**filters)
        order = _EVENT_SORT.get(sort, _EVENT_SORT["time_desc"])
        limit = max(1, min(int(limit), 10000))
        offset = max(0, int(offset))
        return self.conn.execute(
            f"SELECT * FROM events{where} ORDER BY {order} LIMIT ? OFFSET ?",
            (*params, limit, offset)).fetchall()

    def count_events(self, **filters: Any) -> int:
        where, params = self._event_filters(**filters)
        return int(self.conn.execute(f"SELECT COUNT(*) FROM events{where}", params).fetchone()[0])

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        """Return one event in Unified Event Schema form, including ``raw_event``."""
        row = self.conn.execute(
            "SELECT e.*, r.raw_line FROM events e JOIN raw_events r ON r.raw_id = e.event_id "
            "WHERE e.event_id = ?", (event_id,)).fetchone()
        if row is None:
            return None
        event = {k: row[k] for k in row.keys() if k not in ("raw_line", "ts_epoch")}
        event["raw_event"] = self._raw_to_object(row["source_type"], row["raw_line"])
        return event

    @staticmethod
    def _raw_to_object(source_type: str, raw_line: str) -> dict[str, Any]:
        if source_type != "linux_auth":
            try:
                obj = json.loads(raw_line)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                pass
        return {"raw": raw_line}

    def get_raw_lines(self, event_ids: Iterable[str]) -> dict[str, str]:
        ids = list(event_ids)
        out: dict[str, str] = {}
        for i in range(0, len(ids), 500):
            chunk = ids[i:i + 500]
            marks = ", ".join("?" for _ in chunk)
            for row in self.conn.execute(
                    f"SELECT raw_id, raw_line FROM raw_events WHERE raw_id IN ({marks})", chunk):
                out[row["raw_id"]] = row["raw_line"]
        return out

    def list_rejected(self, limit: int = 100, offset: int = 0) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT raw_id, source_type, line_no, error, substr(raw_line, 1, 300) AS raw_line "
            "FROM raw_events WHERE status = 'rejected' ORDER BY ingested_at DESC, line_no LIMIT ? OFFSET ?",
            (limit, offset)).fetchall()

    # ------------------------------------------------------------------- alerts
    def find_overlapping_alerts(self, rule_id: str, entity_key: str, first_ts: float,
                                last_ts: float) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM alerts WHERE rule_id = ? AND entity_key = ? AND first_ts <= ? AND last_ts >= ? "
            "ORDER BY alert_id", (rule_id, entity_key, last_ts, first_ts)).fetchall()

    def find_alerts_near(self, rule_id: str, entity_key: str, start_ts: float,
                         end_ts: float) -> list[sqlite3.Row]:
        """Alerts of one rule/entity whose time range touches [start_ts, end_ts], with incident status."""
        return self.conn.execute(
            "SELECT a.*, i.status AS incident_status FROM alerts a "
            "LEFT JOIN incident_alerts ia ON ia.alert_id = a.alert_id "
            "LEFT JOIN incidents i ON i.incident_id = ia.incident_id "
            "WHERE a.rule_id = ? AND a.entity_key = ? AND a.first_ts <= ? AND a.last_ts >= ? "
            "ORDER BY a.first_ts, a.alert_id", (rule_id, entity_key, end_ts, start_ts)).fetchall()

    def insert_alert(self, values: dict[str, Any]) -> int:
        columns = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        cur = self.conn.execute(f"INSERT INTO alerts ({columns}) VALUES ({marks})", list(values.values()))
        return int(cur.lastrowid)

    def update_alert(self, alert_id: int, values: dict[str, Any]) -> None:
        assignments = ", ".join(f"{column} = ?" for column in values)
        self.conn.execute(f"UPDATE alerts SET {assignments} WHERE alert_id = ?",
                          (*values.values(), alert_id))

    def link_alert_events(self, alert_id: int, events: Iterable[tuple[str, str]]) -> int:
        cur = self.conn.executemany(
            "INSERT OR IGNORE INTO alert_events (alert_id, event_id, role) VALUES (?, ?, ?)",
            [(alert_id, event_id, role) for event_id, role in events])
        return cur.rowcount

    def count_alert_events(self, alert_id: int) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM alert_events WHERE alert_id = ?",
                                     (alert_id,)).fetchone()[0])

    def merge_alert_into(self, source_id: int, target_id: int) -> None:
        """Move evidence and the incident link of ``source_id`` to ``target_id`` and delete it."""
        self.conn.execute("INSERT OR IGNORE INTO alert_events (alert_id, event_id, role) "
                          "SELECT ?, event_id, role FROM alert_events WHERE alert_id = ?",
                          (target_id, source_id))
        self.conn.execute("INSERT OR IGNORE INTO incident_alerts (alert_id, incident_id) "
                          "SELECT ?, incident_id FROM incident_alerts WHERE alert_id = ?",
                          (target_id, source_id))
        self.conn.execute("DELETE FROM alerts WHERE alert_id = ?", (source_id,))

    def get_alert(self, alert_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()

    def list_alerts(self, *, rule_id: str | None = None, min_severity: int | None = None,
                    src_ip: str | None = None, limit: int = 200, offset: int = 0) -> list[sqlite3.Row]:
        clauses, params = [], []
        if rule_id:
            clauses.append("a.rule_id = ?")
            params.append(rule_id)
        if min_severity is not None:
            clauses.append("a.severity >= ?")
            params.append(int(min_severity))
        if src_ip:
            clauses.append("a.src_ip = ?")
            params.append(src_ip)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.conn.execute(
            f"SELECT a.*, ia.incident_id FROM alerts a LEFT JOIN incident_alerts ia "
            f"ON ia.alert_id = a.alert_id{where} ORDER BY a.last_ts DESC, a.alert_id DESC LIMIT ? OFFSET ?",
            (*params, max(1, min(int(limit), 10000)), max(0, int(offset)))).fetchall()

    def alert_events(self, alert_id: int, limit: int = 1000) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT e.*, ae.role FROM alert_events ae JOIN events e ON e.event_id = ae.event_id "
            "WHERE ae.alert_id = ? ORDER BY e.ts_epoch, e.event_id LIMIT ?", (alert_id, limit)).fetchall()

    # ---------------------------------------------------------------- incidents
    def incident_for_alert(self, alert_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT i.* FROM incident_alerts ia JOIN incidents i ON i.incident_id = ia.incident_id "
            "WHERE ia.alert_id = ?", (alert_id,)).fetchone()

    def find_open_incident(self, entity_key: str, first_ts: float, last_ts: float,
                           window: float) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM incidents WHERE entity_key = ? AND status IN ('NEW', 'IN_PROGRESS') "
            "AND first_ts - ? <= ? AND last_ts + ? >= ? ORDER BY incident_id LIMIT 1",
            (entity_key, window, last_ts, window, first_ts)).fetchone()

    def insert_incident(self, values: dict[str, Any]) -> int:
        columns = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        cur = self.conn.execute(f"INSERT INTO incidents ({columns}) VALUES ({marks})",
                                list(values.values()))
        return int(cur.lastrowid)

    def update_incident(self, incident_id: int, values: dict[str, Any]) -> None:
        assignments = ", ".join(f"{column} = ?" for column in values)
        self.conn.execute(f"UPDATE incidents SET {assignments} WHERE incident_id = ?",
                          (*values.values(), incident_id))

    def link_incident_alert(self, incident_id: int, alert_id: int) -> None:
        self.conn.execute("INSERT OR IGNORE INTO incident_alerts (alert_id, incident_id) VALUES (?, ?)",
                          (alert_id, incident_id))

    def link_incident_events_from_alert(self, incident_id: int, alert_id: int) -> int:
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO incident_events (incident_id, event_id) "
            "SELECT ?, event_id FROM alert_events WHERE alert_id = ?", (incident_id, alert_id))
        return cur.rowcount

    def add_history(self, incident_id: int, actor: str, old_status: str | None,
                    new_status: str | None, note: str | None) -> None:
        self.conn.execute(
            "INSERT INTO incident_history (incident_id, changed_at, actor, old_status, new_status, note) "
            "VALUES (?, ?, ?, ?, ?, ?)", (incident_id, utc_now(), actor, old_status, new_status, note))

    def add_note(self, incident_id: int, author: str, note: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO incident_notes (incident_id, created_at, author, note) VALUES (?, ?, ?, ?)",
            (incident_id, utc_now(), author, note))
        return int(cur.lastrowid)

    def get_incident(self, incident_id: int) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM incidents WHERE incident_id = ?",
                                 (incident_id,)).fetchone()

    def list_incidents(self, *, status: str | None = None, min_severity: int | None = None,
                       src_ip: str | None = None, text: str | None = None, analyst: str | None = None,
                       limit: int = 200, offset: int = 0) -> list[sqlite3.Row]:
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if analyst:
            clauses.append("assigned_analyst = ?")
            params.append(analyst)
        if min_severity is not None:
            clauses.append("severity >= ?")
            params.append(int(min_severity))
        if src_ip:
            clauses.append("(src_ip = ? OR dst_ip = ?)")
            params += [src_ip, src_ip]
        if text:
            pattern = _like(text)
            clauses.append("(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR "
                           "affected_asset LIKE ? ESCAPE '\\' OR assigned_analyst LIKE ? ESCAPE '\\')")
            params += [pattern] * 4
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return self.conn.execute(
            f"SELECT i.*, (SELECT COUNT(*) FROM incident_alerts ia WHERE ia.incident_id = i.incident_id) "
            f"AS alert_count, (SELECT COUNT(*) FROM incident_events ie WHERE ie.incident_id = "
            f"i.incident_id) AS event_count FROM incidents i{where} "
            f"ORDER BY i.last_ts DESC, i.incident_id DESC LIMIT ? OFFSET ?",
            (*params, max(1, min(int(limit), 10000)), max(0, int(offset)))).fetchall()

    def incident_alerts(self, incident_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT a.* FROM incident_alerts ia JOIN alerts a ON a.alert_id = ia.alert_id "
            "WHERE ia.incident_id = ? ORDER BY a.first_ts, a.alert_id", (incident_id,)).fetchall()

    def incident_events(self, incident_id: int, limit: int = 1000) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT e.*, r.raw_line FROM incident_events ie JOIN events e ON e.event_id = ie.event_id "
            "JOIN raw_events r ON r.raw_id = e.event_id WHERE ie.incident_id = ? "
            "ORDER BY e.ts_epoch, e.event_id LIMIT ?", (incident_id, limit)).fetchall()

    def incident_history(self, incident_id: int) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM incident_history WHERE incident_id = ? "
                                 "ORDER BY history_id", (incident_id,)).fetchall()

    def incident_notes(self, incident_id: int) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY note_id",
                                 (incident_id,)).fetchall()

    # -------------------------------------------------------------------- stats
    def counts(self) -> dict[str, int]:
        one = lambda sql: int(self.conn.execute(sql).fetchone()[0])  # noqa: E731
        return {
            "raw_events": one("SELECT COUNT(*) FROM raw_events"),
            "rejected_events": one("SELECT COUNT(*) FROM raw_events WHERE status = 'rejected'"),
            "events": one("SELECT COUNT(*) FROM events"),
            "alerts": one("SELECT COUNT(*) FROM alerts"),
            "incidents": one("SELECT COUNT(*) FROM incidents"),
            "active_incidents": one("SELECT COUNT(*) FROM incidents WHERE status IN ('NEW', 'IN_PROGRESS')"),
            "closed_incidents": one("SELECT COUNT(*) FROM incidents WHERE status IN ('CLOSED', 'FALSE_POSITIVE')"),
        }

    def dedup_summary(self) -> DedupSummary:
        """Raw alerts (rule detections + Suricata alerts) versus deduplicated alerts and incidents."""
        row = self.conn.execute(
            "SELECT (SELECT COALESCE(SUM(occurrence_count), 0) FROM alerts), "
            "(SELECT COUNT(*) FROM events WHERE action = 'ids_alert'), "
            "(SELECT COUNT(*) FROM alerts), (SELECT COUNT(*) FROM incidents)").fetchone()
        return DedupSummary(raw_detections=int(row[0]), ids_alerts=int(row[1]), alerts=int(row[2]),
                            incidents=int(row[3]))

    def top_attacked_assets(self, limit: int = 10) -> list[sqlite3.Row]:
        """Assets (target host, else target IP) ranked by the alerts raised against them."""
        return self.conn.execute(
            "SELECT COALESCE(hostname, dst_ip) AS asset, COUNT(*) AS alerts, "
            "SUM(occurrence_count) AS detections, MAX(severity) AS max_severity FROM alerts "
            "WHERE COALESCE(hostname, dst_ip) IS NOT NULL GROUP BY asset "
            "ORDER BY alerts DESC, max_severity DESC, asset LIMIT ?", (int(limit),)).fetchall()

    def group_count(self, table: str, column: str, limit: int = 10) -> list[tuple[Any, int]]:
        """COUNT(*) GROUP BY for a whitelisted table/column pair."""
        allowed = {("events", "source_type"), ("events", "src_ip"), ("events", "hostname"),
                   ("events", "action"), ("alerts", "severity"), ("alerts", "rule_id"),
                   ("incidents", "status"), ("incidents", "severity")}
        if (table, column) not in allowed:
            raise ValueError(f"grouping not allowed: {table}.{column}")
        rows = self.conn.execute(
            f"SELECT {column} AS k, COUNT(*) AS n FROM {table} WHERE {column} IS NOT NULL "
            f"GROUP BY {column} ORDER BY n DESC, k LIMIT ?", (limit,)).fetchall()
        return [(r["k"], r["n"]) for r in rows]

    def timeline(self, table: str, bucket_seconds: int = 3600) -> list[tuple[float, int]]:
        """Event or incident counts per time bucket (bucket start epoch, count)."""
        column = {"events": "ts_epoch", "incidents": "first_ts", "alerts": "first_ts"}.get(table)
        if column is None:
            raise ValueError(f"timeline not allowed for table {table}")
        bucket = max(1, int(bucket_seconds))
        rows = self.conn.execute(
            f"SELECT CAST({column} / ? AS INTEGER) * ? AS b, COUNT(*) AS n FROM {table} "
            f"GROUP BY b ORDER BY b", (bucket, bucket)).fetchall()
        return [(float(r["b"]), r["n"]) for r in rows]

    def time_bounds(self) -> tuple[float | None, float | None]:
        row = self.conn.execute("SELECT MIN(ts_epoch), MAX(ts_epoch) FROM events").fetchone()
        return row[0], row[1]
