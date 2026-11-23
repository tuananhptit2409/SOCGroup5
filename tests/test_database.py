"""Database tests: schema, constraints, transactions, search, persistence."""
from __future__ import annotations

import sqlite3

import pytest

from datasets import synth as s
from normalizer.models import SCHEMA_VERSION
from storage.database import REQUIRED_TABLES, Database, DatabaseError
from storage.repository import Repository


def test_init_schema_creates_all_tables_and_is_idempotent(db: Database) -> None:
    db.init_schema()
    db.check_schema()
    with db.connection() as conn:
        tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        indexes = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    assert set(REQUIRED_TABLES) <= tables
    assert {"idx_events_ts", "idx_events_src_ip", "idx_events_dst_ip", "idx_events_severity",
            "idx_events_source", "idx_incidents_status"} <= indexes


def test_connection_pragmas(db: Database) -> None:
    with db.connection() as conn:
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000


def test_missing_database_gives_clear_error(tmp_path) -> None:
    db = Database(tmp_path / "nope.db")
    with pytest.raises(DatabaseError, match="not found"):
        db.check_schema()
    assert not (tmp_path / "nope.db").exists()      # reading must not create an empty file


def test_uninitialized_and_corrupt_database_give_clear_errors(tmp_path) -> None:
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()
    with pytest.raises(DatabaseError, match="not initialized"):
        Database(empty).check_schema()
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not a sqlite database" * 100)
    with pytest.raises(DatabaseError):
        Database(corrupt).check_schema()


def test_foreign_keys_are_enforced(db: Database) -> None:
    with db.connection() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO raw_events (raw_id, batch_id, source_type, line_no, raw_line, status, "
                         "ingested_at) VALUES ('x', 9999, 'linux_auth', 1, 'l', 'accepted', 'now')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO incident_events (incident_id, event_id) VALUES (1, 'missing')")


def test_check_constraints(db: Database, ingest) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(0), "h", "root", "10.0.0.1", 22)])
    with db.connection() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE events SET severity = 9")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE events SET dst_port = 70000")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO incidents (entity_key, title, description, severity, status, rule_id, "
                         "first_seen, last_seen, first_ts, last_ts, created_at, updated_at) "
                         "VALUES ('e', 't', 'd', 3, 'BOGUS', 'r', 'a', 'b', 0, 0, 'c', 'd')")


def test_unique_constraints(db: Database, ingest, detect) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)])
    detect()
    with db.connection() as conn:
        row = conn.execute("SELECT * FROM alerts").fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO alerts (fingerprint, rule_id, rule_name, severity, entity_key, first_seen, "
                         "last_seen, first_ts, last_ts, evidence, rationale, created_at, updated_at) "
                         "VALUES (?, 'r', 'n', 3, 'e', 'a', 'b', 0, 0, '{}', 'x', 'c', 'd')", (row["fingerprint"],))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO incident_alerts (alert_id, incident_id) VALUES (?, 1)", (row["alert_id"],))


def test_transaction_rolls_back_on_error(db: Database, count) -> None:
    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            Repository(conn).create_batch("linux_auth", "file.log")
            assert conn.execute("SELECT COUNT(*) FROM import_batches").fetchone()[0] == 1
            raise RuntimeError("boom")
    assert count("import_batches") == 0
    with db.transaction() as conn:
        Repository(conn).create_batch("linux_auth", "file.log")
    assert count("import_batches") == 1


def test_search_events_filters_and_pagination(db: Database, ingest) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(i * 10), "web01", "root", "203.0.113.1", 1000 + i, i) for i in range(30)]
           + [s.linux_accepted(s.at(500), "db01", "ops", "10.0.0.9", 2000)])
    ingest("suricata", [s.suricata_alert(s.at(100), "203.0.113.1", 1, "10.0.0.2", 80, "SIG one", 1),
                        s.suricata_flow(s.at(200), "10.0.0.9", 2, "203.0.113.1", 443)])
    with db.connection() as conn:
        repo = Repository(conn)
        assert repo.count_events() == 33
        assert repo.count_events(ip="203.0.113.1") == 32            # as source or destination
        assert repo.count_events(ip="10.0.0.9") == 2
        assert repo.count_events(source_type="suricata") == 2
        assert repo.count_events(min_severity=4) == 1
        assert repo.count_events(text="SIG") == 1 and repo.count_events(text="db01") == 1
        base = s.at(0).timestamp()
        assert repo.count_events(start_ts=base + 100, end_ts=base + 200) == 13
        page1 = repo.search_events(limit=10, offset=0, sort="time_asc")
        page2 = repo.search_events(limit=10, offset=10, sort="time_asc")
        assert len(page1) == 10 and len(page2) == 10
        assert not {r["event_id"] for r in page1} & {r["event_id"] for r in page2}
        assert page1[0]["ts_epoch"] <= page1[-1]["ts_epoch"] <= page2[0]["ts_epoch"]
        assert repo.search_events(limit=10, offset=1000) == []


def test_search_uses_indexes(db: Database) -> None:
    with db.connection() as conn:
        def plan(sql: str) -> str:
            return " ".join(r["detail"] for r in conn.execute("EXPLAIN QUERY PLAN " + sql))
        assert "idx_events_src_ip" in plan("SELECT * FROM events WHERE src_ip = '1.1.1.1'")
        assert "idx_events_dst_ip" in plan("SELECT * FROM events WHERE dst_ip = '1.1.1.1'")
        assert "idx_events_ts" in plan("SELECT * FROM events WHERE ts_epoch BETWEEN 1 AND 2")
        assert "idx_events_source" in plan("SELECT * FROM events WHERE source_type = 'sysmon'")
        assert "idx_incidents_status" in plan("SELECT * FROM incidents WHERE status = 'NEW'")
        assert "idx_incident_events_event" in plan("SELECT * FROM incident_events WHERE event_id = 'x'") \
            or "sqlite_autoindex" in plan("SELECT * FROM incident_events WHERE incident_id = 1")


def test_get_event_returns_unified_schema_with_raw_event(db: Database, ingest) -> None:
    line = s.suricata_alert(s.at(0), "10.0.0.1", 1, "10.0.0.2", 80, "SIG", 1)
    ingest("suricata", [line])
    with db.connection() as conn:
        repo = Repository(conn)
        event_id = repo.search_events()[0]["event_id"]
        event = repo.get_event(event_id)
        assert event["raw_event"]["alert"]["signature"] == "SIG" and event["schema_version"] == SCHEMA_VERSION
        assert repo.get_event("missing") is None


def test_group_count_and_timeline_whitelists(db: Database) -> None:
    with db.connection() as conn:
        repo = Repository(conn)
        with pytest.raises(ValueError):
            repo.group_count("events", "raw_id; DROP TABLE events")
        with pytest.raises(ValueError):
            repo.timeline("sqlite_master")
        assert repo.group_count("events", "src_ip") == [] and repo.timeline("events") == []


def test_data_survives_reopen_and_integrity_is_ok(settings, db: Database, ingest, detect, count) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)])
    detect()
    before = {t: count(t) for t in ("raw_events", "events", "alerts", "incidents", "incident_events")}
    reopened = Database(settings.db_path)        # simulates an application restart
    reopened.check_schema()
    with reopened.connection() as conn:
        after = {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in before}
    assert after == before and before["incidents"] == 1
    report = reopened.integrity_report()
    assert report == {"integrity_check": ["ok"], "foreign_key_violations": [], "journal_mode": "wal"}


def test_delete_cascades_only_through_links(db: Database, ingest, detect, count) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)])
    detect()
    with db.transaction() as conn:
        conn.execute("DELETE FROM incidents")
    assert count("incident_alerts") == 0 and count("incident_events") == 0 and count("incident_history") == 0
    assert count("alerts") == 1 and count("events") == 6      # evidence itself is never deleted by a cascade
    with db.connection() as conn:
        with pytest.raises(sqlite3.IntegrityError):         # events referenced by alerts cannot be removed
            conn.execute("DELETE FROM events")
