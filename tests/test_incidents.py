"""Correlation, deduplication and incident lifecycle tests."""
from __future__ import annotations

import json

import pytest

from datasets import synth as s
from engine.incident_manager import IncidentError, IncidentManager
from reporting import build_incident_report
from storage.database import Database
from storage.repository import Repository

ATTACKER = "203.0.113.10"


def fails(n: int, start: float = 0, ip: str = ATTACKER, host: str = "web01", spacing: float = 5):
    return [s.linux_failed(s.at(start + i * spacing), host, "root", ip, 40000 + int(start) + i, 100 + i)
            for i in range(n)]


def incidents(db: Database) -> list[dict]:
    with db.connection() as conn:
        return [dict(r) for r in Repository(conn).list_incidents()][::-1]


def set_status(db: Database, incident_id: int, status: str, note: str | None = None) -> None:
    with db.transaction() as conn:
        IncidentManager(conn).update_status(incident_id, status, "tester", note)


# ---------------------------------------------------------------- deduplication
def test_rerunning_detection_creates_no_duplicates(db, ingest, detect, count) -> None:
    ingest("linux_auth", fails(6))
    first = detect()
    second = detect()
    third = detect()
    assert (first.alerts_new, first.incidents_created) == (1, 1)
    assert (second.alerts_new, second.alerts_duplicate, second.incidents_created) == (0, 1, 0)
    assert (third.alerts_new, third.alerts_updated, third.incidents_updated) == (0, 0, 0)
    assert count("alerts") == 1 and count("incidents") == 1 and count("alert_events") == 6
    assert count("incident_events") == 6 and count("incident_history") == 1


def test_new_events_in_same_burst_update_the_alert(db, ingest, detect, alerts, count) -> None:
    ingest("linux_auth", fails(6))
    detect()
    ingest("linux_auth", fails(3, start=30))            # continues the burst (gap < 60s)
    summary = detect()
    assert (summary.alerts_new, summary.alerts_updated) == (0, 1)
    (alert,) = alerts()
    assert alert["event_count"] == 9 and alert["occurrence_count"] == 1     # still ONE burst
    (incident,) = incidents(db)
    assert incident["event_count"] == 9 and incident["alert_count"] == 1 and count("incidents") == 1


def test_escalation_updates_alert_and_incident_severity(db, ingest, detect, alerts) -> None:
    ingest("linux_auth", fails(6))
    detect()
    assert incidents(db)[0]["severity"] == 3
    ingest("linux_auth", [s.linux_accepted(s.at(40), "web01", "root", ATTACKER, 50000, 999)])
    detect()
    assert alerts()[0]["severity"] == 5 and incidents(db)[0]["severity"] == 5


def test_late_event_bridging_two_alerts_merges_them(db, ingest, detect, count, settings) -> None:
    from dataclasses import replace
    from config import CorrelationConfig
    no_cooldown = replace(settings, correlation=CorrelationConfig(alert_cooldown_seconds=1))
    ingest("linux_auth", fails(5, start=0) + fails(5, start=90))      # gap of 70s -> two bursts
    detect(no_cooldown)
    assert count("alerts") == 2 and count("incidents") == 1           # same entity, close in time
    ingest("linux_auth", [s.linux_failed(s.at(55), "web01", "root", ATTACKER, 49999, 998)])   # bridges the gap
    detect(no_cooldown)
    assert count("alerts") == 1 and count("incidents") == 1
    with db.connection() as conn:
        assert conn.execute("SELECT event_count FROM alerts").fetchone()[0] == 11
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


# ------------------------------------------------------------------ correlation
def test_related_alerts_of_same_source_join_one_incident(db, ingest, detect, count) -> None:
    scanner = "10.0.0.50"
    ingest("suricata", [s.suricata_flow(s.at(i), scanner, 50000 + i, "10.0.0.20", 1000 + i, i) for i in range(20)])
    ingest("linux_auth", fails(6, start=120, ip=scanner, host="srv20"))
    detect()
    assert count("alerts") == 2 and count("incidents") == 1
    (incident,) = incidents(db)
    assert incident["alert_count"] == 2 and incident["event_count"] == 26 and incident["occurrence_count"] == 2
    with db.connection() as conn:
        rules = {r["rule_id"] for r in Repository(conn).incident_alerts(incident["incident_id"])}
        notes = [r["note"] for r in Repository(conn).incident_history(incident["incident_id"])]
    assert rules == {"SOC-001", "SOC-002"} and any("Related alert" in (n or "") for n in notes)


def test_unrelated_alerts_close_in_time_stay_separate(db, ingest, detect, count) -> None:
    ingest("linux_auth", fails(6, ip="203.0.113.1") + fails(6, ip="203.0.113.2"))
    ingest("sysmon", [s.sysmon_process(s.at(3), "WS01", r"C:\Windows\Temp\x.exe", "x.exe", None)])
    detect()
    assert count("alerts") == 3 and count("incidents") == 3


def test_same_source_far_apart_in_time_gives_separate_incidents(db, ingest, detect, count) -> None:
    ingest("linux_auth", fails(6, start=0) + fails(6, start=7200))
    detect()
    assert count("alerts") == 2 and count("incidents") == 2


# -------------------------------------------------------------------- lifecycle
def test_status_changes_are_recorded(db, ingest, detect) -> None:
    ingest("linux_auth", fails(6))
    detect()
    incident_id = incidents(db)[0]["incident_id"]
    set_status(db, incident_id, "IN_PROGRESS", "looking")
    set_status(db, incident_id, "CLOSED", "blocked at firewall")
    with db.connection() as conn:
        incident = Repository(conn).get_incident(incident_id)
        history = [dict(r) for r in Repository(conn).incident_history(incident_id)]
    assert incident["status"] == "CLOSED" and incident["closed_at"] is not None
    assert [(h["old_status"], h["new_status"], h["actor"]) for h in history] == [
        (None, "NEW", "system"), ("NEW", "IN_PROGRESS", "tester"), ("IN_PROGRESS", "CLOSED", "tester")]
    assert history[2]["note"] == "blocked at firewall" and all(h["changed_at"] for h in history)


def test_false_positive_and_reopen(db, ingest, detect) -> None:
    ingest("linux_auth", fails(6))
    detect()
    incident_id = incidents(db)[0]["incident_id"]
    set_status(db, incident_id, "FALSE_POSITIVE")
    with db.connection() as conn:
        assert Repository(conn).get_incident(incident_id)["closed_at"] is not None
    set_status(db, incident_id, "IN_PROGRESS")
    with db.connection() as conn:
        row = Repository(conn).get_incident(incident_id)
    assert row["status"] == "IN_PROGRESS" and row["closed_at"] is None


@pytest.mark.parametrize("status", ["DONE", "new", "", "CLOSED; DROP TABLE incidents"])
def test_invalid_status_is_rejected(db, ingest, detect, status: str) -> None:
    ingest("linux_auth", fails(6))
    detect()
    with pytest.raises(IncidentError, match="invalid status"):
        set_status(db, 1, status)
    assert incidents(db)[0]["status"] == "NEW"


def test_same_status_and_unknown_incident_are_rejected(db, ingest, detect) -> None:
    ingest("linux_auth", fails(6))
    detect()
    with pytest.raises(IncidentError, match="already NEW"):
        set_status(db, 1, "NEW")
    with pytest.raises(IncidentError, match="not found"):
        set_status(db, 999, "CLOSED")


def test_closed_incident_is_not_duplicated_by_reprocessing(db, ingest, detect, count) -> None:
    ingest("linux_auth", fails(6))
    detect()
    set_status(db, 1, "CLOSED")
    summary = detect()
    assert summary.incidents_created == 0 and count("incidents") == 1
    assert incidents(db)[0]["status"] == "CLOSED"


def test_new_wave_after_close_creates_new_incident(db, ingest, detect, count) -> None:
    ingest("linux_auth", fails(6, start=0))
    detect()
    set_status(db, 1, "CLOSED")
    ingest("linux_auth", fails(6, start=600))           # same attacker, new burst 10 minutes later
    summary = detect()
    assert summary.incidents_created == 1 and count("incidents") == 2
    old, new = incidents(db)
    assert (old["status"], new["status"]) == ("CLOSED", "NEW") and old["event_count"] == 6 == new["event_count"]


def test_new_wave_while_open_joins_existing_alert_within_cooldown(db, ingest, detect, alerts, count) -> None:
    ingest("linux_auth", fails(6, start=0))
    detect()
    ingest("linux_auth", fails(6, start=600))            # 575 s after the first burst: inside the cooldown
    detect()
    (alert,) = alerts()
    assert alert["occurrence_count"] == 2 and alert["event_count"] == 12 and count("incidents") == 1


def test_new_wave_after_cooldown_while_open_joins_existing_incident(db, ingest, detect, count) -> None:
    ingest("linux_auth", fails(6, start=0))
    detect()
    ingest("linux_auth", fails(6, start=1200))           # outside the 600 s cooldown, inside the 1800 s incident window
    detect()
    assert count("alerts") == 2 and count("incidents") == 1 and incidents(db)[0]["occurrence_count"] == 2


def test_new_evidence_on_closed_incident_reopens_it(db, ingest, detect, count) -> None:
    ingest("linux_auth", fails(6))
    detect()
    set_status(db, 1, "CLOSED")
    ingest("linux_auth", fails(2, start=40))            # same burst continues
    detect()
    (incident,) = incidents(db)
    assert incident["status"] == "NEW" and incident["event_count"] == 8 and count("incidents") == 1
    with db.connection() as conn:
        last = Repository(conn).incident_history(1)[-1]
    assert (last["old_status"], last["new_status"], last["actor"]) == ("CLOSED", "NEW", "system")


def test_new_evidence_on_false_positive_keeps_status_but_is_logged(db, ingest, detect) -> None:
    ingest("linux_auth", fails(6))
    detect()
    set_status(db, 1, "FALSE_POSITIVE")
    ingest("linux_auth", fails(2, start=40))
    detect()
    assert incidents(db)[0]["status"] == "FALSE_POSITIVE"
    with db.connection() as conn:
        assert "FALSE_POSITIVE" in Repository(conn).incident_history(1)[-1]["note"]


# ------------------------------------------------------- notes, views, report
def test_notes_details_timeline_and_report(db, ingest, detect) -> None:
    ingest("linux_auth", fails(6) + [s.linux_accepted(s.at(40), "web01", "root", ATTACKER, 50000, 999)])
    detect()
    with db.transaction() as conn:
        manager = IncidentManager(conn)
        manager.add_note(1, "  Checked firewall | logs  ", "alice")
        with pytest.raises(IncidentError, match="empty"):
            manager.add_note(1, "   ")
        with pytest.raises(IncidentError, match="not found"):
            manager.add_note(42, "x")
    with db.connection() as conn:
        manager = IncidentManager(conn)
        details = manager.details(1)
        timeline = manager.timeline(1)
        report = build_incident_report(conn, 1)
        with pytest.raises(IncidentError):
            build_incident_report(conn, 42)
    assert len(details["events"]) == 7 and len(details["alerts"]) == 1
    assert details["notes"][0]["note"] == "Checked firewall | logs"
    assert all("Failed password" in e["raw_line"] or "Accepted" in e["raw_line"] for e in details["events"])
    kinds = [entry["kind"] for entry in timeline]
    assert kinds.count("event") == 7 and "alert" in kinds and "history" in kinds and "analyst_note" in kinds
    assert [e["time"] for e in timeline] == sorted(e["time"] for e in timeline)
    assert report.startswith("# Incident Report #1") and "SOC-001" in report
    assert "success_after_failures" in report and "Failed password for root from 203.0.113.10" in report
    assert "Checked firewall \\| logs" in report      # table cell is escaped


def test_report_neutralizes_markup_in_log_data(db, ingest, detect) -> None:
    payload = "<script>alert(1)</script>|`x`"
    lines = [s.linux_failed(s.at(i * 5), "<b>web01</b>", "u```x", ATTACKER, 40000 + i, 100 + i)
             for i in range(6)]
    ingest("linux_auth", lines)
    detect()
    with db.transaction() as conn:
        IncidentManager(conn).add_note(1, payload, payload)
    with db.connection() as conn:
        report = build_incident_report(conn, 1)
    tables = "\n".join(line for line in report.splitlines() if line.startswith(("|", "- ")))
    assert "<script>" not in tables and "<b>" not in tables
    assert "\\<script\\>" in tables and "\\<b\\>web01" in tables
    fences = [line for line in report.splitlines() if line.startswith("```")]
    assert len(fences) % 2 == 0 and "u```" not in report      # log data cannot close a code block


# --------------------------------------------------- deduplication (cooldown window)
def _cooldown_settings(settings, seconds: int):
    from dataclasses import replace
    from config import CorrelationConfig
    return replace(settings, correlation=CorrelationConfig(alert_cooldown_seconds=seconds))


@pytest.mark.parametrize("gap,expected_alerts", [(100, 1), (101, 2)])
def test_cooldown_boundary_is_inclusive(ingest, detect, count, settings, gap: int, expected_alerts: int) -> None:
    first = fails(5, start=0)                        # last event at t=20
    second = fails(5, start=20 + gap)                # starts exactly `gap` seconds later
    ingest("linux_auth", first + second)
    detect(_cooldown_settings(settings, 100))
    assert count("alerts") == expected_alerts


def test_occurrence_count_is_idempotent_and_independent_of_import_order(db, ingest, detect, alerts) -> None:
    import random
    bursts = [fails(6, start=k * 180) for k in range(4)]        # 4 bursts, 3 minutes apart
    lines = [line for burst in bursts for line in burst]
    random.Random(3).shuffle(lines)
    for i in range(0, len(lines), 5):                           # import in chunks, detect after each
        ingest("linux_auth", lines[i:i + 5])
        detect()
    (alert,) = alerts("SOC-001")
    assert alert["occurrence_count"] == 4 and alert["event_count"] == 24
    detect()
    detect()
    assert alerts("SOC-001")[0]["occurrence_count"] == 4
    evidence = json.loads(alerts("SOC-001")[0]["evidence"])
    assert len(evidence["occurrences"]) == 4 and "4 occurrences" in alerts("SOC-001")[0]["rationale"]


def test_dedup_summary_counts_raw_alerts_against_incidents(db, ingest, detect) -> None:
    scanner = "10.0.0.50"
    ingest("linux_auth", [line for k in range(4) for line in fails(6, start=k * 180)]          # 4 bursts, 1 IP
                         + fails(6, start=300, ip=scanner, host="srv20"))                      # 1 burst, scanner
    ingest("suricata", [s.suricata_flow(s.at(320 + i), scanner, 50000 + i, "10.0.0.20", 1000 + i, i) for i in range(20)]
                       + [s.suricata_alert(s.at(400 + i), "198.51.100.7", 1000 + i, "10.0.0.9", 80, "SIG noise", 3, 900 + i)
                          for i in range(10)])
    summary = detect()
    assert summary.raw_detections == 6
    with db.connection() as conn:
        dedup = Repository(conn).dedup_summary()
    assert (dedup.raw_detections, dedup.ids_alerts, dedup.alerts, dedup.incidents) == (6, 10, 3, 2)
    assert dedup.raw_alerts == 16 and dedup.reduction_percent == 87.5 and dedup.detections_per_incident == 3.0
    assert summary.dedup == dedup.to_dict()
    assert "16 raw alerts" in dedup.sentence() and "2 incidents" in dedup.sentence()


def test_dedup_summary_on_empty_database(db) -> None:
    with db.connection() as conn:
        dedup = Repository(conn).dedup_summary()
    assert dedup.raw_alerts == 0 and dedup.reduction_percent == 0.0 and dedup.detections_per_incident == 0.0


# ------------------------------------------------------------- assigned analyst
def test_assign_reassign_and_unassign_incident(db, ingest, detect) -> None:
    ingest("linux_auth", fails(6))
    detect()
    with db.transaction() as conn:
        manager = IncidentManager(conn)
        manager.assign(1, "  alice  ", "lead")
        with pytest.raises(IncidentError, match="already assigned to alice"):
            manager.assign(1, "alice")
        manager.assign(1, "bob", "lead")
        manager.assign(1, None, "lead")
        manager.assign(1, "x" * 500, "lead")
        with pytest.raises(IncidentError, match="not found"):
            manager.assign(99, "alice")
    with db.connection() as conn:
        repo = Repository(conn)
        incident = repo.get_incident(1)
        notes = [h["note"] for h in repo.incident_history(1)][1:]
        assert len(repo.list_incidents(analyst="x" * 100)) == 1 and repo.list_incidents(analyst="alice") == []
    assert incident["assigned_analyst"] == "x" * 100 and incident["status"] == "NEW"
    assert notes == ["Assigned to alice", "Assigned to bob (was alice)", "Unassigned (was bob)", "Assigned to " + "x" * 100]


def test_assigned_analyst_appears_in_report(db, ingest, detect) -> None:
    ingest("linux_auth", fails(6))
    detect()
    with db.transaction() as conn:
        IncidentManager(conn).assign(1, "alice")
    with db.connection() as conn:
        report = build_incident_report(conn, 1)
    assert "| Assigned analyst | alice |" in report and "| Status | New |" in report


def test_old_database_without_assigned_analyst_is_migrated(tmp_path) -> None:
    import sqlite3
    from storage.database import Database, DatabaseError
    path = tmp_path / "old.db"
    old_schema = Database(path)
    old_schema.init_schema()
    with old_schema.connection() as conn:                      # simulate a database from the previous version
        conn.execute("DROP INDEX idx_incidents_analyst")
        conn.execute("ALTER TABLE incidents DROP COLUMN assigned_analyst")
        conn.execute("INSERT INTO incidents (entity_key, title, description, severity, rule_id, first_seen, last_seen, "
                     "first_ts, last_ts, created_at, updated_at) VALUES ('e', 'kept', 'd', 3, 'r', 'a', 'b', 0, 0, 'c', 'd')")
    with pytest.raises(DatabaseError, match="out of date"):
        Database(path).check_schema()
    Database(path).init_schema()
    Database(path).check_schema()
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT title, assigned_analyst FROM incidents").fetchall() == [("kept", None)]
    conn.close()
