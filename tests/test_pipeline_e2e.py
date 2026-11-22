"""End-to-end tests against the labelled synthetic dataset, idempotency and recovery."""
from __future__ import annotations

import json
import random
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from datasets import synth as s
from datasets.generate_dataset import build
from ingestors.base import InputPathError
from pipeline import PipelineError, ingest_file, run_detection
from storage.database import Database, DatabaseError
from storage.repository import Repository
from ui import data_access

SOURCE_OF = {"linux_auth.log": "linux_auth", "suricata_eve.jsonl": "suricata", "sysmon.jsonl": "sysmon",
             "web_access.log": "web_access"}


def load_dataset(db: Database, settings, shuffle_seed: int | None = None) -> dict:
    files, truth = build()
    settings = replace(settings, web_server_name=truth["web_server_name"])
    for name, lines in files.items():
        if shuffle_seed is not None:
            lines = list(lines)
            random.Random(shuffle_seed).shuffle(lines)
        path = settings.allowed_input_dirs[0] / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        ingest_file(db, settings, SOURCE_OF[name], path)
    return truth


def alert_rows(db: Database) -> list[dict]:
    with db.connection() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY rule_id, entity_key")]


def matches(alert: dict, entity: dict) -> bool:
    return bool(entity) and all(alert.get(key) == value for key, value in entity.items())


# ----------------------------------------------------------- ground truth e2e
def test_full_pipeline_matches_ground_truth(db, settings, count) -> None:
    truth = load_dataset(db, settings)
    summary = run_detection(db, settings)
    totals = truth["expected_totals"]
    assert count("raw_events") == totals["raw_events"]
    assert count("events") == totals["events"]
    with db.connection() as conn:
        counts = Repository(conn).counts()
        per_source = dict(conn.execute("SELECT source_type, COUNT(*) FROM events GROUP BY source_type").fetchall())
        rejected = dict(conn.execute("SELECT source_type, COUNT(*) FROM raw_events WHERE status = 'rejected' "
                                     "GROUP BY source_type").fetchall())
    assert counts["rejected_events"] == totals["rejected"]
    for name, info in truth["files"].items():
        assert per_source[SOURCE_OF[name]] == info["valid_events"]
        assert rejected[SOURCE_OF[name]] == info["rejected"]
    raw_per_rule: dict[str, int] = {rule: 0 for rule in summary.per_rule}
    for scenario in truth["scenarios"]:
        if scenario["expected_alert"]:
            rule = scenario["expected_rule_id"]
            raw_per_rule[rule] = raw_per_rule.get(rule, 0) + scenario["expected_occurrences"]
    assert summary.rule_errors == {} and summary.per_rule == raw_per_rule      # raw detections per rule
    assert sum(raw_per_rule.values()) == summary.raw_detections == totals["raw_detections"]
    assert count("alerts") == totals["alerts"] and count("incidents") == totals["incidents"]
    with db.connection() as conn:
        stored = dict(conn.execute("SELECT rule_id, COUNT(*) FROM alerts GROUP BY rule_id").fetchall())
    assert stored == totals["alerts_per_rule"]
    groups = {s["incident_group"] for s in truth["scenarios"] if s["expected_alert"]}
    assert len(groups) == totals["incidents"]
    assert summary.dedup["raw_alerts"] == totals["raw_alerts"]
    assert summary.dedup["incidents"] == totals["incidents"]

    alerts = alert_rows(db)
    for scenario in truth["scenarios"]:
        hits = [a for a in alerts if matches(a, scenario["entity"])]
        if scenario["expected_alert"]:
            # one entity can be hit by two rules (S01 SSH + S27 web from the same IP): match the rule too
            hits = [a for a in hits if a["rule_id"] == scenario["expected_rule_id"]]
            assert len(hits) == 1, scenario["scenario_id"]
            alert = hits[0]
            assert alert["rule_id"] == scenario["expected_rule_id"], scenario["scenario_id"]
            assert alert["severity"] == scenario["expected_severity"], scenario["scenario_id"]
            assert alert["event_count"] == scenario["input"]["events"], scenario["scenario_id"]
            assert alert["occurrence_count"] == scenario["expected_occurrences"], scenario["scenario_id"]
        else:
            assert hits == [], scenario["scenario_id"]


def test_alert_incident_relationships_and_evidence(db, settings, count) -> None:
    load_dataset(db, settings)
    run_detection(db, settings)
    with db.connection() as conn:
        # every alert belongs to exactly one incident, every incident has alerts and events
        assert conn.execute("SELECT COUNT(*) FROM alerts a LEFT JOIN incident_alerts ia ON ia.alert_id = "
                            "a.alert_id WHERE ia.incident_id IS NULL").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM incident_alerts ia "
                            "WHERE ia.incident_id = i.incident_id)").fetchone()[0] == 0
        # stored counters equal the real number of evidence links
        assert conn.execute("SELECT COUNT(*) FROM alerts a WHERE a.event_count <> (SELECT COUNT(*) FROM "
                            "alert_events ae WHERE ae.alert_id = a.alert_id)").fetchone()[0] == 0
        # incident evidence is the union of its alerts' evidence
        assert conn.execute(
            "SELECT COUNT(*) FROM incident_alerts ia JOIN alert_events ae ON ae.alert_id = ia.alert_id "
            "WHERE NOT EXISTS (SELECT 1 FROM incident_events ie WHERE ie.incident_id = ia.incident_id "
            "AND ie.event_id = ae.event_id)").fetchone()[0] == 0
        # evidence events carry the original raw line
        row = conn.execute("SELECT r.raw_line FROM alerts a JOIN alert_events ae ON ae.alert_id = a.alert_id "
                           "JOIN raw_events r ON r.raw_id = ae.event_id WHERE a.rule_id = 'SOC-001' "
                           "AND a.src_ip = '203.0.113.10' LIMIT 1").fetchone()
        assert "Failed password for root from 203.0.113.10" in row["raw_line"]
        roles = {r[0] for r in conn.execute("SELECT DISTINCT role FROM alert_events")}
    assert {"failed_login", "successful_login_after_failures", "account_lockout", "scan_connection",
            "process_creation", "suricata_alert", "sysmon_internal_connection"} <= roles
    assert db.integrity_report()["foreign_key_violations"] == []


def test_dashboard_data_reflects_database(db, settings, count) -> None:
    truth = load_dataset(db, settings)
    run_detection(db, settings)
    overview = data_access.overview(db)
    assert overview["counts"]["events"] == count("events") == truth["expected_totals"]["events"]
    assert overview["counts"]["alerts"] == count("alerts")
    assert overview["counts"]["active_incidents"] == count("incidents")
    assert int(overview["events_by_source"]["count"].sum()) == count("events")
    assert int(overview["event_timeline"]["count"].sum()) == count("events")
    assert int(overview["alerts_by_severity"]["count"].sum()) == count("alerts")
    assert int(overview["incident_timeline"]["count"].sum()) == count("incidents")
    assert len(data_access.list_alerts(db)) == count("alerts")
    assert len(data_access.list_incidents(db)) == count("incidents")


# ------------------------------------------------------------------ idempotency
def test_importing_same_files_twice_adds_nothing(db, settings, count) -> None:
    load_dataset(db, settings)
    run_detection(db, settings)
    before = {t: count(t) for t in ("raw_events", "events", "alerts", "alert_events", "incidents",
                                    "incident_events", "incident_alerts", "incident_history")}
    files, _truth = build()
    for name in files:
        result = ingest_file(db, settings, SOURCE_OF[name], settings.allowed_input_dirs[0] / name)
        assert result.new_events == 0 and result.new_rejected == 0
        assert result.duplicates == result.total_lines - result.blank_lines
    summary = run_detection(db, settings)
    assert (summary.alerts_new, summary.alerts_updated, summary.incidents_created) == (0, 0, 0)
    assert {t: count(t) for t in before} == before
    assert count("import_batches") == 2 * len(files)      # each import is still recorded as its own batch
    with db.connection() as conn:
        dup = conn.execute("SELECT SUM(duplicates), SUM(new_events) FROM import_batches WHERE batch_id > ?",
                           (len(files),)).fetchone()
    assert dup[0] == before["raw_events"] and dup[1] == 0


def test_out_of_order_ingestion_gives_identical_detections(tmp_path, settings) -> None:
    def run(seed: int | None, name: str) -> list[tuple]:
        custom = replace(settings, db_path=tmp_path / name)
        database = Database(custom.db_path)
        database.init_schema()
        load_dataset(database, custom, seed)
        run_detection(database, custom)
        with database.connection() as conn:
            alerts = [(r["rule_id"], r["entity_key"], r["severity"], r["first_seen"], r["last_seen"],
                       r["event_count"], r["fingerprint"]) for r in
                      conn.execute("SELECT * FROM alerts ORDER BY rule_id, entity_key")]
            incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        return alerts + [("incidents", incidents)]

    ordered = run(None, "ordered.db")
    assert run(7, "shuffled7.db") == ordered
    assert run(99, "shuffled99.db") == ordered


def test_incremental_ingestion_in_chunks_matches_single_run(db, settings, count) -> None:
    files, truth = build()
    for name, lines in files.items():
        for i in range(0, len(lines), 97):
            path = settings.allowed_input_dirs[0] / f"{i}_{name}"
            path.write_text("\n".join(lines[i:i + 97]) + "\n", encoding="utf-8")
            ingest_file(db, settings, SOURCE_OF[name], path)
            run_detection(db, settings)             # detection after every chunk
    totals = truth["expected_totals"]
    assert count("events") == totals["events"]
    assert count("alerts") == totals["alerts"] and count("incidents") == totals["incidents"]
    severities = sorted(a["severity"] for a in alert_rows(db))
    assert severities == sorted(sc["expected_severity"] for sc in truth["scenarios"] if sc["expected_alert"])


# ---------------------------------------------------------- ingestion edge cases
def test_empty_file_and_blank_lines(ingest, count) -> None:
    result = ingest("linux_auth", [])
    assert (result.total_lines, result.new_events, result.rejected) in {(0, 0, 0), (1, 0, 0)}
    result = ingest("linux_auth", ["", "   ", s.linux_failed(s.at(0), "h", "root", "10.0.0.1", 22), ""])
    assert result.new_events == 1 and result.blank_lines >= 3 and result.rejected == 0
    assert count("events") == 1


def test_malformed_lines_do_not_stop_the_pipeline(ingest, count, db) -> None:
    good = [s.linux_failed(s.at(i), "h", "root", "10.0.0.1", 22 + i, i) for i in range(3)]
    result = ingest("linux_auth", [good[0], "garbage line", good[1], "\x00\x01\x02", good[2]])
    assert result.new_events == 3 and result.rejected == 2 and result.reject_reasons == {"malformed_syslog_line": 2}
    with db.connection() as conn:
        rows = conn.execute("SELECT line_no, error, status FROM raw_events WHERE status = 'rejected' "
                            "ORDER BY line_no").fetchall()
    assert [(r["line_no"], r["error"]) for r in rows] == [(2, "malformed_syslog_line"), (4, "malformed_syslog_line")]


def test_oversized_line_is_rejected_and_truncated(ingest, db, settings) -> None:
    huge = json.dumps({"timestamp": "2026-11-13T10:00:00Z", "event_type": "http", "http": {"url": "A" * 300_000}})
    ok = s.suricata_flow(s.at(0), "10.0.0.1", 1, "10.0.0.2", 80)
    result = ingest("suricata", [ok, huge, ok.replace('"flow_id": 1', '"flow_id": 2')])
    assert result.new_events == 2 and result.reject_reasons == {"line_too_long": 1}
    with db.connection() as conn:
        stored = conn.execute("SELECT LENGTH(raw_line) FROM raw_events WHERE status = 'rejected'").fetchone()[0]
    assert stored <= 4096 < settings.max_line_length


def test_wrong_source_type_for_file_rejects_lines_without_crashing(ingest, count) -> None:
    result = ingest("sysmon", [s.linux_failed(s.at(0), "h", "root", "10.0.0.1", 22)])
    assert result.new_events == 0 and result.reject_reasons == {"malformed_json": 1} and count("events") == 0


def test_unknown_source_type_and_missing_file(db, settings) -> None:
    with pytest.raises(PipelineError, match="unknown source type"):
        ingest_file(db, settings, "firewall", settings.allowed_input_dirs[0] / "x.log")
    with pytest.raises(InputPathError, match="not found"):
        ingest_file(db, settings, "linux_auth", settings.allowed_input_dirs[0] / "missing.log")
    with db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM import_batches").fetchone()[0] == 0


def test_batches_are_recorded_with_counts(ingest, db) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(0), "h", "root", "10.0.0.1", 22), "bad", ""], name="a.log")
    with db.connection() as conn:
        batch = dict(conn.execute("SELECT * FROM import_batches").fetchone())
    assert batch["status"] == "completed" and batch["finished_at"]
    assert (batch["new_events"], batch["new_rejected"], batch["duplicates"]) == (1, 1, 0)
    assert batch["file_path"].endswith("a.log")


def test_many_small_batches(db, settings, count) -> None:
    custom = replace(settings, batch_size=7)
    path = settings.allowed_input_dirs[0] / "many.log"
    path.write_text("\n".join(s.linux_failed(s.at(i * 100), "h", "root", "10.0.0.1", 1000 + i, i)
                              for i in range(100)) + "\n")
    assert ingest_file(db, custom, "linux_auth", path).new_events == 100 and count("events") == 100


def test_line_rejected_under_one_config_can_be_accepted_later(db, settings, count) -> None:
    path = settings.allowed_input_dirs[0] / "leap.log"
    path.write_text("Feb 29 10:00:00 h sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n")
    assert ingest_file(db, replace(settings, syslog_default_year=2026), "linux_auth", path).rejected == 1
    result = ingest_file(db, replace(settings, syslog_default_year=2028), "linux_auth", path)
    assert result.new_events == 1 and result.new_rejected == 0 and count("events") == 1
    with db.connection() as conn:
        assert conn.execute("SELECT status, error FROM raw_events").fetchone()[:] == ("accepted", None)


# --------------------------------------------------------------------- recovery
def test_locked_database_gives_clear_error_and_recovers(settings, db, count) -> None:
    path = settings.allowed_input_dirs[0] / "a.log"
    path.write_text("\n".join(s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)) + "\n")
    impatient = Database(settings.db_path, busy_timeout_ms=100)
    blocker = sqlite3.connect(settings.db_path, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(DatabaseError, match="busy or locked"):
            ingest_file(impatient, settings, "linux_auth", path)
        with pytest.raises(DatabaseError, match="busy or locked"):
            run_detection(impatient, settings)
        with impatient.connection() as conn:          # readers still work while a writer holds the lock (WAL)
            assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    assert ingest_file(impatient, settings, "linux_auth", path).new_events == 6
    assert run_detection(impatient, settings).alerts_new == 1
    assert db.integrity_report()["integrity_check"] == ["ok"] and count("incidents") == 1


def test_failure_in_the_middle_of_ingestion_keeps_database_consistent(db, settings, count, monkeypatch) -> None:
    custom = replace(settings, batch_size=10)
    path = settings.allowed_input_dirs[0] / "a.log"
    path.write_text("\n".join(s.linux_failed(s.at(i * 100), "h", "root", "10.0.0.1", 1000 + i, i)
                              for i in range(35)) + "\n")
    original = Repository.insert_events
    calls = {"n": 0}

    def flaky(self, events):
        calls["n"] += 1
        if calls["n"] == 3:
            raise sqlite3.OperationalError("simulated disk I/O error")
        return original(self, events)

    monkeypatch.setattr(Repository, "insert_events", flaky)
    with pytest.raises(sqlite3.OperationalError, match="simulated"):
        ingest_file(db, custom, "linux_auth", path)
    # the failing batch was rolled back as a whole: no raw line without its event
    assert count("events") == 20 and count("raw_events") == 20
    with db.connection() as conn:
        assert conn.execute("SELECT status FROM import_batches").fetchone()[0] == "failed"
    monkeypatch.setattr(Repository, "insert_events", original)
    result = ingest_file(db, custom, "linux_auth", path)        # retry after the fault is gone
    assert (result.new_events, result.duplicates) == (15, 20) and count("events") == 35
    assert db.integrity_report() == {"integrity_check": ["ok"], "foreign_key_violations": [], "journal_mode": "wal"}


def test_failing_rule_does_not_block_other_rules_or_corrupt_state(db, settings, ingest, count, monkeypatch) -> None:
    from engine.rules.port_scan import PortScanRule
    ingest("linux_auth", [s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)])

    def broken(self, conn):
        raise RuntimeError("rule bug")
        yield  # pragma: no cover

    monkeypatch.setattr(PortScanRule, "detect", broken)
    summary = run_detection(db, settings)
    assert "SOC-002" in summary.rule_errors and "rule bug" in summary.rule_errors["SOC-002"]
    assert summary.per_rule["SOC-001"] == 1 and count("alerts") == 1


def test_detection_failure_rolls_back_everything(db, settings, ingest, count, monkeypatch) -> None:
    from engine.incident_manager import IncidentManager
    ingest("linux_auth", [s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)])
    monkeypatch.setattr(IncidentManager, "sync_alert", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("crash")))
    with pytest.raises(RuntimeError, match="crash"):
        run_detection(db, settings)
    assert count("alerts") == 0 and count("alert_events") == 0 and count("incidents") == 0


def test_restart_persistence_of_incident_state(settings, db, ingest, detect, count) -> None:
    from engine.incident_manager import IncidentManager
    ingest("linux_auth", [s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)])
    detect()
    with db.transaction() as conn:
        IncidentManager(conn).update_status(1, "IN_PROGRESS", "alice", "working on it")
        IncidentManager(conn).add_note(1, "note survives restart", "alice")
    del db
    fresh = Database(Path(settings.db_path))          # new process would do exactly this
    fresh.check_schema()
    detail = data_access.incident_detail(fresh, settings, 1)
    assert detail["incident"]["status"] == "IN_PROGRESS"
    assert detail["notes"]["note"].tolist() == ["note survives restart"]
    assert len(detail["events"]) == 6 and len(detail["history"]) == 2
    assert run_detection(fresh, settings).incidents_created == 0


# ------------------------------------------------------------- watch (giám sát liên tục)
def test_watch_files_picks_up_new_lines_and_survives_missing_file(db, settings) -> None:
    from pipeline import watch_files
    log = settings.allowed_input_dirs[0] / "auth.log"
    log.write_text(s.linux_failed(s.at(0), "web01", "root", "203.0.113.70", 40000, 1) + "\n", encoding="utf-8")
    missing = settings.allowed_input_dirs[0] / "eve.json"                      # not created yet
    reports, appended = [], []

    def fake_sleep(_seconds: float) -> None:      # between two rounds the attacker keeps trying
        if not appended:
            more = [s.linux_failed(s.at(5 + i * 5), "web01", "root", "203.0.113.70", 40001 + i, 2 + i)
                    for i in range(5)]
            with log.open("a", encoding="utf-8") as handle:
                handle.write("\n".join(more) + "\n")
            appended.append(True)

    rounds = watch_files(db, settings, [("linux_auth", log), ("suricata", missing)], interval=1, cycles=3,
                         report=reports.append, sleep=fake_sleep)
    assert rounds == 3
    assert reports[0]["new_events"] == 1 and "alerts_new" in reports[0] and reports[0]["alerts_new"] == 0
    assert reports[1]["new_events"] == 5 and reports[1]["alerts_new"] == 1          # threshold reached
    assert reports[2]["new_events"] == 0 and "alerts_new" not in reports[2]         # nothing new: no detection
    assert all("input file not found" in r["errors"][0] for r in reports)          # missing file never fatal


def test_watch_reads_only_appended_bytes_waits_for_partial_line_and_handles_rotation(db, settings) -> None:
    from pipeline import watch_files
    log = settings.allowed_input_dirs[0] / "auth.log"
    first = s.linux_failed(s.at(0), "web01", "root", "203.0.113.72", 40000, 1)
    second = s.linux_failed(s.at(5), "web01", "root", "203.0.113.72", 40001, 2)
    log.write_text(first + "\n" + second[:30], encoding="utf-8")              # second line half written
    def finish_line() -> None:                                                # writer finishes the line
        with log.open("a", encoding="utf-8") as handle:
            handle.write(second[30:] + "\n")

    steps = iter([
        finish_line,
        lambda: log.write_text(s.linux_failed(s.at(9), "web01", "root", "203.0.113.72", 40002, 3) + "\n",
                               encoding="utf-8"),                              # logrotate: new, shorter file
    ])
    reports = []
    watch_files(db, settings, [("linux_auth", log)], interval=1, cycles=3, report=reports.append,
                sleep=lambda _s: next(steps)())
    assert [r["new_events"] for r in reports] == [1, 1, 1]
    with db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM raw_events WHERE status = 'rejected'").fetchone()[0] == 0
        lines = [r[0] for r in conn.execute("SELECT raw_line FROM raw_events ORDER BY rowid")]
    assert lines[1] == second                                                  # never stored half a line
