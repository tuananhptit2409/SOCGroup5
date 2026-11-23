"""Security tests: SQL injection, path traversal, input validation, secrets, log hygiene."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest

from config import PROJECT_ROOT
from datasets import synth as s
from engine.incident_manager import IncidentManager
from ingestors.base import InputPathError
from pipeline import ingest_file
from storage.database import REQUIRED_TABLES
from storage.repository import Repository
from ui import data_access

SOURCE_DIRS = ("ingestors", "normalizer", "storage", "engine", "ui", "datasets", "benchmarks", "config", "docs")


def project_files(suffixes: set[str], skip: tuple[str, ...] = ()) -> list[Path]:
    """Files of the project itself (never a virtualenv, cache or results folder inside it)."""
    files = [p for p in PROJECT_ROOT.iterdir() if p.is_file() and p.suffix in suffixes]
    for folder in SOURCE_DIRS:
        if folder in skip:
            continue
        files += [p for p in (PROJECT_ROOT / folder).rglob("*")
                  if p.is_file() and p.suffix in suffixes and "__pycache__" not in p.parts
                  and "results" not in p.parts]
    return sorted(files)


PAYLOADS = ["' OR '1'='1", "'; DROP TABLE events; --", "\" OR 1=1 --", "1; DELETE FROM incidents",
            "' UNION SELECT raw_line, 1 FROM raw_events --", "%", "_", "\\", "%' ESCAPE '\\"]


def tables(db) -> set[str]:
    with db.connection() as conn:
        return {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


# ------------------------------------------------------------- SQL injection
@pytest.mark.parametrize("payload", PAYLOADS)
def test_sql_payload_in_log_data_is_stored_as_text(db, ingest, detect, count, payload: str) -> None:
    lines = [s.linux_failed(s.at(i * 5), "web01", payload, "203.0.113.10", 40000 + i, 100 + i) for i in range(6)]
    lines.append(s.linux_accepted(s.at(60), "web01", "ops", "10.0.0.9", 50000))
    ingest("linux_auth", lines)
    ingest("suricata", [s.suricata_alert(s.at(0), "10.0.0.1", 1, "10.0.0.2", 80, payload, 1)])
    detect()
    assert set(REQUIRED_TABLES) <= tables(db)
    assert count("events") == 8 and count("alerts") == 1
    with db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events WHERE username = ?", (payload,)).fetchone()[0] == 6
        assert conn.execute("SELECT message FROM events WHERE action = 'ids_alert'").fetchone()[0] == payload


@pytest.mark.parametrize("payload", PAYLOADS)
def test_sql_payload_in_search_filters_cannot_change_the_query(db, ingest, count, payload: str) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(i), "web01", "root", "203.0.113.10", 40000 + i, i) for i in range(5)])
    with db.connection() as conn:
        repo = Repository(conn)
        assert repo.count_events(text=payload) == 0            # matched literally, never "everything"
        assert repo.count_events(ip=payload) == 0
        assert repo.count_events(source_type=payload) == 0
        assert repo.search_events(sort=payload, limit=3) != []  # unknown sort falls back to the default
        assert repo.list_incidents(status=payload, text=payload, src_ip=payload) == []
        assert repo.list_alerts(rule_id=payload, src_ip=payload) == []
    with pytest.raises(ValueError, match="not a valid IP"):
        data_access.search_events(db, ip=payload)
    frame, total = data_access.search_events(db, text=payload)
    assert total == 0 and frame.empty
    assert count("events") == 5 and set(REQUIRED_TABLES) <= tables(db)


def test_like_wildcards_are_literal(db, ingest) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(0), "web01", "100%_user", "10.0.0.1", 1, 1),
                          s.linux_failed(s.at(1), "web01", "plainuser", "10.0.0.1", 2, 2)])
    with db.connection() as conn:
        repo = Repository(conn)
        assert repo.count_events(text="%") == 1 and repo.count_events(text="_") == 1
        assert repo.count_events(text="user") == 2


def test_sql_payload_in_notes_and_status(db, ingest, detect, count) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)])
    detect()
    payload = "x'); DROP TABLE incident_notes; --"
    with db.transaction() as conn:
        manager = IncidentManager(conn)
        manager.add_note(1, payload, payload)
        manager.update_status(1, "IN_PROGRESS", payload, payload)
    assert set(REQUIRED_TABLES) <= tables(db) and count("incident_notes") == 1
    with db.connection() as conn:
        assert conn.execute("SELECT note FROM incident_notes").fetchone()[0] == payload


def test_no_string_built_sql_with_external_values() -> None:
    """Static check: f-string SQL may only interpolate whitelisted identifiers/placeholders."""
    allowed = {"where", "order", "marks", "columns", "assignments", "placeholders", "column", "table",
               "name_marks", "', '.join(_EVENT_COLUMNS)"}
    pattern = re.compile(r"f\"[^\"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\"", re.I)
    offenders = []
    for path in project_files({".py"}, skip=("benchmarks",)):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in pattern.finditer(line):
                for expr in re.findall(r"\{([^}]*)\}", match.group(0)):
                    if expr not in allowed:
                        offenders.append(f"{path.name}:{number}: {expr}")
        text = path.read_text(encoding="utf-8")
        assert ".format(" not in text or "execute" not in text, path
        assert not re.search(r"execute\w*\([^)]*%\s*\(", text), path
    assert offenders == []


def test_source_scans_ignore_a_virtualenv_inside_the_project(tmp_path, monkeypatch) -> None:
    """README tells users to create .venv inside the project; scans must not read it."""
    files = project_files({".py"})
    assert files and not any(part.startswith(".") or part in {"venv", "site-packages"}
                             for path in files for part in path.relative_to(PROJECT_ROOT).parts)


# ------------------------------------------------------------ path traversal
@pytest.mark.parametrize("target", ["../outside.log", "../../outside.log", "sub/../../outside.log"])
def test_ingest_rejects_traversal_outside_allowed_folder(db, settings, count, target: str) -> None:
    base = settings.allowed_input_dirs[0]
    (base / "sub").mkdir(exist_ok=True)
    (base.parent / "outside.log").write_text(s.linux_failed(s.at(0), "h", "root", "10.0.0.1", 22) + "\n")
    with pytest.raises(InputPathError, match="outside"):
        ingest_file(db, settings, "linux_auth", base / target)
    assert count("events") == 0 and count("raw_events") == 0


def test_ingest_rejects_absolute_system_paths_and_bad_names(db, settings, count) -> None:
    for target in ("/etc/passwd", "/etc/shadow", "C:\\Windows\\win.ini", str(Path(settings.db_path)),
                   "", "bad\x00name", "con", "a" * 5000):
        with pytest.raises(InputPathError):
            ingest_file(db, settings, "linux_auth", target)
    assert count("raw_events") == 0


def test_database_file_itself_cannot_be_ingested(db, settings, count) -> None:
    with pytest.raises(InputPathError, match="outside"):
        ingest_file(db, settings, "linux_auth", settings.db_path)


# ---------------------------------------------------------- input validation
def test_unexpected_field_types_are_rejected_with_reasons(ingest, count) -> None:
    bad = [
        json.dumps({"timestamp": "2026-11-13T10:00:00Z", "event_type": "flow", "src_ip": ["10.0.0.1"]}),
        json.dumps({"timestamp": "2026-11-13T10:00:00Z", "event_type": "flow", "src_port": {"a": 1}}),
        json.dumps({"timestamp": {"nested": True}, "event_type": "flow"}),
        json.dumps({"timestamp": "2026-11-13T10:00:00Z", "event_type": "alert", "alert": ["x"]}),
        json.dumps({"timestamp": "2026-11-13T10:00:00Z", "event_type": ["alert"]}),
        json.dumps({"timestamp": "2026-11-13T10:00:00Z", "event_type": "flow", "dest_port": -5}),
        "null", "true", "12", '"string"', "[]", "{}",
    ]
    result = ingest("suricata", bad)
    assert result.new_events == 0 and result.rejected == len(bad) and count("events") == 0
    assert set(result.reject_reasons) <= {"invalid_ip", "invalid_port", "invalid_timestamp", "not_a_json_object",
                                          "unexpected_field_type", "missing_required_field"}


def test_very_long_field_values_are_truncated_not_crashing(ingest, db, settings) -> None:
    long_cmd = "cmd.exe /c " + "A" * 30000
    result = ingest("sysmon", [s.sysmon_process(s.at(0), "WS01", "C:\\a.exe", long_cmd, None)])
    assert result.new_events == 1
    with db.connection() as conn:
        assert conn.execute("SELECT LENGTH(command_line) FROM events").fetchone()[0] == 8192


def test_control_characters_and_unicode_in_logs(ingest, count) -> None:
    lines = [s.linux_failed(s.at(0), "h", "ro\x1b[31mot", "10.0.0.1", 22, 1),
             s.linux_failed(s.at(1), "h", "người_dùng😀", "10.0.0.1", 23, 2)]
    assert ingest("linux_auth", lines).new_events == 2 and count("events") == 2


def test_incident_note_and_actor_lengths_are_bounded(db, ingest, detect) -> None:
    ingest("linux_auth", [s.linux_failed(s.at(i), "h", "root", "203.0.113.1", 22 + i, i) for i in range(6)])
    detect()
    with db.transaction() as conn:
        IncidentManager(conn).add_note(1, "N" * 100_000, "A" * 100_000)
    with db.connection() as conn:
        row = conn.execute("SELECT LENGTH(note), LENGTH(author) FROM incident_notes").fetchone()
    assert tuple(row) == (4000, 100)


# -------------------------------------------------------------------- secrets
def test_no_hardcoded_secrets_in_source() -> None:
    patterns = [
        re.compile(r"(password|passwd|secret|api[_-]?key|token)\s*=\s*[\"'][^\"']{4,}[\"']", re.I),
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"\b(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,})\b"),
        re.compile(r"[a-z]+://[^/\s:@]+:[^/\s:@]+@"),         # credentials inside a URL
    ]
    offenders = []
    for path in project_files({".py", ".json", ".sql", ".txt", ".ini", ".md"}, skip=("datasets",)):
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if any(p.search(line) for p in patterns):
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}:{number}")
    assert offenders == []


def test_logs_do_not_contain_raw_log_content(ingest, detect, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    marker = "SuperSecretUser123"
    lines = [s.linux_failed(s.at(i * 5), "web01", marker, "203.0.113.10", 40000 + i, 100 + i) for i in range(6)]
    ingest("linux_auth", lines + ["malformed line with " + marker])
    detect()
    assert caplog.records, "pipeline should log its progress"
    assert marker not in caplog.text
    assert "event=ingest_completed" in caplog.text and "event=detection_completed" in caplog.text
