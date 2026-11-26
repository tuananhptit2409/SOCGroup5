"""Regression tests for defects found during the stability audit (see docs/BUG_FIX_LOG.md)."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone

import pytest

from config import PROJECT_ROOT
from datasets import synth as s
from ingestors import linux_auth
from normalizer import linux_normalizer
from normalizer.models import NormalizationError, NormalizeContext, normalize_ip
from storage.database import Database


# BUG-008: 29 February lines were rejected when the year was inferred in a non-leap year
@pytest.mark.parametrize("now,expected", [
    (datetime(2029, 3, 10, tzinfo=timezone.utc), "2028-02-29T10:00:00Z"),
    (datetime(2028, 3, 1, tzinfo=timezone.utc), "2028-02-29T10:00:00Z"),
    (datetime(2031, 1, 2, tzinfo=timezone.utc), "2028-02-29T10:00:00Z"),
])
def test_feb_29_year_is_inferred_from_last_leap_year(now: datetime, expected: str) -> None:
    line = "Feb 29 10:00:00 h sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"
    event = linux_normalizer.normalize(linux_auth.parse_line(line), line, "x", NormalizeContext(now=now))
    assert event.timestamp_utc == expected


def test_feb_29_with_configured_non_leap_year_is_still_rejected() -> None:
    line = "Feb 29 10:00:00 h sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"
    ctx = NormalizeContext(now=datetime(2026, 3, 1, tzinfo=timezone.utc), syslog_default_year=2026)
    with pytest.raises(NormalizationError, match="invalid_timestamp"):
        linux_normalizer.normalize(linux_auth.parse_line(line), line, "x", ctx)


def test_impossible_date_is_rejected_when_year_is_inferred() -> None:
    line = "Nov 31 10:00:00 h sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2"
    with pytest.raises(NormalizationError, match="invalid_timestamp"):
        linux_normalizer.normalize(linux_auth.parse_line(line), line, "x",
                                   NormalizeContext(now=datetime(2026, 12, 5, tzinfo=timezone.utc)))


# BUG-009: IPv4-mapped IPv6 addresses never correlated with plain IPv4 addresses
def test_ipv4_mapped_ipv6_is_normalized_to_ipv4() -> None:
    assert normalize_ip("::ffff:10.0.0.30") == "10.0.0.30"
    assert normalize_ip("::FFFF:203.0.113.99") == "203.0.113.99"
    assert normalize_ip("2001:db8::1") == "2001:db8::1"


def test_pivot_matches_when_sysmon_logs_ipv4_mapped_addresses(ingest, detect, alerts) -> None:
    ingest("suricata", [s.suricata_alert(s.at(0), "203.0.113.99", 51515, "10.0.0.30", 445, "SIG", 1)])
    ingest("sysmon", [s.sysmon_network(s.at(5), "WS02", "rundll32.exe", "::ffff:10.0.0.30", 49000,
                                       "::ffff:10.0.0.40", 445, initiated=True)])
    detect()
    assert len(alerts("SOC-004")) == 1


# BUG-007: dashboard width keyword was chosen from a guessed Streamlit version
def test_full_width_keyword_is_chosen_from_signature(monkeypatch) -> None:
    import types
    fake = types.ModuleType("streamlit")
    fake.dataframe = lambda data=None, width=None, height=None, *, use_container_width=False: None
    fake.plotly_chart = lambda fig, use_container_width=False, *, width="stretch": None
    for name in ("set_page_config", "title", "error", "info", "stop", "selectbox", "sidebar"):
        setattr(fake, name, None)
    monkeypatch.setitem(sys.modules, "streamlit", fake)
    monkeypatch.delitem(sys.modules, "ui.common", raising=False)
    import ui.common as common
    assert common.TABLE == {"use_container_width": True}      # old API: width is an int / None
    assert common.CHART == {"width": "stretch"}                # new API: width is a string
    assert common.full_width(lambda x: None) == {"use_container_width": True}
    assert common.full_width(len) == {"use_container_width": True}   # builtin without a signature
    monkeypatch.delitem(sys.modules, "ui.common", raising=False)


# Multi-process write contention (audit recovery test)
_WORKER = r"""
import sys, json
sys.path.insert(0, sys.argv[1])
from dataclasses import replace
from pathlib import Path
from config import Settings
from pipeline import ingest_file, run_detection
db_path, folder, action = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
settings = replace(Settings(), db_path=db_path, allowed_input_dirs=(folder,), syslog_default_year=2026, batch_size=500)
from storage.database import Database
db = Database(db_path)
out = []
if action == "detect":
    for _ in range(5):
        out.append(run_detection(db, settings).detections)
else:
    out.append(ingest_file(db, settings, "linux_auth", folder / action).new_events)
print(json.dumps(out))
"""


def test_concurrent_processes_writing_the_same_database(tmp_path) -> None:
    folder = tmp_path / "in"
    folder.mkdir()
    db_path = tmp_path / "shared.db"
    Database(db_path).init_schema()
    for name, ip in (("a.log", "203.0.113.1"), ("b.log", "203.0.113.2")):
        lines = [s.linux_failed(s.at(i * 2), f"host-{name}", "root", ip, 1000 + i % 60000, i) for i in range(6000)]
        (folder / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    script = tmp_path / "worker.py"
    script.write_text(_WORKER, encoding="utf-8")
    procs = [subprocess.Popen([sys.executable, str(script), str(PROJECT_ROOT), str(db_path), str(folder), action],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
             for action in ("a.log", "b.log", "detect")]
    results = [p.communicate(timeout=300) for p in procs]
    for proc, (out, err) in zip(procs, results):
        assert proc.returncode == 0, err[-1500:]
    assert json.loads(results[0][0]) == [6000] and json.loads(results[1][0]) == [6000]
    db = Database(db_path)
    with db.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 12000
        assert conn.execute("SELECT status, COUNT(*) FROM import_batches GROUP BY status").fetchall()[0][:] == ("completed", 2)
    assert db.integrity_report()["integrity_check"] == ["ok"]


def test_dashboard_pages_only_use_width_keywords_from_common() -> None:
    for page in [PROJECT_ROOT / "ui" / "dashboard.py", *(PROJECT_ROOT / "ui" / "pages").glob("*.py")]:
        text = page.read_text(encoding="utf-8")
        assert "use_container_width" not in text and 'width="stretch"' not in text, page.name


# AUD-06: the dashboard (no authentication) listened on every network interface
def test_dashboard_command_binds_to_localhost(monkeypatch) -> None:
    import importlib.util as iu
    import main as cli
    monkeypatch.setattr(iu, "find_spec", lambda name, *a: object())   # pretend the dashboard packages exist
    calls = []
    monkeypatch.setattr(cli.subprocess, "call", lambda cmd, **kw: calls.append((cmd, kw)) or 0)
    assert cli.main(["dashboard"]) == 0
    (command, kwargs), = calls
    assert command[command.index("--server.address") + 1] == "127.0.0.1"
    assert kwargs["cwd"] == str(PROJECT_ROOT)


def test_project_streamlit_config_binds_to_localhost() -> None:
    import tomllib
    config = tomllib.loads((PROJECT_ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8"))
    assert config["server"]["address"] == "127.0.0.1"


# AUD-08: one Sysmon line with "EventID": Infinity aborted the whole import (found by fuzzing)
INF_LINE = '{"EventID": Infinity, "UtcTime": "2026-11-13 02:00:00.000", "Image": "C:\\\\a.exe"}'


@pytest.mark.parametrize("line", [INF_LINE, INF_LINE.replace("Infinity", "-Infinity"), INF_LINE.replace("Infinity", "NaN"),
                                  '{"EventID": 1, "UtcTime": NaN, "Image": "C:\\\\a.exe"}'])
def test_sysmon_non_standard_json_constants_are_rejected(line: str) -> None:
    from ingestors import sysmon
    from ingestors.base import ParseError
    with pytest.raises(ParseError, match="malformed_json"):
        sysmon.parse_line(line)


def test_suricata_non_standard_json_constants_are_rejected() -> None:
    from ingestors import suricata
    from ingestors.base import ParseError
    with pytest.raises(ParseError, match="non-standard JSON constant"):
        suricata.parse_line('{"timestamp": "2026-11-13T10:00:00Z", "event_type": "flow", "dest_port": Infinity}')


def test_sysmon_huge_event_id_is_rejected_not_crashing() -> None:
    from ingestors import sysmon
    from ingestors.base import ParseError
    with pytest.raises(ParseError, match="unexpected_field_type"):
        sysmon.parse_line('{"EventID": 1e400, "Image": "a"}')        # 1e400 parses as float inf


def test_one_bad_line_does_not_stop_the_import(ingest, count) -> None:
    good = [s.sysmon_process(s.at(i), "WS01", rf"C:\Windows\Temp\x{i}.exe", "x.exe", None, pid=i) for i in range(6)]
    result = ingest("sysmon", good[:2] + [INF_LINE] + good[2:])
    assert result.new_events == 6 and result.rejected == 1 and count("events") == 6
    assert result.reject_reasons == {"malformed_json": 1}


def test_unexpected_parser_exception_rejects_only_that_line(ingest, count, db, monkeypatch, caplog) -> None:
    import pipeline
    real_parse, real_norm = pipeline.SOURCES["sysmon"]

    def flaky(line: str):
        if "boom" in line:
            raise RuntimeError("simulated parser bug")
        return real_parse(line)

    monkeypatch.setitem(pipeline.SOURCES, "sysmon", (flaky, real_norm))
    good = [s.sysmon_process(s.at(i), "WS01", rf"C:\Windows\Temp\y{i}.exe", "y.exe", None, pid=i) for i in range(4)]
    result = ingest("sysmon", good[:2] + ['{"boom": 1}'] + good[2:])
    assert result.new_events == 4 and result.reject_reasons == {"unexpected_error": 1}
    with db.connection() as conn:
        assert conn.execute("SELECT error FROM raw_events WHERE status = 'rejected'").fetchone()[0] == \
            "unexpected_error: RuntimeError"
        assert conn.execute("SELECT status FROM import_batches").fetchone()[0] == "completed"
    assert "event=unexpected_parse_error" in caplog.text and "boom" not in caplog.text


def test_unexpected_normalizer_exception_rejects_only_that_line(ingest, monkeypatch) -> None:
    import pipeline
    real_parse, real_norm = pipeline.SOURCES["sysmon"]

    def flaky_norm(parsed, line, event_id, ctx):
        if "z2.exe" in line:
            raise KeyError("simulated normalizer bug")
        return real_norm(parsed, line, event_id, ctx)

    monkeypatch.setitem(pipeline.SOURCES, "sysmon", (real_parse, flaky_norm))
    lines = [s.sysmon_process(s.at(i), "WS01", rf"C:\Windows\Temp\z{i}.exe", "z.exe", None, pid=i) for i in range(4)]
    result = ingest("sysmon", lines)
    assert result.new_events == 3 and result.reject_reasons == {"unexpected_error": 1}


# AUD-09: an escaped lone surrogate ("\ud800") in a JSON log aborted the whole import at the DB insert
SURROGATE_CASES = {
    "suricata": [r'{"timestamp": "2026-11-13T10:00:00Z", "event_type": "flow", "src_ip": "\ud800"}',
                 r'{"timestamp": "2026-11-13T10:00:00Z", "event_type": "\udc01"}',
                 r'{"timestamp": "2026-11-13T10:00:00Z", "event_type": "alert", "host": "s\ud800", '
                 r'"alert": {"signature": "SIG \udfff"}}'],
    "sysmon": [r'{"EventID": 1, "UtcTime": "2026-11-13 10:00:00.000", "Image": "C:\\Users\\a\\x\ud800.exe", '
               r'"Computer": "WS\udc00"}',
               r'{"EventID": 3, "UtcTime": "2026-11-13 10:00:01.000", "Image": "a.exe", "SourceIp": "\ud800"}'],
}


@pytest.mark.parametrize("source", sorted(SURROGATE_CASES))
def test_lone_surrogates_do_not_stop_the_import(ingest, db, source: str) -> None:
    good = ([s.suricata_flow(s.at(i), "10.0.0.1", 1000 + i, "10.0.0.2", 80, i) for i in range(3)] if source == "suricata"
            else [s.sysmon_process(s.at(i), "WS01", rf"C:\a{i}.exe", "a.exe", None, pid=i) for i in range(3)])
    result = ingest(source, good[:1] + SURROGATE_CASES[source] + good[1:])
    assert result.new_events + result.rejected == 3 + len(SURROGATE_CASES[source])
    assert result.new_events >= 4
    with db.connection() as conn:
        assert conn.execute("SELECT status FROM import_batches").fetchone()[0] == "completed"
        texts = [v for row in conn.execute("SELECT hostname, process_path, message, event_id FROM events") for v in row if v]
        texts += [r[0] for r in conn.execute("SELECT error FROM raw_events WHERE error IS NOT NULL")]
        raws = [r[0] for r in conn.execute("SELECT raw_line FROM raw_events")]
    assert all(not any(0xD800 <= ord(ch) <= 0xDFFF for ch in t) for t in texts)
    assert any("\\ud800" in r or "\\udc00" in r or "\\udc01" in r for r in raws)   # evidence keeps the original escape
    assert db.integrity_report()["integrity_check"] == ["ok"]


def test_valid_surrogate_pairs_are_kept() -> None:
    from ingestors.base import load_json_line
    assert load_json_line(r'{"u": "\ud83d\ude00 ok"}') == {"u": "\U0001F600 ok"}
    assert load_json_line(r'{"u": "a\ud800b"}') == {"u": "a\ufffdb"}


# AUD-07: `main.py dashboard` without Streamlit only showed "No module named streamlit"
def test_dashboard_command_explains_missing_packages(monkeypatch, capsys) -> None:
    import importlib.util as iu
    import main as cli
    real = iu.find_spec
    monkeypatch.setattr(iu, "find_spec", lambda name, *a: None if name in ("streamlit", "plotly") else real(name, *a))
    called = []
    monkeypatch.setattr(cli.subprocess, "call", lambda *a, **k: called.append(a) or 0)
    assert cli.main(["dashboard"]) == 2
    err = capsys.readouterr().err
    assert "streamlit, plotly" in err and "pip install -r requirements.txt" in err and called == []


# Small fuzz run on every test run (the full tool is benchmarks/fuzz_test.py)
def test_fuzz_smoke_parsers_never_crash_and_imports_complete() -> None:
    from benchmarks import fuzz_test as fuzz
    from benchmarks.fuzz_test import pipeline_fuzz, unit_fuzz
    unit = unit_fuzz(3000, seed=11)
    assert unit["crash_count"] == 0, unit["crashes"][:3]
    assert unit["slow_calls"] == []
    pipe = pipeline_fuzz(1500, seed=11)
    assert pipe["batches"] == {"completed": len(fuzz.SOURCES)} and pipe["unexpected_errors"] == 0
    assert pipe["rule_errors"] == {} and pipe["integrity"] == ["ok"] and pipe["foreign_key_violations"] == 0
