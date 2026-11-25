"""Dashboard tests.

Three levels:
  1. ui.data_access (the real queries behind every page) - always runs.
  2. Page scripts executed against a minimal Streamlit/Plotly stand-in - always
     runs; it exercises the page logic and error handling, NOT real rendering.
  3. Streamlit's own AppTest harness - runs only when streamlit and plotly are
     installed (skipped otherwise).
"""
from __future__ import annotations

import runpy
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

from config import PROJECT_ROOT
from engine.incident_manager import IncidentError
from datasets import synth as s
from pipeline import run_detection
from storage.database import Database, DatabaseError
from tests.test_pipeline_e2e import load_dataset
from ui import data_access

PAGES = [PROJECT_ROOT / "ui" / "dashboard.py", *sorted((PROJECT_ROOT / "ui" / "pages").glob("*.py"))]


@pytest.fixture
def populated(db, settings):
    load_dataset(db, settings)
    run_detection(db, settings)
    return db


# ------------------------------------------------------- 1. data access layer
def test_overview_on_empty_database(db) -> None:
    data = data_access.overview(db)
    assert data["counts"]["events"] == 0 and data["counts"]["alerts"] == 0
    for key in ("alerts_by_severity", "events_by_source", "top_source_ips", "top_target_hosts",
                "event_timeline", "incident_timeline"):
        assert data[key].empty


def test_lists_on_empty_database(db, settings) -> None:
    frame, total = data_access.search_events(db)
    assert frame.empty and total == 0 and list(frame.columns) == data_access.EVENT_COLUMNS
    assert data_access.list_alerts(db).empty and data_access.list_incidents(db).empty
    assert data_access.source_types(db) == []
    assert data_access.event_detail(db, "x") is None and data_access.alert_detail(db, 1) is None


def test_missing_or_broken_database_raises_clear_error(tmp_path, settings) -> None:
    from dataclasses import replace
    with pytest.raises(DatabaseError, match="not found"):
        data_access.get_database(replace(settings, db_path=tmp_path / "missing.db"))
    broken = tmp_path / "broken.db"
    broken.write_bytes(b"garbage" * 500)
    with pytest.raises(DatabaseError):
        data_access.get_database(replace(settings, db_path=broken))


def test_overview_with_data(populated) -> None:
    data = data_access.overview(populated)
    assert data["counts"]["events"] == 1212 and data["counts"]["alerts"] == 14
    assert set(data["events_by_source"]["source_type"]) == {"linux_auth", "suricata", "sysmon", "web_access"}
    assert len(data["top_source_ips"]) == 10 and data["top_source_ips"]["count"].is_monotonic_decreasing
    assert set(data["alerts_by_severity"]["label"]) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert data["event_timeline"]["time"].is_monotonic_increasing


def test_event_search_filters_and_pagination(populated) -> None:
    frame, total = data_access.search_events(populated, ip="203.0.113.10", source_type="linux_auth")
    assert total == 6 and set(frame["action"]) == {"failed_login"}
    frame, total = data_access.search_events(populated, source_type="sysmon", page_size=50)
    assert total == 280 and len(frame) == 50 and set(frame["source_type"]) == {"sysmon"}
    _f, high = data_access.search_events(populated, min_severity=4)
    assert high == 2                                           # HIGH-or-above Suricata alerts
    start = datetime(2026, 11, 13, 2, 10, tzinfo=timezone.utc)
    end = datetime(2026, 11, 13, 2, 11, tzinfo=timezone.utc)
    frame, total = data_access.search_events(populated, start=start, end=end, ip="203.0.113.10",
                                             source_type="linux_auth")
    assert total == 6
    frame, total = data_access.search_events(populated, text="powershell")
    assert total == 1
    seen: set[str] = set()
    for page in range(1, 7):
        frame, total = data_access.search_events(populated, source_type="sysmon", page=page, page_size=50)
        seen |= set(frame["event_id"])
    assert len(seen) == 280                                    # pages do not overlap or skip rows
    frame, _ = data_access.search_events(populated, page=999)
    assert frame.empty


def test_event_search_rejects_invalid_ip(populated) -> None:
    with pytest.raises(ValueError, match="not a valid IP"):
        data_access.search_events(populated, ip="999.1.1")


def test_raw_event_viewer(populated) -> None:
    frame, _ = data_access.search_events(populated, text="powershell")
    detail = data_access.event_detail(populated, frame["event_id"].iloc[0])
    assert detail["raw_event"]["EventID"] == 1 and "WINWORD" in detail["raw_event"]["ParentImage"]
    frame, _ = data_access.search_events(populated, ip="203.0.113.10", source_type="linux_auth", page_size=1)
    assert "Failed password" in data_access.event_detail(populated, frame["event_id"].iloc[0])["raw_event"]["raw"]


def test_alert_list_and_evidence(populated) -> None:
    frame = data_access.list_alerts(populated)
    assert len(frame) == 14 and frame["alert_id"].is_unique and frame["incident_id"].notna().all()
    assert len(data_access.list_alerts(populated, rule_id="SOC-001")) == 5
    assert len(data_access.list_alerts(populated, min_severity=5)) == 2
    scan = data_access.list_alerts(populated, src_ip="10.0.0.50").iloc[0]
    detail = data_access.alert_detail(populated, int(scan["alert_id"]))
    assert detail["alert"]["evidence"]["distinct_ports"] == 25 and len(detail["events"]) == 25
    assert set(detail["events"]["role"]) == {"scan_connection"}


def test_incident_views_update_note_and_report(populated, settings) -> None:
    frame = data_access.list_incidents(populated)
    assert len(frame) == 12 and set(frame["status"]) == {"NEW"}
    target = data_access.list_incidents(populated, src_ip="198.51.100.23").iloc[0]
    incident_id = int(target["incident_id"])
    detail = data_access.incident_detail(populated, settings, incident_id)
    assert len(detail["events"]) == 9 and len(detail["alerts"]) == 1 and len(detail["raw_lines"]) == 9
    assert detail["timeline"]["time"].is_monotonic_increasing
    assert set(detail["timeline"]["kind"]) == {"event", "alert", "history"}
    data_access.update_incident_status(populated, settings, incident_id, "IN_PROGRESS", "alice", "triage")
    data_access.add_incident_note(populated, settings, incident_id, "password reset requested", "alice")
    assert len(data_access.list_incidents(populated, status="IN_PROGRESS")) == 1
    assert len(data_access.list_incidents(populated, status="NEW")) == 11
    assert len(data_access.list_incidents(populated, text="db01")) == 1
    detail = data_access.incident_detail(populated, settings, incident_id)
    assert detail["notes"]["note"].tolist() == ["password reset requested"]
    assert detail["history"]["new_status"].tolist()[-1] == "IN_PROGRESS"
    report = data_access.incident_report(populated, incident_id)
    assert "IN_PROGRESS" in report and "password reset requested" in report and "198.51.100.23" in report


def test_large_result_sets_are_capped(db, ingest) -> None:
    ingest("suricata", [s.suricata_flow(s.at(i), "10.0.1.1", 1000 + i % 60000, "10.0.0.2", 80, i)
                        for i in range(3000)])
    frame, total = data_access.search_events(db, page_size=100000)
    assert total == 3000 and len(frame) == 500
    assert int(data_access.overview(db)["event_timeline"]["count"].sum()) == 3000


# ------------------------------------- 2. page scripts with a Streamlit stand-in
class StopPage(Exception):
    pass


class _Ctx:
    def __init__(self, owner: "FakeStreamlit") -> None:
        self._owner = owner

    def __enter__(self) -> "_Ctx":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def __getattr__(self, name: str):
        return getattr(self._owner, name)


class FakeStreamlit:
    """Records calls and returns default widget values. It does not render anything."""
    __version__ = "1.40.0"

    def __init__(self, submit: bool = False, checkbox: bool = False, text: str = "",
                 upload: object = None) -> None:
        self.submit, self.checkbox_value, self.text_value = submit, checkbox, text
        self.upload = upload
        self.errors: list[str] = []
        self.calls: list[str] = []
        self.session_state: dict = {}
        self.sidebar = _Ctx(self)

    def __getattr__(self, name: str):
        if name.startswith("__"):
            raise AttributeError(name)

        def recorder(*args: object, **kwargs: object) -> None:
            self.calls.append(name)
        return recorder

    def error(self, message: object, *a: object, **k: object) -> None:
        self.errors.append(str(message))

    def stop(self) -> None:
        raise StopPage()

    def rerun(self) -> None:
        self.calls.append("rerun")

    def columns(self, spec, *a: object, **k: object):
        return [_Ctx(self) for _ in range(spec if isinstance(spec, int) else len(spec))]

    def tabs(self, labels, *a: object, **k: object):
        return [_Ctx(self) for _ in labels]

    def form(self, *a: object, **k: object) -> _Ctx:
        return _Ctx(self)

    expander = container = form

    def text_input(self, label, value: str = "", **k: object) -> str:
        return value or self.text_value

    def text_area(self, label, value: str = "", **k: object) -> str:
        return value

    def selectbox(self, label, options, index: int = 0, **k: object):
        options = list(options)
        return options[index] if options else None

    def number_input(self, label, min_value=None, max_value=None, value=1, **k: object):
        return value

    def checkbox(self, label, value: bool = False, **k: object) -> bool:
        return self.checkbox_value

    def multiselect(self, label, options, default=None, **k: object):
        return list(default or [])

    def file_uploader(self, *a: object, **k: object):
        self.calls.append("file_uploader")
        return self.upload

    def date_input(self, label, value=None, **k: object):
        return value

    time_input = date_input

    def form_submit_button(self, *a: object, **k: object) -> bool:
        return self.submit

    def button(self, *a: object, **k: object) -> bool:
        return False

    def download_button(self, label, data=None, **k: object) -> bool:
        self.calls.append("download_button")
        self.downloaded = data
        return False


def run_pages(monkeypatch, db_path: Path, **stub_options) -> dict[str, FakeStreamlit]:
    """Execute every page script with the stand-in modules; return the stub used for each page."""
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    monkeypatch.delenv("SOC_CONFIG_FILE", raising=False)
    express = types.ModuleType("plotly.express")
    for chart in ("bar", "line", "pie", "histogram", "scatter", "timeline"):
        setattr(express, chart, lambda *a, **k: object())
    plotly = types.ModuleType("plotly")
    plotly.express = express
    monkeypatch.setitem(sys.modules, "plotly", plotly)
    monkeypatch.setitem(sys.modules, "plotly.express", express)
    results = {}
    for page in PAGES:
        stub = FakeStreamlit(**stub_options)
        monkeypatch.setitem(sys.modules, "streamlit", stub)
        monkeypatch.delitem(sys.modules, "ui.common", raising=False)
        try:
            runpy.run_path(str(page), run_name="__main__")
        except StopPage:
            stub.calls.append("stopped")
        results[page.name] = stub
    monkeypatch.delitem(sys.modules, "ui.common", raising=False)
    return results


def test_pages_with_missing_database_show_error_and_stop(monkeypatch, tmp_path) -> None:
    results = run_pages(monkeypatch, tmp_path / "missing.db")
    assert len(results) == 6
    for name, stub in results.items():
        assert "stopped" in stub.calls, name
        assert any("Cannot open the database" in e for e in stub.errors), name
    assert not (tmp_path / "missing.db").exists()


def test_pages_with_corrupt_database_show_error_and_stop(monkeypatch, tmp_path) -> None:
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"not a database" * 300)
    for name, stub in run_pages(monkeypatch, corrupt).items():
        assert "stopped" in stub.calls and stub.errors, name


def test_pages_with_empty_database_do_not_crash(monkeypatch, db, settings) -> None:
    results = run_pages(monkeypatch, settings.db_path)
    for name, stub in results.items():
        assert stub.errors == [] and "stopped" not in stub.calls, name
        assert "info" in stub.calls, name                       # each page explains that there is no data
    assert "plotly_chart" not in results["dashboard.py"].calls


def test_pages_with_data_render_all_sections(monkeypatch, populated, settings) -> None:
    results = run_pages(monkeypatch, settings.db_path)
    for name, stub in results.items():
        assert stub.errors == [] and "stopped" not in stub.calls, name
    overview = results["dashboard.py"].calls
    assert overview.count("metric") == 9 and overview.count("plotly_chart") == 8   # incl. dedup + Gantt
    assert "plotly_chart" in results["4_Investigation.py"].calls                # interactive timeline
    assert "file_uploader" in results["5_Upload_Logs.py"].calls
    assert results["1_Events.py"].calls.count("dataframe") == 1 and "json" in results["1_Events.py"].calls
    assert results["2_Alerts.py"].calls.count("dataframe") == 2 and "json" in results["2_Alerts.py"].calls
    assert results["3_Incidents.py"].calls.count("dataframe") == 3
    investigation = results["4_Investigation.py"]
    assert "download_button" in investigation.calls and "code" in investigation.calls
    assert investigation.downloaded.startswith("# Incident Report #")


def test_pages_with_time_filter_and_search_text(monkeypatch, populated, settings) -> None:
    results = run_pages(monkeypatch, settings.db_path, checkbox=True, text="zzz-no-match")
    events = results["1_Events.py"]
    assert any("not a valid IP" in e for e in events.errors)     # the stub typed text into the IP box too
    assert results["4_Investigation.py"].errors == []


def test_page_forms_update_status_and_handle_empty_note(monkeypatch, populated, settings) -> None:
    results = run_pages(monkeypatch, settings.db_path, submit=True)
    incidents = results["3_Incidents.py"]
    assert incidents.errors == [] and "success" in incidents.calls and "rerun" in incidents.calls
    frame = data_access.list_incidents(populated)
    assert sorted(frame["status"].tolist()).count("IN_PROGRESS") == 1      # the form really wrote to SQLite
    investigation = results["4_Investigation.py"]
    assert any("Note not saved" in e and "empty" in e for e in investigation.errors)


# --------------------------------------------- 3. real Streamlit (when installed)
@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_pages_with_real_streamlit_apptest(monkeypatch, populated, settings, page: Path) -> None:
    pytest.importorskip("streamlit", reason="streamlit is not installed in this environment")
    pytest.importorskip("plotly", reason="plotly is not installed in this environment")
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("SOC_DB_PATH", str(settings.db_path))
    monkeypatch.delenv("SOC_CONFIG_FILE", raising=False)
    monkeypatch.delitem(sys.modules, "ui.common", raising=False)
    app = AppTest.from_file(str(page), default_timeout=60).run()
    assert not app.exception, [e.value for e in app.exception]
    assert not app.error, [e.value for e in app.error]


# ------------------------------------------- 4. assignment, dedup metric, upload
def test_overview_dedup_assets_and_gantt(populated) -> None:
    data = data_access.overview(populated)
    dedup = data["dedup"]
    assert dedup["alerts"] == 14 and dedup["incidents"] == 12 and dedup["raw_alerts"] == 21
    assert dedup["reduction_percent"] == 42.9 and "21 raw alerts" in data["dedup_sentence"]
    assets = data["top_attacked_assets"]
    assert not assets.empty and assets["alerts"].is_monotonic_decreasing
    gantt = data["incident_gantt"]
    assert len(gantt) == 12 and (gantt["end"] > gantt["start"]).all()
    assert gantt["start"].is_monotonic_increasing


def test_incident_timeline_chart_has_lanes(populated, settings) -> None:
    incident_id = int(data_access.list_incidents(populated, src_ip="198.51.100.23").iloc[0]["incident_id"])
    data_access.add_incident_note(populated, settings, incident_id, "checked", "alice")
    chart = data_access.incident_detail(populated, settings, incident_id)["timeline_chart"]
    assert {"Log events", "Alerts", "Notes"} <= set(chart["lane"])
    assert chart["time"].is_monotonic_increasing


def test_assign_incident_and_filter_by_analyst(populated, settings) -> None:
    incident_id = int(data_access.list_incidents(populated).iloc[0]["incident_id"])
    data_access.assign_incident(populated, settings, incident_id, "bob", "lead")
    frame = data_access.list_incidents(populated, analyst="bob")
    assert frame["incident_id"].tolist() == [incident_id] and frame["assigned_analyst"].tolist() == ["bob"]
    with pytest.raises(IncidentError, match="already assigned"):
        data_access.assign_incident(populated, settings, incident_id, "bob", "lead")
    data_access.assign_incident(populated, settings, incident_id, "", "lead")
    assert data_access.list_incidents(populated, analyst="bob").empty


def test_safe_upload_name() -> None:
    assert data_access.safe_upload_name("../../etc/passwd") == "passwd"
    assert data_access.safe_upload_name("C:\\x\\my auth.log") == "my_auth.log"
    assert data_access.safe_upload_name("...") == "upload.log"
    assert len(data_access.safe_upload_name("a" * 500)) == 100


def test_ingest_uploaded_saves_imports_and_detects(db, settings) -> None:
    lines = [f"Nov 13 05:00:{i:02d} web09 sshd[{100 + i}]: Failed password for root from 203.0.113.200 "
             f"port {40000 + i} ssh2" for i in range(6)]
    content = ("\n".join(lines) + "\nnot a syslog line\n").encode()
    result = data_access.ingest_uploaded(db, settings, "linux_auth", "../evil name.log", content)
    saved = Path(result["file"])
    assert saved.parent == settings.allowed_input_dirs[0] / "uploads" and saved.name.endswith("evil_name.log")
    assert result["ingest"].new_events == 6 and result["ingest"].rejected == 1
    assert result["detection"].alerts_new == 1 and result["detection"].incidents_created == 1
    with pytest.raises(ValueError, match="empty"):
        data_access.ingest_uploaded(db, settings, "linux_auth", "x.log", b"")
    with pytest.raises(ValueError, match="unknown source"):
        data_access.ingest_uploaded(db, settings, "windows", "x.log", b"abc")


def test_upload_page_imports_file(monkeypatch, db, settings) -> None:
    class Upload:
        name = "auth.log"

        def getvalue(self) -> bytes:
            return b"Nov 13 05:10:00 web09 sshd[1]: Accepted password for bob from 10.0.0.9 port 1 ssh2\n"
    monkeypatch.setenv("SOC_ALLOWED_INPUT_DIRS", str(settings.allowed_input_dirs[0]))  # never write into datasets/
    results = run_pages(monkeypatch, settings.db_path, submit=True, upload=Upload())
    upload = results["5_Upload_Logs.py"]
    assert upload.errors == [] and upload.calls.count("success") == 1      # detection box is unchecked
    assert data_access.overview(db)["counts"]["events"] == 1
    assert len(list((settings.allowed_input_dirs[0] / "uploads").iterdir())) == 1
