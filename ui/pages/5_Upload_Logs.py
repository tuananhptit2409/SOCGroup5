"""Upload Logs page: import a log file from the browser, then run detection and correlation."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from pipeline import PipelineError  # noqa: E402
from ui import data_access  # noqa: E402
from ui.common import HANDLED_ERRORS, setup_page  # noqa: E402

SOURCE_LABELS = {"linux_auth": "Linux auth.log (syslog)", "sysmon": "Sysmon (JSON lines)",
                 "suricata": "Suricata eve.json", "web_access": "Web access log (nginx / Apache)"}


def render() -> None:
    settings, db = setup_page("Upload Logs")
    st.info("Upload an auth.log, Sysmon JSON-lines or Suricata eve.json file. It is saved under "
            "datasets/uploads/, imported (bad lines are kept as rejected, never fatal), and detection "
            f"runs on the whole database. Limit: {data_access.MAX_UPLOAD_BYTES // (1024 * 1024)} MB; "
            "larger files: `python main.py ingest --source <type> --file <path> --detect`.")
    with st.form("upload_log"):
        source_type = st.selectbox("Log source", list(data_access.UPLOAD_SOURCES),
                                   format_func=lambda s: SOURCE_LABELS.get(s, s))
        uploaded = st.file_uploader("Log file", type=None, accept_multiple_files=False)
        detect = st.checkbox("Run detection and correlation after import", value=True, key="upload_detect")
        submitted = st.form_submit_button("Import")
    if not submitted:
        return
    if uploaded is None:
        st.error("Choose a file to upload first.")
        return
    try:
        result = data_access.ingest_uploaded(db, settings, source_type, uploaded.name, uploaded.getvalue(),
                                             detect=detect)
    except (*HANDLED_ERRORS, PipelineError, OSError) as exc:
        st.error(f"Import failed: {exc}")
        return
    ingest = result["ingest"]
    st.success(f"Imported {uploaded.name}: {ingest.new_events:,} new events, {ingest.rejected:,} rejected "
               f"lines, {ingest.duplicates:,} duplicates.")
    cols = st.columns(3)
    cols[0].metric("Lines read", f"{ingest.total_lines:,}")
    cols[1].metric("New events", f"{ingest.new_events:,}")
    cols[2].metric("Rejected", f"{ingest.rejected:,}")
    if ingest.reject_reasons:
        st.json(ingest.reject_reasons)
    detection = result.get("detection")
    if detection is not None:
        st.success(f"Detection: {detection.alerts_new} new alerts, {detection.alerts_updated} updated, "
                   f"{detection.incidents_created} new incidents.")
        if detection.rule_errors:
            st.error(f"Some rules failed: {detection.rule_errors}")


render()
