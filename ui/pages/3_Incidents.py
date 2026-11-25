"""Incidents page: incident list, details and status update."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from storage.repository import INCIDENT_STATUSES  # noqa: E402
from ui import data_access  # noqa: E402
from ui.common import HANDLED_ERRORS, TABLE, setup_page, severity_filter  # noqa: E402


def render() -> None:
    settings, db = setup_page("Incidents")
    cols = st.columns(5)
    with cols[0]:
        status = st.selectbox("Status", ["Any", *INCIDENT_STATUSES])
    with cols[1]:
        min_severity = severity_filter(key="incidents_severity")
    with cols[2]:
        src_ip = st.text_input("IP address")
    with cols[3]:
        text = st.text_input("Search title / asset")
    with cols[4]:
        analyst_filter = st.text_input("Assigned analyst")
    try:
        frame = data_access.list_incidents(db, status=None if status == "Any" else status,
                                           min_severity=min_severity, src_ip=src_ip, text=text,
                                           analyst=analyst_filter)
    except HANDLED_ERRORS as exc:
        st.error(str(exc))
        return
    st.caption(f"{len(frame):,} incidents")
    if frame.empty:
        st.info("No incidents match the filters.")
        return
    st.dataframe(frame, **TABLE, hide_index=True)

    st.subheader("Incident details")
    incident_id = st.selectbox("Incident", frame["incident_id"].tolist())
    if incident_id is None:
        return
    try:
        detail = data_access.incident_detail(db, settings, int(incident_id))
    except HANDLED_ERRORS as exc:
        st.error(str(exc))
        return
    incident = detail["incident"]
    mcols = st.columns(5)
    mcols[0].metric("Severity", incident["severity"])
    mcols[1].metric("Status", incident["status"])
    mcols[2].metric("Assigned to", incident.get("assigned_analyst") or "(unassigned)")
    mcols[3].metric("Linked alerts", len(detail["alerts"]))
    mcols[4].metric("Linked events", len(detail["events"]))
    st.text(f"{incident['title']}\nSource IP: {incident['src_ip']} | Destination IP: {incident['dst_ip']} | "
            f"Asset: {incident['affected_asset']} | Rule: {incident['rule_id']}\n"
            f"First seen: {incident['first_seen']} | Last seen: {incident['last_seen']}")
    st.text(incident["description"])

    with st.form("update_status"):
        st.caption("Update status")
        choices = [s for s in INCIDENT_STATUSES if s != incident["status"]]
        new_status = st.selectbox("New status", choices)
        actor = st.text_input("Analyst", value="analyst")
        note = st.text_area("Note (optional)")
        submitted = st.form_submit_button("Update status")
    if submitted:
        try:
            data_access.update_incident_status(db, settings, int(incident_id), new_status, actor, note)
        except HANDLED_ERRORS as exc:
            st.error(f"Status not updated: {exc}")
        else:
            st.success(f"Incident #{incident_id} is now {new_status}.")
            st.rerun()

    with st.form("assign_analyst"):
        st.caption("Assign analyst (leave empty to unassign)")
        analyst = st.text_input("Assign to", value=incident.get("assigned_analyst") or "")
        assigner = st.text_input("Changed by", value="analyst", key="assign_actor")
        assigned = st.form_submit_button("Save assignment")
    current = incident.get("assigned_analyst") or ""
    if assigned and analyst.strip() == current:
        st.info("Assignment unchanged.")
    elif assigned:
        try:
            data_access.assign_incident(db, settings, int(incident_id), analyst, assigner)
        except HANDLED_ERRORS as exc:
            st.error(f"Assignment not saved: {exc}")
        else:
            st.success(f"Incident #{incident_id} assigned to {analyst.strip() or 'nobody'}.")
            st.rerun()
    with st.form("add_note"):
        st.caption("Add note")
        note_text = st.text_area("Note", key="note_text")
        note_author = st.text_input("Author", value="analyst", key="note_author")
        note_submitted = st.form_submit_button("Save note")
    if note_submitted:
        if not note_text.strip():
            st.warning("Please enter a note.")
        else:
            try:
                data_access.add_incident_note(db, settings, int(incident_id), note_text, note_author)
            except HANDLED_ERRORS as exc:
                st.error(f"Note not saved: {exc}")
            else:
                st.success(f"Note added to incident #{incident_id}.")
                st.rerun()
    st.caption("Linked alerts")
    st.dataframe(detail["alerts"].drop(columns=["evidence"], errors="ignore"),
                 **TABLE, hide_index=True)
    st.caption("Status history")
    st.dataframe(detail["history"], **TABLE, hide_index=True)


render()
