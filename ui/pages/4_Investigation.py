"""Investigation page: timeline, linked alerts, related events, raw evidence, notes, report."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import plotly.express as px  # noqa: E402
import streamlit as st  # noqa: E402

from ui import data_access  # noqa: E402
from ui.common import CHART, HANDLED_ERRORS, TABLE, setup_page  # noqa: E402

EVENT_VIEW = ["timestamp_utc", "source_type", "action", "severity", "hostname", "username", "src_ip",
              "dst_ip", "dst_port", "message", "command_line", "event_id"]


def render() -> None:
    settings, db = setup_page("Investigation")
    try:
        incidents = data_access.list_incidents(db)
    except HANDLED_ERRORS as exc:
        st.error(str(exc))
        return
    if incidents.empty:
        st.info("No incidents to investigate yet.")
        return
    labels = {int(r.incident_id): f"#{r.incident_id} [{r.status}] sev {r.severity} - {r.title}"
              for r in incidents.itertuples()}
    incident_id = st.selectbox("Incident", list(labels), format_func=lambda i: labels.get(i, str(i)))
    if incident_id is None:
        return
    try:
        detail = data_access.incident_detail(db, settings, int(incident_id))
    except HANDLED_ERRORS as exc:
        st.error(str(exc))
        return
    incident = detail["incident"]
    st.text(f"{incident['title']} | status {incident['status']} | severity {incident['severity']}")

    st.subheader("Incident timeline (UTC)")
    chart = detail["timeline_chart"]
    if chart.empty:
        st.caption("No timeline entries.")
    else:
        st.caption("Hover a point for its details; drag to zoom, double-click to reset.")
        st.plotly_chart(px.scatter(chart, x="time", y="lane", color="lane", hover_data=["summary", "ref"],
                                   labels={"time": "Time (UTC)", "lane": ""}), **CHART)
    kinds = sorted(detail["timeline"]["kind"].unique().tolist()) if not detail["timeline"].empty else []
    shown = st.multiselect("Show entry types", kinds, default=kinds)
    table = detail["timeline"]
    if shown is not None and kinds:
        table = table[table["kind"].isin(shown)]
    st.dataframe(table, **TABLE, hide_index=True)

    st.subheader("Linked alerts")
    for alert in detail["alerts"].to_dict("records"):
        with st.expander(f"Alert #{alert['alert_id']} - {alert['rule_id']} {alert['rule_name']} "
                         f"(severity {alert['severity']})"):
            st.text(f"Rationale: {alert['rationale']}")
            evidence = data_access.alert_detail(db, int(alert["alert_id"]))
            if evidence:
                st.json(evidence["alert"]["evidence"])

    st.subheader("Related events")
    events = detail["events"]
    query = st.text_input("Search in related events")
    if not events.empty:
        view = events[[c for c in EVENT_VIEW if c in events.columns]]
        if query.strip():
            needle = query.strip().lower()
            mask = view.astype(str).apply(lambda col: col.str.lower().str.contains(needle, regex=False))
            view = view[mask.any(axis=1)]
        st.caption(f"{len(view):,} of {len(events):,} events")
        st.dataframe(view, **TABLE, hide_index=True)
    else:
        st.caption("No linked events.")

    st.subheader("Raw log evidence")
    st.code("\n".join(line[:2000] for line in detail["raw_lines"][:200]) or "(none)", language="text")

    st.subheader("Analyst notes")
    if detail["notes"].empty:
        st.caption("No notes yet.")
    else:
        st.dataframe(detail["notes"][["created_at", "author", "note"]], **TABLE,
                     hide_index=True)
    with st.form("add_note"):
        author = st.text_input("Analyst", value="analyst")
        note = st.text_area("New note")
        submitted = st.form_submit_button("Add note")
    if submitted:
        try:
            data_access.add_incident_note(db, settings, int(incident_id), note, author)
        except HANDLED_ERRORS as exc:
            st.error(f"Note not saved: {exc}")
        else:
            st.success("Note saved.")
            st.rerun()

    st.subheader("Export report")
    try:
        report = data_access.incident_report(db, int(incident_id))
    except HANDLED_ERRORS as exc:
        st.error(str(exc))
        return
    st.download_button("Download incident report (Markdown)", data=report,
                       file_name=f"incident_{int(incident_id)}.md", mime="text/markdown")


render()
