"""SOC dashboard — Overview page. Run with:  streamlit run ui/dashboard.py"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import plotly.express as px  # noqa: E402
import streamlit as st  # noqa: E402

from ui import data_access  # noqa: E402
from ui.common import HANDLED_ERRORS, CHART, setup_page  # noqa: E402


def render() -> None:
    _settings, db = setup_page("SOC Overview")
    try:
        data = data_access.overview(db)
    except HANDLED_ERRORS as exc:
        st.error(f"Cannot load overview data: {exc}")
        return
    counts = data["counts"]
    cols = st.columns(5)
    cols[0].metric("Total Events", f"{counts['events']:,}")
    cols[1].metric("Total Alerts", f"{counts['alerts']:,}")
    cols[2].metric("Active Incidents", f"{counts['active_incidents']:,}")
    cols[3].metric("Closed Incidents", f"{counts['closed_incidents']:,}")
    cols[4].metric("Rejected Lines", f"{counts['rejected_events']:,}")
    dedup = data["dedup"]
    dcols = st.columns(4)
    dcols[0].metric("Raw alerts", f"{dedup['raw_alerts']:,}",
                    help="Rule detections before deduplication plus Suricata alert events")
    dcols[1].metric("Deduplicated alerts", f"{dedup['alerts']:,}")
    dcols[2].metric("Incidents to triage", f"{dedup['incidents']:,}")
    dcols[3].metric("Alert noise removed", f"{dedup['reduction_percent']}%")
    if counts["events"] == 0:
        st.info("The database has no events yet. Import logs with `python main.py run-sample` "
                "or `python main.py ingest --source <type> --file <path>`.")
        return

    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by Severity")
        if data["alerts_by_severity"].empty:
            st.caption("No alerts.")
        else:
            st.plotly_chart(px.bar(data["alerts_by_severity"], x="label", y="count",
                                   labels={"label": "Severity", "count": "Alerts"}), **CHART)
        st.subheader("Top Source IPs")
        if data["top_source_ips"].empty:
            st.caption("No source IPs.")
        else:
            st.plotly_chart(px.bar(data["top_source_ips"], x="count", y="src_ip", orientation="h",
                                   labels={"src_ip": "Source IP", "count": "Events"}), **CHART)
    with right:
        st.subheader("Events by Source")
        st.plotly_chart(px.pie(data["events_by_source"], names="source_type", values="count"),
                        **CHART)
        st.subheader("Top Target Hosts")
        if data["top_target_hosts"].empty:
            st.caption("No hosts.")
        else:
            st.plotly_chart(px.bar(data["top_target_hosts"], x="count", y="hostname", orientation="h",
                                   labels={"hostname": "Host", "count": "Events"}), **CHART)

    st.caption(data["dedup_sentence"])
    st.subheader("Top Attacked Assets")
    if data["top_attacked_assets"].empty:
        st.caption("No alerts yet.")
    else:
        st.plotly_chart(px.bar(data["top_attacked_assets"], x="alerts", y="asset", orientation="h",
                               color="max_severity", hover_data=["detections"],
                               labels={"asset": "Asset", "alerts": "Alerts", "max_severity": "Max severity",
                                       "detections": "Raw detections"}), **CHART)

    st.subheader("Event Timeline (UTC)")
    st.plotly_chart(px.line(data["event_timeline"], x="time", y="count",
                            labels={"time": "Time", "count": "Events"}), **CHART)
    st.subheader("Incident Timeline (UTC)")
    if data["incident_gantt"].empty:
        st.caption("No incidents.")
    else:
        st.caption("Each bar runs from the incident's first to last seen event; hover for details, "
                   "drag to zoom, double-click to reset.")
        st.plotly_chart(px.timeline(data["incident_gantt"], x_start="start", x_end="end", y="incident",
                                    color="severity", hover_data=["status", "title"],
                                    labels={"incident": "Incident", "severity": "Severity"}), **CHART)
        st.plotly_chart(px.bar(data["incident_timeline"], x="time", y="count",
                               labels={"time": "Time (first seen)", "count": "New incidents"}), **CHART)


render()
