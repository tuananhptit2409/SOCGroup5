"""Events page: search, filter, paginate normalized events and view the raw event."""
from __future__ import annotations

import sys
from datetime import datetime, time, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from ui import data_access  # noqa: E402
from ui.common import HANDLED_ERRORS, TABLE, setup_page, severity_filter  # noqa: E402


def render() -> None:
    _settings, db = setup_page("Events")
    try:
        sources = data_access.source_types(db)
    except HANDLED_ERRORS as exc:
        st.error(f"Cannot load events: {exc}")
        return

    cols = st.columns(4)
    with cols[0]:
        text = st.text_input("Search (message, user, host, command line)")
    with cols[1]:
        ip = st.text_input("IP address (source or destination)")
    with cols[2]:
        source = st.selectbox("Source", ["Any", *sources])
    with cols[3]:
        min_severity = severity_filter(key="events_severity")
    use_time = st.checkbox("Filter by time range (UTC)")
    start = end = None
    if use_time:
        tcols = st.columns(2)
        today = datetime.now(timezone.utc).date()
        with tcols[0]:
            start_date = st.date_input("From date", value=today)
            start_time = st.time_input("From time", value=time(0, 0))
        with tcols[1]:
            end_date = st.date_input("To date", value=today)
            end_time = st.time_input("To time", value=time(23, 59, 59))
        start = datetime.combine(start_date, start_time, tzinfo=timezone.utc)
        end = datetime.combine(end_date, end_time, tzinfo=timezone.utc)
        if start > end:
            st.warning("'From' is after 'To'; no events can match.")
    pcols = st.columns(2)
    with pcols[0]:
        page_size = st.selectbox("Rows per page", [25, 50, 100, 200], index=1)
    with pcols[1]:
        page = st.number_input("Page", min_value=1, value=1, step=1)

    try:
        frame, total = data_access.search_events(
            db, ip=ip, source_type=None if source == "Any" else source, min_severity=min_severity,
            start=start, end=end, text=text, page=int(page), page_size=int(page_size))
    except HANDLED_ERRORS as exc:
        st.error(str(exc))
        return
    pages = max(1, -(-total // int(page_size)))
    st.caption(f"{total:,} matching events - page {int(page)} of {pages}")
    if frame.empty:
        st.info("No events match the filters." if total == 0 else "This page is past the last result.")
        return
    st.dataframe(frame, **TABLE, hide_index=True)

    st.subheader("Raw event viewer")
    event_id = st.selectbox("Event", frame["event_id"].tolist())
    detail = data_access.event_detail(db, str(event_id)) if event_id else None
    if detail:
        st.json(detail)


render()
