"""Alerts page: alert list with rule, severity, source, event count and evidence."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from ui import data_access  # noqa: E402
from ui.common import HANDLED_ERRORS, TABLE, setup_page, severity_filter  # noqa: E402

RULES = ["Any", "SOC-001", "SOC-002", "SOC-003", "SOC-004"]


def render() -> None:
    _settings, db = setup_page("Alerts")
    cols = st.columns(3)
    with cols[0]:
        rule = st.selectbox("Rule", RULES)
    with cols[1]:
        min_severity = severity_filter(key="alerts_severity")
    with cols[2]:
        src_ip = st.text_input("Source IP")
    try:
        frame = data_access.list_alerts(db, rule_id=None if rule == "Any" else rule,
                                        min_severity=min_severity, src_ip=src_ip)
    except HANDLED_ERRORS as exc:
        st.error(str(exc))
        return
    st.caption(f"{len(frame):,} alerts")
    if frame.empty:
        st.info("No alerts. Run `python main.py detect` after importing logs.")
        return
    st.dataframe(frame, **TABLE, hide_index=True)

    st.subheader("Alert evidence")
    alert_id = st.selectbox("Alert", frame["alert_id"].tolist())
    detail = data_access.alert_detail(db, int(alert_id)) if alert_id is not None else None
    if not detail:
        return
    alert = detail["alert"]
    st.text(f"{alert['rule_id']} {alert['rule_name']} | severity {alert['severity']} | "
            f"{alert['first_seen']} to {alert['last_seen']} | MITRE: {alert['mitre']}")
    st.text(f"Rationale: {alert['rationale']}")
    st.json(alert["evidence"])
    st.caption(f"Linked events ({alert['event_count']})")
    st.dataframe(detail["events"], **TABLE, hide_index=True)


render()
