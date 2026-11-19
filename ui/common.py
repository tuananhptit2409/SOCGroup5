"""Shared Streamlit helpers for all dashboard pages."""
from __future__ import annotations

import inspect

import streamlit as st

from config import ConfigError, Settings, load_settings
from engine.incident_manager import IncidentError
from storage.database import Database, DatabaseError
from ui import data_access

SEVERITY_OPTIONS = {"Any": None, "LOW (2+)": 2, "MEDIUM (3+)": 3, "HIGH (4+)": 4, "CRITICAL (5)": 5}
HANDLED_ERRORS = (DatabaseError, IncidentError, ValueError)


def full_width(func: object) -> dict[str, object]:
    """Keyword that makes a table/chart use the full container width on this Streamlit version.

    Newer Streamlit takes ``width="stretch"`` (``use_container_width`` is deprecated);
    older versions only know ``use_container_width=True``. The choice is made from
    the function signature, not from a guessed version number.
    """
    try:
        parameter = inspect.signature(func).parameters.get("width")  # type: ignore[arg-type]
    except (TypeError, ValueError):
        parameter = None
    if parameter is not None and isinstance(parameter.default, str):
        return {"width": "stretch"}
    return {"use_container_width": True}


TABLE = full_width(st.dataframe)
CHART = full_width(st.plotly_chart)


def setup_page(title: str) -> tuple[Settings, Database]:
    """Configure the page and return (settings, database); stop the page if the DB is unusable."""
    st.set_page_config(page_title=f"SOC Toolkit - {title}", layout="wide")
    st.title(title)
    try:
        settings = load_settings()
        db = data_access.get_database(settings)
    except (ConfigError, DatabaseError) as exc:
        st.error(f"Cannot open the database: {exc}")
        st.info("Initialize it with `python main.py init-db`, then import logs with "
                "`python main.py run-sample` or `python main.py ingest ...`.")
        st.stop()
        raise  # only reached if st.stop() did not stop (never in a real Streamlit run)
    st.sidebar.caption(f"Database: {settings.db_path}")
    return settings, db


def severity_filter(label: str = "Minimum severity", key: str | None = None) -> int | None:
    choice = st.selectbox(label, list(SEVERITY_OPTIONS), key=key)
    return SEVERITY_OPTIONS.get(choice)
