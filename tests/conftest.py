"""Shared pytest fixtures. Every test uses its own temporary database and input folder."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Callable, Iterable

import pytest

from config import Settings
from pipeline import DetectionSummary, IngestResult, ingest_file, run_detection
from storage.database import Database


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    return replace(Settings(), db_path=tmp_path / "db" / "soc.db", allowed_input_dirs=(inputs,),
                   reports_dir=tmp_path / "reports", syslog_default_year=2026)


@pytest.fixture
def db(settings: Settings) -> Database:
    database = Database(settings.db_path)
    database.init_schema()
    return database


@pytest.fixture
def ingest(db: Database, settings: Settings) -> Callable[..., IngestResult]:
    """ingest(source_type, lines, name=None) -> IngestResult (writes the lines to a temp file)."""
    counter = {"n": 0}

    def _ingest(source_type: str, lines: Iterable[str], name: str | None = None,
                custom: Settings | None = None) -> IngestResult:
        counter["n"] += 1
        path = settings.allowed_input_dirs[0] / (name or f"{source_type}_{counter['n']}.log")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        return ingest_file(db, custom or settings, source_type, path)

    return _ingest


@pytest.fixture
def detect(db: Database, settings: Settings) -> Callable[..., DetectionSummary]:
    def _detect(custom: Settings | None = None) -> DetectionSummary:
        return run_detection(db, custom or settings)

    return _detect


@pytest.fixture
def alerts(db: Database) -> Callable[..., list[dict]]:
    """alerts(rule_id=None) -> list of alert rows as dicts."""
    def _alerts(rule_id: str | None = None) -> list[dict]:
        with db.connection() as conn:
            sql = "SELECT * FROM alerts" + (" WHERE rule_id = ?" if rule_id else "") + " ORDER BY alert_id"
            return [dict(r) for r in conn.execute(sql, (rule_id,) if rule_id else ())]

    return _alerts


@pytest.fixture
def count(db: Database) -> Callable[[str], int]:
    def _count(table: str) -> int:
        assert table.isidentifier()
        with db.connection() as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    return _count
