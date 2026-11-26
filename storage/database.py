"""SQLite connection management and schema initialization."""
from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)
SCHEMA_FILE = Path(__file__).with_name("schema.sql")
# Columns added after the first release: (table, column, column definition).
# init_schema() adds them to an existing database; check_schema() reports them.
MIGRATED_COLUMNS = (
    ("incidents", "assigned_analyst", "TEXT"),
    ("events", "url", "TEXT"),
    ("events", "http_status", "INTEGER"),
    ("events", "user_agent", "TEXT"),
)
REQUIRED_TABLES = ("import_batches", "raw_events", "events", "alerts", "alert_events", "incidents",
                   "incident_alerts", "incident_events", "incident_history", "incident_notes")


class DatabaseError(Exception):
    """The database is missing, unreadable or not initialized."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Database:
    """Opens short-lived connections to one SQLite file.

    Every connection enables foreign keys, WAL journaling and a busy timeout.
    Use ``connection()`` for reads and ``transaction()`` for atomic writes;
    both always close the connection.
    """

    def __init__(self, path: str | Path, busy_timeout_ms: int = 5000, cache_mb: int = 64) -> None:
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self.cache_mb = cache_mb

    def _open(self, must_exist: bool) -> sqlite3.Connection:
        if must_exist and not self.path.is_file():
            raise DatabaseError(f"database file not found: {self.path} (run: python main.py init-db)")
        try:
            conn = sqlite3.connect(str(self.path), timeout=self.busy_timeout_ms / 1000,
                                   isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_ms)}")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute(f"PRAGMA cache_size = {-1024 * int(self.cache_mb)}")   # negative = size in KiB
            conn.execute("PRAGMA temp_store = MEMORY")
        except sqlite3.Error as exc:
            raise DatabaseError(f"cannot open database {self.path}: {exc}") from exc
        return conn

    @contextmanager
    def connection(self, must_exist: bool = True) -> Iterator[sqlite3.Connection]:
        """Yield an autocommit connection and close it afterwards."""
        conn = self._open(must_exist)
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self, must_exist: bool = True) -> Iterator[sqlite3.Connection]:
        """Yield a connection inside BEGIN IMMEDIATE; commit on success, roll back on error."""
        conn = self._open(must_exist)
        try:
            try:
                conn.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                raise DatabaseError(f"cannot start a write transaction on {self.path} "
                                    f"(database busy or locked): {exc}") from exc
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Create the database file (if needed) and all tables and indexes."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        script = SCHEMA_FILE.read_text(encoding="utf-8")
        with self.connection(must_exist=False) as conn:
            added = self._add_missing_columns(conn)   # before the script: it indexes the new columns
            conn.executescript(script)
        if added:
            logger.info("event=schema_migrated added=%s", ",".join(added))
        logger.info("event=schema_initialized path=%s", self.path)

    @staticmethod
    def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

    def _add_missing_columns(self, conn: sqlite3.Connection) -> list[str]:
        """Upgrade a database created by an older version (ALTER TABLE ... ADD COLUMN)."""
        added = []
        for table, column, definition in MIGRATED_COLUMNS:
            existing = self._columns(conn, table)
            if existing and column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                added.append(f"{table}.{column}")
        return added

    def check_schema(self) -> None:
        """Raise DatabaseError unless every required table exists."""
        try:
            with self.connection() as conn:
                names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        except sqlite3.Error as exc:
            raise DatabaseError(f"cannot read database {self.path}: {exc}") from exc
        missing = [t for t in REQUIRED_TABLES if t not in names]
        if missing:
            raise DatabaseError(f"database is not initialized (missing tables: {', '.join(missing)}); "
                                "run: python main.py init-db")
        with self.connection() as conn:
            outdated = [f"{table}.{column}" for table, column, _ in MIGRATED_COLUMNS
                        if column not in self._columns(conn, table)]
        if outdated:
            raise DatabaseError(f"database schema is out of date (missing {', '.join(outdated)}); "
                                "run: python main.py init-db (existing data is kept)")

    def integrity_report(self) -> dict[str, object]:
        """Run PRAGMA integrity_check and foreign_key_check."""
        with self.connection() as conn:
            integrity = [r[0] for r in conn.execute("PRAGMA integrity_check")]
            fk = [tuple(r) for r in conn.execute("PRAGMA foreign_key_check")]
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        return {"integrity_check": integrity, "foreign_key_violations": fk, "journal_mode": mode}
