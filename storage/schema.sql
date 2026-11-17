-- SOC Analyst Toolkit schema (SQLite). Idempotent: safe to run repeatedly.

CREATE TABLE IF NOT EXISTS import_batches (
    batch_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type  TEXT NOT NULL,
    file_path    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    total_lines  INTEGER NOT NULL DEFAULT 0,
    blank_lines  INTEGER NOT NULL DEFAULT 0,
    new_events   INTEGER NOT NULL DEFAULT 0,
    new_rejected INTEGER NOT NULL DEFAULT 0,
    duplicates   INTEGER NOT NULL DEFAULT 0,
    error        TEXT
);

-- One row per distinct raw line (raw_id = hash of source type + line).
CREATE TABLE IF NOT EXISTS raw_events (
    raw_id      TEXT PRIMARY KEY,
    batch_id    INTEGER NOT NULL REFERENCES import_batches (batch_id),
    source_type TEXT NOT NULL,
    line_no     INTEGER NOT NULL,
    raw_line    TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('accepted', 'rejected')),
    error       TEXT,
    ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_raw_batch ON raw_events (batch_id);
CREATE INDEX IF NOT EXISTS idx_raw_status ON raw_events (status, source_type);

-- Normalized events (Unified Event Schema). raw_event JSON lives in raw_events.
CREATE TABLE IF NOT EXISTS events (
    event_id       TEXT PRIMARY KEY REFERENCES raw_events (raw_id),  -- same id as its raw line
    schema_version INTEGER NOT NULL,
    timestamp_utc  TEXT NOT NULL,
    ts_epoch       REAL NOT NULL,
    source_type    TEXT NOT NULL,
    hostname       TEXT,
    username       TEXT,
    src_ip         TEXT,
    dst_ip         TEXT,
    src_port       INTEGER CHECK (src_port IS NULL OR src_port BETWEEN 0 AND 65535),
    dst_port       INTEGER CHECK (dst_port IS NULL OR dst_port BETWEEN 0 AND 65535),
    protocol       TEXT,
    action         TEXT NOT NULL,
    severity       INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 5),
    message        TEXT NOT NULL,
    process_name   TEXT,
    process_path   TEXT,
    command_line   TEXT,
    parent_process TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events (dst_ip, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_source ON events (source_type, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_action ON events (action, src_ip, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_hostname ON events (hostname);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint      TEXT NOT NULL UNIQUE,
    rule_id          TEXT NOT NULL,
    rule_name        TEXT NOT NULL,
    severity         INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 5),
    entity_key       TEXT NOT NULL,
    src_ip           TEXT,
    dst_ip           TEXT,
    hostname         TEXT,
    username         TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    first_ts         REAL NOT NULL,
    last_ts          REAL NOT NULL,
    event_count      INTEGER NOT NULL DEFAULT 0,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    evidence         TEXT NOT NULL,
    rationale        TEXT NOT NULL,
    mitre            TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_entity ON alerts (rule_id, entity_key, first_ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts (alert_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES events (event_id),
    role     TEXT NOT NULL DEFAULT 'evidence',
    PRIMARY KEY (alert_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events (event_id);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_key       TEXT NOT NULL,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    severity         INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 5),
    status           TEXT NOT NULL DEFAULT 'NEW'
                     CHECK (status IN ('NEW', 'IN_PROGRESS', 'CLOSED', 'FALSE_POSITIVE')),
    rule_id          TEXT NOT NULL,
    src_ip           TEXT,
    dst_ip           TEXT,
    affected_asset   TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    first_ts         REAL NOT NULL,
    last_ts          REAL NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    closed_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_entity ON incidents (entity_key, status);
CREATE INDEX IF NOT EXISTS idx_incidents_src_ip ON incidents (src_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (created_at);

-- An alert belongs to at most one incident (PRIMARY KEY on alert_id).
CREATE TABLE IF NOT EXISTS incident_alerts (
    alert_id    INTEGER PRIMARY KEY REFERENCES alerts (alert_id) ON DELETE CASCADE,
    incident_id INTEGER NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident ON incident_alerts (incident_id);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id INTEGER NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    event_id    TEXT NOT NULL REFERENCES events (event_id),
    PRIMARY KEY (incident_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events (event_id);

-- Audit trail of status changes and automatic actions.
CREATE TABLE IF NOT EXISTS incident_history (
    history_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    changed_at  TEXT NOT NULL,
    actor       TEXT NOT NULL,
    old_status  TEXT,
    new_status  TEXT,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_incident ON incident_history (incident_id);

CREATE TABLE IF NOT EXISTS incident_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    author      TEXT NOT NULL,
    note        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notes_incident ON incident_notes (incident_id);
