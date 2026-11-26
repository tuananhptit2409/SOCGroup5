"""Storage models: incident statuses, severity scale and typed records read from SQLite.

The Unified Event Schema (normalized events) lives in ``normalizer/models.py``;
this module describes what the toolkit derives from those events: alerts,
incidents and the deduplication summary.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Mapping

# Incident lifecycle. NEW / IN_PROGRESS / CLOSED are the statuses of the
# assignment; FALSE_POSITIVE is an extra closed state for benign detections.
INCIDENT_STATUSES = ("NEW", "IN_PROGRESS", "CLOSED", "FALSE_POSITIVE")
OPEN_STATUSES = ("NEW", "IN_PROGRESS")
CLOSED_STATUSES = ("CLOSED", "FALSE_POSITIVE")
STATUS_LABELS = {"NEW": "New", "IN_PROGRESS": "In Progress", "CLOSED": "Closed", "FALSE_POSITIVE": "False Positive"}

SEVERITY_LABELS = {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}


def severity_label(severity: int | None) -> str:
    return SEVERITY_LABELS.get(int(severity), "?") if severity is not None else "?"


def _row(row: sqlite3.Row | Mapping[str, Any]) -> Mapping[str, Any]:
    return dict(row) if isinstance(row, sqlite3.Row) else row


@dataclass(frozen=True)
class AlertRecord:
    """One deduplicated alert. ``occurrence_count`` = raw detections merged into it."""
    alert_id: int
    rule_id: str
    rule_name: str
    severity: int
    entity_key: str
    src_ip: str | None
    dst_ip: str | None
    hostname: str | None
    first_seen: str
    last_seen: str
    event_count: int
    occurrence_count: int

    @classmethod
    def from_row(cls, row: sqlite3.Row | Mapping[str, Any]) -> "AlertRecord":
        data = _row(row)
        return cls(**{name: data[name] for name in cls.__dataclass_fields__})


@dataclass(frozen=True)
class IncidentRecord:
    """One incident (a group of related alerts about the same entity)."""
    incident_id: int
    title: str
    severity: int
    status: str
    rule_id: str
    src_ip: str | None
    dst_ip: str | None
    affected_asset: str | None
    assigned_analyst: str | None
    first_seen: str
    last_seen: str
    occurrence_count: int
    created_at: str
    updated_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row | Mapping[str, Any]) -> "IncidentRecord":
        data = _row(row)
        return cls(**{name: data[name] for name in cls.__dataclass_fields__})

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_STATUSES

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)


# Tuần 9: DedupSummary thống kê giảm tải cảnh báo cho SOC Analyst
@dataclass(frozen=True)
class DedupSummary:
    """How much alert volume the toolkit removes before an analyst sees it.

    raw_detections  every individual rule hit (one per attack burst / window)
    ids_alerts      raw Suricata alert events (NIDS alerts as they arrive)
    alerts          alerts left after deduplication (cooldown window per rule + entity)
    incidents       incidents left after grouping related alerts per entity
    """
    raw_detections: int
    ids_alerts: int
    alerts: int
    incidents: int

    @property
    def raw_alerts(self) -> int:
        """Everything that would reach an analyst without the toolkit."""
        return self.raw_detections + self.ids_alerts

    @property
    def reduction_percent(self) -> float:
        """Share of raw alerts that did not become a separate incident."""
        if self.raw_alerts == 0:
            return 0.0
        return round(100.0 * (1 - self.incidents / self.raw_alerts), 1)

    @property
    def detections_per_incident(self) -> float:
        return round(self.raw_detections / self.incidents, 2) if self.incidents else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"raw_detections": self.raw_detections, "ids_alerts": self.ids_alerts,
                "raw_alerts": self.raw_alerts, "alerts": self.alerts, "incidents": self.incidents,
                "reduction_percent": self.reduction_percent,
                "detections_per_incident": self.detections_per_incident}

    def sentence(self) -> str:
        return (f"{self.raw_alerts} raw alerts ({self.raw_detections} rule detections + {self.ids_alerts} "
                f"Suricata alerts) -> {self.alerts} deduplicated alerts -> {self.incidents} incidents "
                f"({self.reduction_percent}% fewer items to triage)")
