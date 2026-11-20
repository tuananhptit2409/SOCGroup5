"""Quản lý incident: gộp alert liên quan thành incident, vòng đời, giao analyst, lịch sử.

Quy tắc gộp: một alert nhập vào incident ĐANG MỞ khi cả hai có cùng thực thể
(IP nguồn; nếu không có IP thì tên máy) và cách nhau không quá 30 phút
(incident_window_seconds). Ví dụ 10.0.0.61 quét cổng rồi brute force SSH
-> 2 alert, 1 incident. Incident đã đóng thì không dùng lại.

Vòng đời: NEW -> IN_PROGRESS -> CLOSED hoặc FALSE_POSITIVE; mỗi lần đổi trạng
thái, giao analyst hay hệ thống tự cập nhật đều ghi vào incident_history.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from config import CorrelationConfig
from normalizer.models import epoch_to_iso
from storage.database import utc_now
from storage.repository import INCIDENT_STATUSES, OPEN_STATUSES, Repository

SYSTEM_ACTOR = "system"
MAX_NOTE_LENGTH = 4000
MAX_ANALYST_LENGTH = 100


class IncidentError(Exception):
    """Invalid incident operation (unknown incident, bad status, empty note)."""


def incident_entity_key(alert: sqlite3.Row) -> str:
    """Entity that ties alerts into one incident: the source IP, else the host."""
    if alert["src_ip"]:
        return f"ip:{alert['src_ip']}"
    return f"host:{alert['hostname'] or 'unknown'}"


class IncidentManager:
    """Groups alerts into incidents and manages the incident lifecycle.

    Correlation policy: an alert joins an OPEN incident only when both share
    the same entity (source IP, or host when there is no source IP) and lie
    within ``incident_window_seconds`` of each other. Closeness in time alone
    never merges alerts. A closed incident is not reused: a new wave of
    activity creates a new incident.
    """

    def __init__(self, conn: sqlite3.Connection, config: CorrelationConfig | None = None) -> None:
        self.repo = Repository(conn)
        self.config = config or CorrelationConfig()

    # ----------------------------------------------------------- correlation
    def sync_alert(self, alert_id: int, outcome: str) -> tuple[int, str]:
        """Attach an alert to an incident; return (incident_id, 'created'|'linked'|'updated'|'unchanged')."""
        repo = self.repo
        alert = repo.get_alert(alert_id)
        if alert is None:
            raise IncidentError(f"alert {alert_id} not found")
        incident = repo.incident_for_alert(alert_id)
        if incident is not None:
            if outcome == "duplicate":
                return int(incident["incident_id"]), "unchanged"
            self._refresh(incident, alert, new_alert=False)
            return int(incident["incident_id"]), "updated"

        entity_key = incident_entity_key(alert)
        incident = repo.find_open_incident(entity_key, alert["first_ts"], alert["last_ts"],
                                           self.config.incident_window_seconds)
        if incident is not None:
            repo.link_incident_alert(int(incident["incident_id"]), alert_id)
            self._refresh(incident, alert, new_alert=True)
            repo.add_history(int(incident["incident_id"]), SYSTEM_ACTOR, None, None,
                             f"Related alert #{alert_id} ({alert['rule_id']} {alert['rule_name']}) linked")
            return int(incident["incident_id"]), "linked"

        now = utc_now()
        target = alert["hostname"] or alert["dst_ip"]
        source = alert["src_ip"] or alert["hostname"] or "unknown source"
        incident_id = repo.insert_incident({
            "entity_key": entity_key,
            "title": f"{alert['rule_name']}: {source}" + (f" -> {target}" if target and target != source else ""),
            "description": alert["rationale"], "severity": alert["severity"], "status": "NEW",
            "rule_id": alert["rule_id"], "src_ip": alert["src_ip"], "dst_ip": alert["dst_ip"],
            "affected_asset": target, "first_seen": alert["first_seen"], "last_seen": alert["last_seen"],
            "first_ts": alert["first_ts"], "last_ts": alert["last_ts"], "occurrence_count": 1,
            "created_at": now, "updated_at": now})
        repo.link_incident_alert(incident_id, alert_id)
        repo.link_incident_events_from_alert(incident_id, alert_id)
        repo.add_history(incident_id, SYSTEM_ACTOR, None, "NEW",
                         f"Incident created from alert #{alert_id} ({alert['rule_id']})")
        return incident_id, "created"

    def _refresh(self, incident: sqlite3.Row, alert: sqlite3.Row, *, new_alert: bool) -> None:
        """Extend an incident with the alert's time range, severity and evidence."""
        repo = self.repo
        incident_id = int(incident["incident_id"])
        added = repo.link_incident_events_from_alert(incident_id, int(alert["alert_id"]))
        first_ts = min(incident["first_ts"], alert["first_ts"])
        last_ts = max(incident["last_ts"], alert["last_ts"])
        values: dict[str, Any] = {
            "first_ts": first_ts, "last_ts": last_ts, "first_seen": epoch_to_iso(first_ts),
            "last_seen": epoch_to_iso(last_ts), "severity": max(incident["severity"], alert["severity"]),
            "updated_at": utc_now()}
        if new_alert:
            values["occurrence_count"] = int(incident["occurrence_count"]) + 1
        if not incident["affected_asset"] and (alert["hostname"] or alert["dst_ip"]):
            values["affected_asset"] = alert["hostname"] or alert["dst_ip"]
        if added and not new_alert and incident["status"] == "CLOSED":
            values["status"], values["closed_at"] = "NEW", None
            repo.add_history(incident_id, SYSTEM_ACTOR, "CLOSED", "NEW",
                             f"Reopened automatically: {added} new event(s) on alert #{alert['alert_id']}")
        elif added and not new_alert and incident["status"] == "FALSE_POSITIVE":
            repo.add_history(incident_id, SYSTEM_ACTOR, None, None,
                             f"{added} new event(s) arrived on alert #{alert['alert_id']} after the "
                             "incident was marked FALSE_POSITIVE (status left unchanged)")
        repo.update_incident(incident_id, values)

    # -------------------------------------------------------------- lifecycle
    def update_status(self, incident_id: int, new_status: str, actor: str = "analyst",
                      note: str | None = None) -> None:
        """Change the status and record the change in incident_history."""
        if new_status not in INCIDENT_STATUSES:
            raise IncidentError(f"invalid status {new_status!r}; allowed: {', '.join(INCIDENT_STATUSES)}")
        incident = self.repo.get_incident(incident_id)
        if incident is None:
            raise IncidentError(f"incident {incident_id} not found")
        if incident["status"] == new_status:
            raise IncidentError(f"incident {incident_id} is already {new_status}")
        now = utc_now()
        closed_at = now if new_status not in OPEN_STATUSES else None
        self.repo.update_incident(incident_id, {"status": new_status, "updated_at": now,
                                                "closed_at": closed_at})
        self.repo.add_history(incident_id, _clean(actor, 100) or "analyst", incident["status"],
                              new_status, _clean(note, MAX_NOTE_LENGTH))

    def assign(self, incident_id: int, analyst: str | None, actor: str = "analyst") -> None:
        """Set (or clear, with None/empty) the analyst responsible for an incident."""
        incident = self.repo.get_incident(incident_id)
        if incident is None:
            raise IncidentError(f"incident {incident_id} not found")
        name = _clean(analyst, MAX_ANALYST_LENGTH)
        if name == incident["assigned_analyst"]:
            raise IncidentError(f"incident {incident_id} is already assigned to {name or 'nobody'}")
        self.repo.update_incident(incident_id, {"assigned_analyst": name, "updated_at": utc_now()})
        note = f"Assigned to {name}" if name else "Unassigned"
        if incident["assigned_analyst"]:
            note += f" (was {incident['assigned_analyst']})"
        self.repo.add_history(incident_id, _clean(actor, 100) or "analyst", None, None, note)

    def add_note(self, incident_id: int, note: str, author: str = "analyst") -> int:
        """Add an analyst note to an incident."""
        text = _clean(note, MAX_NOTE_LENGTH)
        if not text:
            raise IncidentError("note must not be empty")
        if self.repo.get_incident(incident_id) is None:
            raise IncidentError(f"incident {incident_id} not found")
        note_id = self.repo.add_note(incident_id, _clean(author, 100) or "analyst", text)
        self.repo.update_incident(incident_id, {"updated_at": utc_now()})
        return note_id

    # ------------------------------------------------------------------ views
    def details(self, incident_id: int, event_limit: int = 1000) -> dict[str, Any]:
        """Return the incident with linked alerts, events, history and notes."""
        incident = self.repo.get_incident(incident_id)
        if incident is None:
            raise IncidentError(f"incident {incident_id} not found")
        return {
            "incident": dict(incident),
            "alerts": [dict(r) for r in self.repo.incident_alerts(incident_id)],
            "events": [dict(r) for r in self.repo.incident_events(incident_id, event_limit)],
            "history": [dict(r) for r in self.repo.incident_history(incident_id)],
            "notes": [dict(r) for r in self.repo.incident_notes(incident_id)],
        }

    def timeline(self, incident_id: int, event_limit: int = 1000) -> list[dict[str, Any]]:
        """Chronological list of events, alerts, status changes and notes."""
        data = self.details(incident_id, event_limit)
        entries: list[dict[str, Any]] = []
        for event in data["events"]:
            entries.append({"time": event["timestamp_utc"], "kind": "event",
                            "summary": f"[{event['source_type']}] {event['action']}: {event['message']}",
                            "ref": event["event_id"]})
        for alert in data["alerts"]:
            entries.append({"time": alert["first_seen"], "kind": "alert",
                            "summary": f"{alert['rule_id']} {alert['rule_name']} (severity {alert['severity']})",
                            "ref": str(alert["alert_id"])})
        for item in data["history"]:
            change = (f"{item['old_status'] or '-'} -> {item['new_status']}" if item["new_status"]
                      else "note")
            entries.append({"time": item["changed_at"], "kind": "history",
                            "summary": f"{change} by {item['actor']}: {item['note'] or ''}".strip(),
                            "ref": str(item["history_id"])})
        for note in data["notes"]:
            entries.append({"time": note["created_at"], "kind": "analyst_note",
                            "summary": f"{note['author']}: {note['note']}", "ref": str(note["note_id"])})
        entries.sort(key=lambda entry: entry["time"])
        return entries


def _clean(value: str | None, max_len: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:max_len] if text else None
