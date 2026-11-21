"""Incident investigation report (Markdown)."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from engine.incident_manager import IncidentManager
from storage.database import utc_now

from storage.models import SEVERITY_LABELS, STATUS_LABELS  # noqa: E402  (re-exported for ui.data_access)
MAX_REPORT_EVENTS = 200


def _cell(value: Any) -> str:
    """Make a value safe for a Markdown table cell (log data is attacker-controlled)."""
    text = "" if value is None else str(value)
    for char in ("|", "`", "<", ">", "[", "]", "*", "_"):
        text = text.replace(char, "\\" + char)
    return text.replace("\r", " ").replace("\n", " ")[:300]


def _code_block(text: str) -> str:
    return "```text\n" + text.replace("```", "'''") + "\n```"


def build_incident_report(conn: sqlite3.Connection, incident_id: int) -> str:
    """Return a Markdown report for one incident (raises IncidentError if unknown)."""
    manager = IncidentManager(conn)
    data = manager.details(incident_id, event_limit=MAX_REPORT_EVENTS)
    incident = data["incident"]
    lines = [
        f"# Incident Report #{incident['incident_id']}",
        "",
        f"Generated: {utc_now()} (SOC Analyst Toolkit, academic simulation)",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Title | {_cell(incident['title'])} |",
        f"| Status | {STATUS_LABELS.get(incident['status'], incident['status'])} |",
        f"| Assigned analyst | {_cell(incident['assigned_analyst']) or '(unassigned)'} |",
        f"| Severity | {incident['severity']} ({SEVERITY_LABELS.get(incident['severity'], '?')}) |",
        f"| Detection rule | {_cell(incident['rule_id'])} |",
        f"| Source IP | {_cell(incident['src_ip'])} |",
        f"| Destination IP | {_cell(incident['dst_ip'])} |",
        f"| Affected asset | {_cell(incident['affected_asset'])} |",
        f"| First seen (UTC) | {incident['first_seen']} |",
        f"| Last seen (UTC) | {incident['last_seen']} |",
        f"| Created | {incident['created_at']} |",
        f"| Updated | {incident['updated_at']} |",
        f"| Linked alerts | {len(data['alerts'])} |",
        f"| Raw detections merged | {sum(int(a['occurrence_count']) for a in data['alerts'])} |",
        f"| Occurrence count | {incident['occurrence_count']} |",
        "",
        "## Description",
        "",
        _code_block(incident["description"]),
        "",
        "## Linked alerts",
        "",
    ]
    for alert in data["alerts"]:
        lines += [
            f"### Alert #{alert['alert_id']} — {_cell(alert['rule_id'])} {_cell(alert['rule_name'])}",
            "",
            f"- Severity: {alert['severity']} ({SEVERITY_LABELS.get(alert['severity'], '?')})",
            f"- Time range (UTC): {alert['first_seen']} to {alert['last_seen']}",
            f"- Events: {alert['event_count']}; raw detections merged (occurrences): {alert['occurrence_count']}",
            f"- MITRE ATT&CK: {_cell(alert['mitre'])}",
            "",
            "Rationale:",
            "",
            _code_block(alert["rationale"]),
            "",
            "Evidence:",
            "",
            "```json",
            json.dumps(json.loads(alert["evidence"]), indent=2, ensure_ascii=False).replace("```", "'''"),
            "```",
            "",
        ]
    lines += ["## Timeline", "", "| Time (UTC) | Kind | Summary |", "|---|---|---|"]
    for entry in manager.timeline(incident_id, event_limit=MAX_REPORT_EVENTS):
        lines.append(f"| {entry['time']} | {entry['kind']} | {_cell(entry['summary'])} |")
    lines += ["", f"## Raw log evidence (first {MAX_REPORT_EVENTS} events)", ""]
    raw = "\n".join(str(event["raw_line"])[:2000] for event in data["events"])
    lines.append(_code_block(raw or "(no events)"))
    lines += ["", "## Analyst notes", ""]
    if data["notes"]:
        for note in data["notes"]:
            lines.append(f"- {note['created_at']} — {_cell(note['author'])}: {_cell(note['note'])}")
    else:
        lines.append("(none)")
    lines += ["", "## Status history", "", "| Time (UTC) | Actor | Change | Note |", "|---|---|---|---|"]
    for item in data["history"]:
        change = f"{item['old_status'] or '-'} -> {item['new_status']}" if item["new_status"] else "-"
        lines.append(f"| {item['changed_at']} | {_cell(item['actor'])} | {change} | {_cell(item['note'])} |")
    return "\n".join(lines) + "\n"
