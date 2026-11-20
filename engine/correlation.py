"""Chống trùng cảnh báo (deduplication): biến Detection thành Alert.

Thuật ngữ:
  * detection (phát hiện thô) - một lần rule bắt được, ví dụ một đợt brute force.
    Mỗi lần chạy detect, rule quét lại TOÀN BỘ event, nên danh sách detection
    của lần chạy mới nhất luôn đầy đủ.
  * alert - thứ analyst nhìn thấy. Các detection CÙNG rule, CÙNG thực thể
    (entity_key) mà chồng lên nhau về thời gian, hoặc cách nhau không quá
    `alert_cooldown_seconds` (600 giây), được gộp vào MỘT alert;
    occurrence_count = số detection đã gộp.
  * duplicate - cùng một detection gặp lại khi chạy detect lần nữa: không ghi gì.

Ngoại lệ: nếu incident của alert cũ đã CLOSED / FALSE_POSITIVE thì đợt tấn công
mới (không chồng thời gian) tạo alert mới, không nhập vào alert đã đóng.

Cách dùng (xem pipeline.run_detection):
    manager = AlertManager(conn, config)
    for detection in detections:
        alert_id, outcome = manager.persist(detection)   # "new" / "updated" / "duplicate"
    manager.finalize()                                    # ghi occurrence_count
"""
import hashlib
import json
import sqlite3

from config import CorrelationConfig
from engine.rules.base import Detection
from normalizer.models import epoch_to_iso
from storage.database import utc_now
from storage.models import CLOSED_STATUSES
from storage.repository import Repository

MAX_OCCURRENCES_IN_EVIDENCE = 50


def alert_fingerprint(rule_id: str, entity_key: str, first_ts: float) -> str:
    """Mã định danh của alert: băm (rule + thực thể + thời điểm bắt đầu)."""
    text = f"{rule_id}|{entity_key}|{first_ts:.6f}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def count_unique_events(detection: Detection) -> int:
    return len({event_id for event_id, _role in detection.events})


class AlertManager:
    """Lưu detection thành alert, không tạo bản trùng khi chạy lại."""

    def __init__(self, conn: sqlite3.Connection, config: CorrelationConfig | None = None) -> None:
        self.repo = Repository(conn)
        self.config = config or CorrelationConfig()
        # alert_id -> các detection thuộc alert đó trong lần chạy này (dùng ở finalize)
        self.detections_by_alert: dict[int, list[Detection]] = {}

    # ------------------------------------------------------------ bước 1: persist
    def persist(self, detection: Detection) -> tuple[int, str]:
        """Ghi một detection. Trả về (alert_id, "new" | "updated" | "duplicate")."""
        existing = self._find_existing_alerts(detection)
        if not existing:
            alert_id = self._create_alert(detection)
            self._remember(alert_id, detection)
            return alert_id, "new"
        return self._merge_into(existing, detection)

    def _find_existing_alerts(self, detection: Detection) -> list[sqlite3.Row]:
        """Các alert cùng rule + thực thể mà detection này thuộc về.

        Một alert được chọn khi nó chồng thời gian với detection, hoặc nằm trong
        khoảng cooldown và incident của nó chưa bị đóng.
        """
        cooldown = self.config.alert_cooldown_seconds
        nearby = self.repo.find_alerts_near(detection.rule_id, detection.entity_key,
                                            detection.first_ts - cooldown, detection.last_ts + cooldown)
        chosen = []
        for alert in nearby:
            overlaps = alert["first_ts"] <= detection.last_ts and alert["last_ts"] >= detection.first_ts
            still_open = alert["incident_status"] not in CLOSED_STATUSES
            if overlaps or still_open:
                chosen.append(alert)
        return chosen

    def _create_alert(self, detection: Detection) -> int:
        now = utc_now()
        alert_id = self.repo.insert_alert({
            "fingerprint": alert_fingerprint(detection.rule_id, detection.entity_key, detection.first_ts),
            "rule_id": detection.rule_id,
            "rule_name": detection.rule_name,
            "severity": detection.severity,
            "entity_key": detection.entity_key,
            "src_ip": detection.src_ip,
            "dst_ip": detection.dst_ip,
            "hostname": detection.hostname,
            "username": detection.username,
            "first_seen": epoch_to_iso(detection.first_ts),
            "last_seen": epoch_to_iso(detection.last_ts),
            "first_ts": detection.first_ts,
            "last_ts": detection.last_ts,
            "event_count": count_unique_events(detection),
            "occurrence_count": 1,
            "evidence": json.dumps(detection.evidence, ensure_ascii=False, sort_keys=True),
            "rationale": detection.rationale,
            "mitre": detection.mitre,
            "created_at": now,
            "updated_at": now,
        })
        self.repo.link_alert_events(alert_id, detection.events)
        return alert_id

    def _merge_into(self, existing: list[sqlite3.Row], detection: Detection) -> tuple[int, str]:
        """Nhập detection vào alert đã có (alert đầu tiên trong danh sách)."""
        primary = existing[0]
        alert_id = int(primary["alert_id"])

        # Hiếm gặp: detection nối liền hai alert cũ -> gộp các alert đó lại làm một.
        for other in existing[1:]:
            other_id = int(other["alert_id"])
            self.repo.merge_alert_into(other_id, alert_id)
            moved = self.detections_by_alert.pop(other_id, [])
            self.detections_by_alert.setdefault(alert_id, []).extend(moved)
        self._remember(alert_id, detection)

        events_before = self.repo.count_alert_events(alert_id)
        self.repo.link_alert_events(alert_id, detection.events)
        events_after = self.repo.count_alert_events(alert_id)

        # Khoảng thời gian và severity mới = bao trùm tất cả.
        first_ts = detection.first_ts
        last_ts = detection.last_ts
        severity = detection.severity
        for alert in existing:
            first_ts = min(first_ts, alert["first_ts"])
            last_ts = max(last_ts, alert["last_ts"])
            severity = max(severity, alert["severity"])

        changed = (events_after != events_before
                   or len(existing) > 1
                   or severity != primary["severity"]
                   or first_ts != primary["first_ts"]
                   or last_ts != primary["last_ts"])
        if not changed:
            return alert_id, "duplicate"             # không có gì mới

        self.repo.update_alert(alert_id, {
            "fingerprint": alert_fingerprint(detection.rule_id, detection.entity_key, first_ts),
            "severity": severity,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "first_seen": epoch_to_iso(first_ts),
            "last_seen": epoch_to_iso(last_ts),
            "event_count": events_after,
            "updated_at": utc_now(),
        })
        return alert_id, "updated"

    def _remember(self, alert_id: int, detection: Detection) -> None:
        self.detections_by_alert.setdefault(alert_id, []).append(detection)

    # ----------------------------------------------------------- bước 2: finalize
    def finalize(self) -> int:
        """Ghi occurrence_count, evidence và lời giải thích cho mọi alert của lần chạy này.

        Gọi MỘT lần sau khi persist hết detection. Giá trị được GÁN (không cộng
        dồn) nên chạy lại bao nhiêu lần cũng cho cùng kết quả.
        Trả về tổng số detection thô (dùng cho chỉ số giảm nhiễu).
        """
        total = 0
        for alert_id, detections in self.detections_by_alert.items():
            if self.repo.get_alert(alert_id) is None:     # alert đã bị gộp vào alert khác
                continue
            occurrences = _unique_sorted(detections)
            total += len(occurrences)

            # Detection nặng nhất làm "đại diện" cho alert.
            lead = occurrences[0]
            for detection in occurrences:
                if (detection.severity, detection.first_ts) > (lead.severity, lead.first_ts):
                    lead = detection
            evidence = dict(lead.evidence)
            rationale = lead.rationale
            if len(occurrences) > 1:
                evidence["occurrences"] = [_occurrence_info(d) for d in occurrences[:MAX_OCCURRENCES_IN_EVIDENCE]]
                rationale = (f"{len(occurrences)} occurrences of this activity within the "
                             f"{self.config.alert_cooldown_seconds}s deduplication cooldown; "
                             f"most severe: {lead.rationale}")
            self.repo.update_alert(alert_id, {
                "occurrence_count": len(occurrences),
                "rationale": rationale,
                "evidence": json.dumps(evidence, ensure_ascii=False, sort_keys=True),
            })
        return total


def _unique_sorted(detections: list[Detection]) -> list[Detection]:
    """Bỏ detection trùng (cùng thời gian, cùng event) rồi sắp theo thời gian."""
    unique: dict[tuple, Detection] = {}
    for detection in detections:
        event_ids = tuple(sorted(event_id for event_id, _role in detection.events))
        unique[(detection.first_ts, detection.last_ts, event_ids)] = detection
    return sorted(unique.values(), key=lambda d: (d.first_ts, d.last_ts))


def _occurrence_info(detection: Detection) -> dict:
    return {"first_seen": epoch_to_iso(detection.first_ts), "last_seen": epoch_to_iso(detection.last_ts),
            "events": count_unique_events(detection), "severity": detection.severity}
