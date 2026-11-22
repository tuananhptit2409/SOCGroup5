"""Luồng xử lý chính của toolkit.

  ingest_file():   file log -> parse -> normalize -> lưu (raw_events, events)
  run_detection(): events -> 4 rule -> detection -> alert (chống trùng) -> incident

main.py (dòng lệnh) và dashboard đều chỉ gọi hai hàm này.
"""
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from config import Settings
from engine.correlation import AlertManager
from engine.incident_manager import IncidentManager
from engine.rule_engine import RuleEngine, build_default_rules
from ingestors import linux_auth, suricata, sysmon, web_access
from ingestors.base import LineRecord, ParseError, iter_lines, resolve_input_path
from normalizer import linux_normalizer, suricata_normalizer, sysmon_normalizer, web_normalizer
from normalizer.models import NormalizationError, NormalizeContext, UnifiedEvent
from storage.database import Database, DatabaseError
from storage.repository import Repository

logger = logging.getLogger(__name__)

SOURCES: dict[str, tuple[Callable[[str], dict[str, Any]], Callable[..., UnifiedEvent]]] = {
    linux_auth.SOURCE_TYPE: (linux_auth.parse_line, linux_normalizer.normalize),
    suricata.SOURCE_TYPE: (suricata.parse_line, suricata_normalizer.normalize),
    sysmon.SOURCE_TYPE: (sysmon.parse_line, sysmon_normalizer.normalize),
    web_access.SOURCE_TYPE: (web_access.parse_line, web_normalizer.normalize),
}


class PipelineError(Exception):
    """Invalid pipeline request (for example an unknown source type)."""


@dataclass
class IngestResult:
    source_type: str
    file_path: str
    batch_id: int = 0
    total_lines: int = 0
    blank_lines: int = 0
    parsed_ok: int = 0          # lines of this file that normalized successfully
    rejected: int = 0           # lines of this file that were rejected
    new_events: int = 0         # events actually added to the database
    new_rejected: int = 0       # rejected raw lines actually added to the database
    duplicates: int = 0         # lines already stored earlier (or repeated in the file)
    reject_reasons: dict[str, int] = field(default_factory=dict)
    seconds_parse: float = 0.0
    seconds_normalize: float = 0.0
    seconds_database: float = 0.0
    seconds_total: float = 0.0
    end_offset: int = 0          # vị trí đã đọc tới (byte); chế độ watch đọc tiếp từ đây


@dataclass
class DetectionSummary:
    detections: int = 0
    per_rule: dict[str, int] = field(default_factory=dict)
    alerts_new: int = 0
    alerts_updated: int = 0
    alerts_duplicate: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0
    raw_detections: int = 0
    dedup: dict[str, Any] = field(default_factory=dict)
    rule_errors: dict[str, str] = field(default_factory=dict)
    seconds_detection: float = 0.0
    seconds_correlation: float = 0.0
    seconds_per_rule: dict[str, float] = field(default_factory=dict)


def raw_id_for(source_type: str, line: str) -> str:
    """Mã của một dòng log = băm (nguồn + nội dung). Nhập lại cùng file sẽ không bị trùng."""
    text = f"{source_type}\n{line}"
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:32]


@dataclass
class ParsedLine:
    """Kết quả bước 1 (parse) cho một dòng."""
    record: LineRecord
    raw_id: str
    fields: dict[str, Any] | None      # các trường đọc được; None nếu lỗi
    error: str | None                  # lý do lỗi; None nếu đọc được


def ingest_file(db: Database, settings: Settings, source_type: str, path: str | Path,
                now: datetime | None = None, start_offset: int = 0,
                complete_lines_only: bool = False) -> IngestResult:
    """Nhập một file log: đọc từng dòng -> parse -> normalize -> lưu vào database.

    - Dòng lỗi KHÔNG làm dừng chương trình: nó được lưu vào raw_events với
      trạng thái 'rejected' và lý do.
    - Đọc theo lô (batch_size dòng / lô) để không phải nạp cả file vào RAM.
    - Nhập lại cùng nội dung không thêm gì (raw_id là khóa chính).
    - start_offset / complete_lines_only dùng cho chế độ watch: chỉ đọc phần mới
      của file, và chưa nhận dòng cuối nếu nó chưa ghi xong (chưa có xuống dòng).
    """
    if source_type not in SOURCES:
        raise PipelineError(f"unknown source type {source_type!r}; expected one of {', '.join(SOURCES)}")
    resolved = resolve_input_path(path, settings.allowed_input_dirs)   # chặn đọc file ngoài thư mục cho phép
    ctx = NormalizeContext(now=now or datetime.now(timezone.utc),
                           syslog_default_year=settings.syslog_default_year,
                           syslog_utc_offset_minutes=settings.syslog_utc_offset_minutes,
                           web_server_name=settings.web_server_name)
    result = IngestResult(source_type=source_type, file_path=str(resolved), end_offset=start_offset)
    started = time.perf_counter()
    with db.transaction() as conn:
        result.batch_id = Repository(conn).create_batch(source_type, str(resolved))

    try:
        batch: list[LineRecord] = []
        for record in iter_lines(resolved, settings.max_line_length, start_offset):
            if complete_lines_only and not record.complete:
                break                                # dòng đang được ghi dở: để vòng sau đọc
            result.total_lines += 1
            result.end_offset = record.end_offset
            if not record.text.strip() and not record.too_long:
                result.blank_lines += 1          # bỏ qua dòng trống
                continue
            batch.append(record)
            if len(batch) >= settings.batch_size:
                _process_batch(db, source_type, batch, ctx, result)
                batch = []
        if batch:
            _process_batch(db, source_type, batch, ctx, result)
    except Exception as exc:
        logger.error("event=ingest_failed source=%s file=%s error=%s", source_type, resolved.name, exc)
        _finish_batch(db, result, "failed", error=str(exc)[:300])
        raise

    result.seconds_total = time.perf_counter() - started
    with db.transaction() as conn:
        Repository(conn).reconcile_raw_status()
    _finish_batch(db, result, "completed")
    logger.info("event=ingest_completed source=%s file=%s lines=%d new_events=%d rejected=%d "
                "duplicates=%d seconds=%.3f", source_type, resolved.name, result.total_lines,
                result.new_events, result.rejected, result.duplicates, result.seconds_total)
    return result


def _process_batch(db: Database, source_type: str, batch: list[LineRecord], ctx: NormalizeContext,
                   result: IngestResult) -> None:
    """Xử lý một lô dòng: parse, normalize, rồi ghi vào database trong một transaction."""
    parse_line, normalize = SOURCES[source_type]

    t0 = time.perf_counter()
    parsed = [_parse_one(source_type, parse_line, record) for record in batch]       # bước 1

    t1 = time.perf_counter()
    raw_rows = []          # mọi dòng (accepted / rejected) -> bảng raw_events
    events = []            # dòng hợp lệ đã chuẩn hóa -> bảng events
    for item in parsed:                                                                 # bước 2
        error = item.error
        if item.fields is not None:
            event, error = _normalize_one(source_type, normalize, item, ctx)
            if event is not None:
                events.append(event)
        status = "accepted" if error is None else "rejected"
        if error is None:
            result.parsed_ok += 1
        else:
            result.rejected += 1
            reason = error.split(":", 1)[0]                      # "invalid_ip: src_ip=..." -> "invalid_ip"
            result.reject_reasons[reason] = result.reject_reasons.get(reason, 0) + 1
            error = error[:300]
        raw_rows.append((item.raw_id, result.batch_id, source_type, item.record.line_no,
                         item.record.text, status, error))

    t2 = time.perf_counter()
    with db.transaction() as conn:                                                      # bước 3
        repo = Repository(conn)
        new_raw = repo.insert_raw_events(raw_rows)
        new_events = repo.insert_events(events)
    result.new_events += new_events
    result.new_rejected += max(0, new_raw - new_events)
    result.duplicates += len(raw_rows) - new_raw
    result.seconds_parse += t1 - t0
    result.seconds_normalize += t2 - t1
    result.seconds_database += time.perf_counter() - t2


def _parse_one(source_type: str, parse_line: Callable, record: LineRecord) -> ParsedLine:
    """Bước 1: tách dòng log thành các trường thô. Lỗi chỉ loại bỏ dòng này."""
    raw_id = raw_id_for(source_type, record.text)
    if record.too_long:
        return ParsedLine(record, raw_id, None, "line_too_long")
    try:
        return ParsedLine(record, raw_id, parse_line(record.text), None)
    except ParseError as exc:
        return ParsedLine(record, raw_id, None, str(exc))
    except Exception as exc:          # lỗi lập trình trong parser cũng không được làm dừng việc nhập
        logger.warning("event=unexpected_parse_error source=%s line=%d error=%s",
                       source_type, record.line_no, type(exc).__name__)
        return ParsedLine(record, raw_id, None, f"unexpected_error: {type(exc).__name__}")


def _normalize_one(source_type: str, normalize: Callable, item: ParsedLine,
                   ctx: NormalizeContext) -> tuple[UnifiedEvent | None, str | None]:
    """Bước 2: chuyển các trường thô thành UnifiedEvent. Trả về (event, lỗi)."""
    try:
        return normalize(item.fields, item.record.text, item.raw_id, ctx), None
    except NormalizationError as exc:
        return None, str(exc)
    except Exception as exc:          # như trên, cho normalizer
        logger.warning("event=unexpected_normalize_error source=%s line=%d error=%s",
                       source_type, item.record.line_no, type(exc).__name__)
        return None, f"unexpected_error: {type(exc).__name__}"


def _finish_batch(db: Database, result: IngestResult, status: str, error: str | None = None) -> None:
    """Ghi trạng thái cuối của lần nhập vào bảng import_batches."""
    try:
        with db.transaction() as conn:
            Repository(conn).finish_batch(result.batch_id, status, total_lines=result.total_lines,
                                          blank_lines=result.blank_lines, new_events=result.new_events,
                                          new_rejected=result.new_rejected, duplicates=result.duplicates,
                                          error=error)
    except DatabaseError as exc:
        if status != "failed":
            raise
        # Đang xử lý một lỗi khác: giữ lỗi gốc, chỉ ghi log việc không lưu được trạng thái.
        logger.error("event=batch_status_not_saved batch_id=%d error=%s", result.batch_id, exc)


def run_detection(db: Database, settings: Settings) -> DetectionSummary:
    """Run all rules over the stored events, then deduplicate alerts and sync incidents.

    Everything happens in one transaction, so a failure leaves alerts and
    incidents exactly as they were. Running it again on unchanged data creates
    no new alerts or incidents.
    """
    summary = DetectionSummary()
    with db.transaction() as conn:
        started = time.perf_counter()
        engine_result = RuleEngine(build_default_rules(settings)).run(conn)
        summary.seconds_detection = time.perf_counter() - started
        summary.detections = len(engine_result.detections)
        summary.per_rule = engine_result.per_rule
        summary.rule_errors = engine_result.errors
        summary.seconds_per_rule = engine_result.seconds_per_rule

        started = time.perf_counter()
        alerts = AlertManager(conn, settings.correlation)
        incidents = IncidentManager(conn, settings.correlation)
        for detection in sorted(engine_result.detections, key=lambda d: (d.first_ts, d.rule_id, d.entity_key)):
            alert_id, outcome = alerts.persist(detection)
            if outcome == "new":
                summary.alerts_new += 1
            elif outcome == "updated":
                summary.alerts_updated += 1
            else:
                summary.alerts_duplicate += 1
            _incident_id, action = incidents.sync_alert(alert_id, outcome)
            if action == "created":
                summary.incidents_created += 1
            elif action in ("linked", "updated"):
                summary.incidents_updated += 1
        summary.raw_detections = alerts.finalize()
        summary.dedup = Repository(conn).dedup_summary().to_dict()
        summary.seconds_correlation = time.perf_counter() - started
    logger.info("event=detection_completed detections=%d alerts_new=%d alerts_updated=%d "
                "alerts_duplicate=%d incidents_created=%d reduction_percent=%s", summary.detections,
                summary.alerts_new, summary.alerts_updated, summary.alerts_duplicate,
                summary.incidents_created, summary.dedup.get("reduction_percent"))
    return summary


def watch_files(db: Database, settings: Settings, inputs: list[tuple[str, Path]], interval: float,
                cycles: int = 0, report: Callable[[dict[str, Any]], None] = print,
                sleep: Callable[[float], None] = time.sleep) -> int:
    """Theo dõi liên tục: cứ `interval` giây lại nhập các file log rồi chạy detection.

    inputs = [(loại nguồn, đường dẫn file), ...], ví dụ [("linux_auth", Path("/var/log/auth.log"))].
    Mỗi vòng chỉ đọc phần được ghi thêm từ vòng trước (nhớ vị trí byte đã đọc).
    Khởi động lại thì đọc lại từ đầu, nhưng dòng đã nhập bị bỏ qua nhờ raw_id.
    Một file lỗi (chưa có, đang bị xoay vòng log ...) chỉ được
    ghi lại trong báo cáo của vòng đó, vòng sau thử lại.
    cycles = 0 nghĩa là chạy mãi (dừng bằng Ctrl+C). Trả về số vòng đã chạy.
    """
    offsets: dict[Path, int] = {}         # file -> vị trí đã đọc tới
    done = 0
    while cycles == 0 or done < cycles:
        done += 1
        cycle: dict[str, Any] = {"cycle": done, "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                 "new_events": 0, "errors": []}
        for source_type, path in inputs:
            try:
                start = offsets.get(path, 0)
                if path.is_file() and path.stat().st_size < start:
                    start = 0                    # file bị xoay vòng (logrotate) hoặc bị làm rỗng: đọc lại từ đầu
                result = ingest_file(db, settings, source_type, path, start_offset=start,
                                     complete_lines_only=True)
                offsets[path] = result.end_offset
                cycle["new_events"] += result.new_events
            except Exception as exc:     # InputPathError, file đang bị ghi đè ...: thử lại ở vòng sau
                cycle["errors"].append(f"{source_type} {path}: {exc}")
        if cycle["new_events"]:
            summary = run_detection(db, settings)          # chỉ chạy rule khi có dữ liệu mới
            cycle.update(alerts_new=summary.alerts_new, alerts_updated=summary.alerts_updated,
                         incidents_created=summary.incidents_created)
        report(cycle)
        if cycles == 0 or done < cycles:
            sleep(interval)
    return done
