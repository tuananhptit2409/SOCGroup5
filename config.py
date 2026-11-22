"""Centralized configuration for the SOC Analyst Toolkit.

All tunable values (database path, allowed input folders, rule thresholds)
live here. Values can be overridden by a JSON file (``config/settings.json``
or the file named by ``SOC_CONFIG_FILE``) and by environment variables
``SOC_DB_PATH`` / ``SOC_ALLOWED_INPUT_DIRS``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields, is_dataclass, replace
from pathlib import Path
from typing import Any, Mapping

PROJECT_ROOT = Path(__file__).resolve().parent


class ConfigError(Exception):
    """Raised when configuration is missing or invalid."""


@dataclass(frozen=True)
class SshBruteForceConfig:
    threshold: int = 5            # failed logins required
    window_seconds: int = 60      # ... within this many seconds
    followup_seconds: int = 60    # success/lockout within this many seconds after the burst (assignment: 60 s)
    require_followup: bool = False  # True = alert ONLY on failures followed by success/lockout (exact
                                    # wording of the assignment); False also reports the failure burst alone


@dataclass(frozen=True)
class PortScanConfig:
    threshold: int = 15           # distinct destination ports required
    window_seconds: int = 30
    internal_only: bool = True    # only consider RFC1918/loopback/link-local sources


@dataclass(frozen=True)
class SuspiciousProcessConfig:
    min_score: int = 2            # minimum indicator score that raises an alert
    dedup_window_seconds: int = 300
    trusted_parent_names: tuple[str, ...] = ("msiexec.exe", "trustedinstaller.exe", "tiworker.exe")
    allow_image_patterns: tuple[str, ...] = ()  # regexes of image paths that are never alerted


@dataclass(frozen=True)
class PivotConfig:
    window_seconds: int = 300           # internal connections up to this long AFTER the alert
    min_alert_severity: int = 4         # normalized severity; 4 = Suricata priority 1 ("high")
    min_internal_targets: int = 1       # distinct internal hosts the pivot IP must contact
    escalate_targets: int = 3           # reaching this many internal hosts -> CRITICAL
    ignore_dst_ports: tuple[int, ...] = (53, 123, 137, 138)   # DNS, NTP, NetBIOS name/datagram: not lateral


@dataclass(frozen=True)
class WebAttackConfig:
    error_threshold: int = 20           # số response lỗi 4xx từ một IP ...
    error_window_seconds: int = 60      # ... trong chừng này giây = đang dò thư mục / quét website
    group_gap_seconds: int = 300        # request cách nhau quá lâu thì tính là đợt tấn công mới
    min_probe_requests: int = 3         # số lần dò file nhạy cảm (/.env, /.git/ ...) mới báo (bot dò lẻ tẻ rất nhiều)


@dataclass(frozen=True)
class CorrelationConfig:
    incident_window_seconds: int = 1800  # alerts of the same entity this close join one incident
    alert_cooldown_seconds: int = 600    # same rule + same entity within this gap = one deduplicated alert


@dataclass(frozen=True)
class Settings:
    db_path: Path = PROJECT_ROOT / "data" / "soc.db"
    allowed_input_dirs: tuple[Path, ...] = (PROJECT_ROOT / "datasets",)
    reports_dir: Path = PROJECT_ROOT / "reports"
    max_line_length: int = 65536
    batch_size: int = 20000                  # lines per transaction (bigger = faster, more RAM)
    syslog_default_year: int | None = None   # None = infer from the current date
    syslog_utc_offset_minutes: int = 0       # timezone of syslog lines that carry no offset
    web_server_name: str | None = None       # host name given to web access log lines (the log has none)
    log_level: str = "INFO"
    ssh_bruteforce: SshBruteForceConfig = field(default_factory=SshBruteForceConfig)
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    suspicious_process: SuspiciousProcessConfig = field(default_factory=SuspiciousProcessConfig)
    pivot: PivotConfig = field(default_factory=PivotConfig)
    web_attack: WebAttackConfig = field(default_factory=WebAttackConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)


def _to_path(value: Any) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise ConfigError(f"expected a path, got {value!r}")
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def _coerce(name: str, current: Any, value: Any) -> Any:
    if isinstance(current, Path):
        return _to_path(value)
    if name == "allowed_input_dirs":
        if not isinstance(value, (list, tuple)):
            raise ConfigError("allowed_input_dirs must be a list of paths")
        return tuple(_to_path(v) for v in value)
    if name.endswith("_ports"):
        if not isinstance(value, (list, tuple)) or not all(
                isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 65535 for v in value):
            raise ConfigError(f"{name} must be a list of port numbers (0-65535)")
        return tuple(value)
    if isinstance(current, tuple):
        if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{name} must be a list of strings")
        return tuple(value)
    if isinstance(current, bool):
        if not isinstance(value, bool):
            raise ConfigError(f"{name} must be true/false")
        return value
    if isinstance(current, int) or (current is None and name == "syslog_default_year"):
        if value is None and current is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{name} must be an integer")
        return value
    if name == "web_server_name":
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ConfigError("web_server_name must be a non-empty string or null")
        return value.strip()[:255] if value else None
    if isinstance(current, str):
        if not isinstance(value, str):
            raise ConfigError(f"{name} must be a string")
        return value
    return value


def apply_overrides(obj: Any, data: Mapping[str, Any]) -> Any:
    """Return a copy of dataclass ``obj`` with ``data`` applied (recursively)."""
    if not isinstance(data, Mapping):
        raise ConfigError("configuration must be a JSON object")
    known = {f.name for f in fields(obj)}
    changes: dict[str, Any] = {}
    for key, value in data.items():
        if key not in known:
            raise ConfigError(f"unknown configuration key: {key}")
        current = getattr(obj, key)
        if is_dataclass(current):
            changes[key] = apply_overrides(current, value)
        else:
            changes[key] = _coerce(key, current, value)
    return replace(obj, **changes)


def validate(settings: Settings) -> None:
    checks = {
        "max_line_length": settings.max_line_length,
        "batch_size": settings.batch_size,
        "ssh_bruteforce.threshold": settings.ssh_bruteforce.threshold,
        "ssh_bruteforce.window_seconds": settings.ssh_bruteforce.window_seconds,
        "port_scan.threshold": settings.port_scan.threshold,
        "port_scan.window_seconds": settings.port_scan.window_seconds,
        "suspicious_process.min_score": settings.suspicious_process.min_score,
        "pivot.window_seconds": settings.pivot.window_seconds,
        "pivot.min_internal_targets": settings.pivot.min_internal_targets,
        "pivot.escalate_targets": settings.pivot.escalate_targets,
        "web_attack.error_threshold": settings.web_attack.error_threshold,
        "web_attack.error_window_seconds": settings.web_attack.error_window_seconds,
        "web_attack.group_gap_seconds": settings.web_attack.group_gap_seconds,
        "web_attack.min_probe_requests": settings.web_attack.min_probe_requests,
        "correlation.incident_window_seconds": settings.correlation.incident_window_seconds,
        "correlation.alert_cooldown_seconds": settings.correlation.alert_cooldown_seconds,
    }
    for name, value in checks.items():
        if value < 1:
            raise ConfigError(f"{name} must be >= 1 (got {value})")
    if not 1 <= settings.pivot.min_alert_severity <= 5:
        raise ConfigError("pivot.min_alert_severity must be between 1 and 5")
    if not -840 <= settings.syslog_utc_offset_minutes <= 840:
        raise ConfigError("syslog_utc_offset_minutes out of range")


def load_settings(config_file: str | Path | None = None,
                  env: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from defaults, an optional JSON file and environment variables."""
    env = os.environ if env is None else env
    settings = Settings()
    explicit = config_file or env.get("SOC_CONFIG_FILE")
    path = Path(explicit) if explicit else PROJECT_ROOT / "config" / "settings.json"
    if explicit and not path.is_file():
        raise ConfigError(f"configuration file not found: {path}")
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read configuration file {path}: {exc}") from exc
        settings = apply_overrides(settings, data)
    if env.get("SOC_DB_PATH"):
        settings = replace(settings, db_path=_to_path(env["SOC_DB_PATH"]))
    if env.get("SOC_ALLOWED_INPUT_DIRS"):
        dirs = tuple(_to_path(p) for p in env["SOC_ALLOWED_INPUT_DIRS"].split(os.pathsep) if p)
        settings = replace(settings, allowed_input_dirs=dirs)
    validate(settings)
    return settings
