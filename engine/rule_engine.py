"""Rule engine: chạy lần lượt các rule (4 rule của đề + SOC-005 cho website) và gom các Detection.

Một rule bị lỗi chỉ được ghi log, các rule khác vẫn chạy.
Muốn thêm rule mới: viết lớp con của Rule rồi thêm vào build_default_rules().
"""
from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Sequence

from config import Settings
from engine.rules.base import Detection, Rule
from engine.rules.network_host_pivot import NetworkHostPivotRule
from engine.rules.port_scan import PortScanRule
from engine.rules.ssh_bruteforce import SshBruteForceRule
from engine.rules.suspicious_process import SuspiciousProcessRule
from engine.rules.web_attack import WebAttackRule

logger = logging.getLogger(__name__)


@dataclass
class EngineResult:
    detections: list[Detection] = field(default_factory=list)
    per_rule: dict[str, int] = field(default_factory=dict)
    seconds_per_rule: dict[str, float] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def build_default_rules(settings: Settings) -> list[Rule]:
    """The rule registry. Add a new rule by appending its instance here."""
    return [
        SshBruteForceRule(settings.ssh_bruteforce),
        PortScanRule(settings.port_scan),
        SuspiciousProcessRule(settings.suspicious_process),
        NetworkHostPivotRule(settings.pivot),
        WebAttackRule(settings.web_attack),          # rule thêm cho website (ngoài 4 rule của đề)
    ]


class RuleEngine:
    """Runs rules one by one; a failing rule is logged and does not stop the others."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        ids = [rule.rule_id for rule in rules]
        if len(ids) != len(set(ids)) or not all(ids):
            raise ValueError("rule ids must be unique and non-empty")
        self.rules = list(rules)

    def run(self, conn: sqlite3.Connection) -> EngineResult:
        result = EngineResult()
        for rule in self.rules:
            started = time.perf_counter()
            try:
                found = list(rule.detect(conn))
            except Exception as exc:  # one broken rule must not hide the others' results
                logger.exception("event=rule_failed rule_id=%s", rule.rule_id)
                result.errors[rule.rule_id] = f"{type(exc).__name__}: {exc}"
                found = []
            result.seconds_per_rule[rule.rule_id] = time.perf_counter() - started
            result.per_rule[rule.rule_id] = len(found)
            result.detections.extend(found)
            logger.info("event=rule_finished rule_id=%s detections=%d seconds=%.3f",
                        rule.rule_id, len(found), result.seconds_per_rule[rule.rule_id])
        return result
