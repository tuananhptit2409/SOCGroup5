"""Mutation fuzzing of the parsers, normalizers and the whole ingest pipeline.

Usage:
    python -m benchmarks.fuzz_test                       # 20,000 mutations per source + pipeline run
    python -m benchmarks.fuzz_test --iterations 100000 --seed 7

Takes valid lines from datasets/raw, mutates them (random text edits and
JSON-aware edits with odd values such as NaN, Infinity, lone surrogates,
huge numbers, nested structures) and checks that:
  * parse_line + normalize only ever raise ParseError / NormalizationError,
  * no single call is slow (regex backtracking),
  * importing whole files of mutated lines always completes, detection runs
    without rule errors, and the database passes integrity checks.
This found AUD-08 (NaN/Infinity) and AUD-09 (lone surrogates); see docs/BUG_FIX_LOG.md.
"""
from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
import tempfile
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import Settings  # noqa: E402
from engine.rules.suspicious_process import SuspiciousProcessRule  # noqa: E402
from engine.rules.web_attack import classify_request  # noqa: E402
from ingestors import linux_auth, suricata, sysmon, web_access  # noqa: E402
from ingestors.base import ParseError  # noqa: E402
from normalizer import linux_normalizer, suricata_normalizer, sysmon_normalizer, web_normalizer  # noqa: E402
from normalizer.models import NormalizationError, NormalizeContext  # noqa: E402
from pipeline import ingest_file, run_detection  # noqa: E402
from storage.database import Database  # noqa: E402

SOURCES = {
    "linux_auth": (linux_auth.parse_line, linux_normalizer.normalize, "linux_auth.log"),
    "suricata": (suricata.parse_line, suricata_normalizer.normalize, "suricata_eve.jsonl"),
    "sysmon": (sysmon.parse_line, sysmon_normalizer.normalize, "sysmon.jsonl"),
    "web_access": (web_access.parse_line, web_normalizer.normalize, "web_access.log"),
}
WEIRD = [None, True, False, 0, -1, 1.5, 2 ** 64, -2 ** 63, 1e308, float("nan"), float("inf"), "", " ", "-", "\x00",
         "\u202e", "999.999.999.999", "::ffff:10.0.0.1", "1" * 400, [], [1, 2], {}, {"a": {"b": [None]}},
         "2026-02-30T00:00:00Z", "9999-12-31T23:59:59Z", "0001-01-01T00:00:00Z", "NaN", "1e999", "' OR 1=1 --",
         "\ud800", "x\udc00y"]
SLOW_SECONDS = 0.2
RESULTS_DIR = Path(__file__).resolve().parent / "results"


class Mutator:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)

    def text(self, line: str) -> str:
        chars = list(line)
        for _ in range(self.rng.randint(1, 6)):
            op, i = self.rng.random(), self.rng.randrange(len(chars) + 1)
            if op < 0.25 and chars:
                del chars[min(i, len(chars) - 1)]
            elif op < 0.5:
                chars.insert(i, self.rng.choice(" :[]{}\",.\\/\n\r\t0123456789abcfF\x00ÿ😀"))
            elif op < 0.7 and chars:
                chars[min(i, len(chars) - 1)] = chr(self.rng.randrange(1, 0x2FF))
            elif op < 0.85 and chars:
                j = self.rng.randrange(len(chars))
                k = self.rng.randrange(j, min(len(chars), j + 40) + 1)
                chars[i:i] = chars[j:k] * self.rng.randint(1, 50)
            else:
                chars = chars[: self.rng.randrange(len(chars) + 1)]
        return "".join(chars)

    def json(self, line: str) -> str:
        try:
            obj = json.loads(line)
        except ValueError:
            return self.text(line)

        def walk(node: object) -> None:
            if isinstance(node, dict):
                for key in list(node):
                    r = self.rng.random()
                    if r < 0.15:
                        node[key] = self.rng.choice(WEIRD)
                    elif r < 0.2:
                        del node[key]
                    elif r < 0.25:
                        node[key] = [node[key]] * self.rng.randint(0, 3)
                    else:
                        walk(node[key])
                if self.rng.random() < 0.1:
                    node[self.rng.choice(["EventData", "alert", "winlog", "Event", "http", "dns"])] = self.rng.choice(WEIRD)

        walk(obj)
        return json.dumps(obj, allow_nan=True)

    def line(self, source: str, seed_line: str) -> str:
        if source in ("linux_auth", "web_access") or self.rng.random() < 0.3:
            return self.text(seed_line)
        return self.json(seed_line)


def seeds_for(file_name: str) -> list[str]:
    return [l for l in (ROOT / "datasets" / "raw" / file_name).read_text(encoding="utf-8").splitlines() if l]


def unit_fuzz(iterations: int, seed: int) -> dict:
    ctx = NormalizeContext(now=datetime(2026, 11, 14, tzinfo=timezone.utc))
    mutator = Mutator(seed)
    stats, crashes, slow = {}, [], []
    for source, (parse, normalize, file_name) in SOURCES.items():
        seeds = seeds_for(file_name)
        accepted = rejected = 0
        for _ in range(iterations):
            line = mutator.line(source, mutator.rng.choice(seeds))
            started = time.perf_counter()
            try:
                event = normalize(parse(line), line, "fuzz", ctx)
                json.dumps(event.to_dict(), default=str)
                accepted += 1
            except (ParseError, NormalizationError):
                rejected += 1
            except Exception as exc:  # noqa: BLE001 - this is exactly what the fuzzer looks for
                crashes.append({"source": source, "error": f"{type(exc).__name__}: {exc}"[:160], "line": line[:200]})
            elapsed = time.perf_counter() - started
            if elapsed > SLOW_SECONDS:
                slow.append({"source": source, "seconds": round(elapsed, 3), "line": line[:80]})
        stats[source] = {"accepted": accepted, "rejected": rejected}
    return {"stats": stats, "crash_count": len(crashes), "crashes": crashes[:10], "slow_calls": slow[:10]}


def redos_checks() -> dict:
    """Time adversarial inputs at the maximum line length against every regular expression."""
    ctx = NormalizeContext(now=datetime(2026, 11, 14, tzinfo=timezone.utc))
    length = 65536
    timings = {}
    linux_cases = {
        "failed_many_from": "Nov 13 10:00:01 h sshd[1]: Failed password for " + "x from 1.2.3.4 port 1 " * (length // 24),
        "failed_no_end": "Nov 13 10:00:01 h sshd[1]: Failed password for " + "a " * (length // 2),
        "accepted_spaces": "Nov 13 10:00:01 h sshd[1]: Accepted password for " + " " * length + "from",
        "header_spaces": "Nov 13 10:00:01 " + " " * length,
        "lockout_words": "Nov 13 10:00:01 h sshd[1]: " + "account " * (length // 8),
        "sudo_semicolons": "Nov 13 10:00:01 h sudo: a : PWD=" + " ; " * (length // 3) + "x",
        "sudo_pwd_users": "Nov 13 10:00:01 h sudo: a : " + "PWD=/x ; USER=r ; " * (length // 18),
        "pam_failure_users": "Nov 13 10:00:01 h su: pam_unix(su:auth): authentication failure;" + " user=" * (length // 6),
    }
    for name, line in linux_cases.items():
        started = time.perf_counter()
        try:
            linux_normalizer.normalize(linux_auth.parse_line(line), line, "x", ctx)
        except (ParseError, NormalizationError):
            pass
        timings["linux_" + name] = round(time.perf_counter() - started, 4)
    head = '1.2.3.4 - - [13/Nov/2026:10:00:01 +0000] '
    web_cases = {
        "quotes_backslashes": head + '"' + '\\"' * (length // 2) + '" 200 1',
        "unclosed_quote": head + '"GET /' + "a" * length,
        "many_escapes_no_status": head + '"' + "\\x41" * (length // 4) + '"',
        "agent_quotes": head + '"GET / HTTP/1.1" 200 1 "-" "' + '\\"' * (length // 2),
    }
    for name, line in web_cases.items():
        started = time.perf_counter()
        try:
            web_normalizer.normalize(web_access.parse_line(line), line, "x", ctx)
        except (ParseError, NormalizationError):
            pass
        timings["web_" + name] = round(time.perf_counter() - started, 4)
    for name, url in {"union_comments": "/?q=union" + "/**/" * 3000 + "x", "quotes_or": "/?q=" + "' or " * 2000,
                      "dots": "/" + "..." * 3000, "pipes": "/?x=" + "| " * 4000,
                      "percent": "/" + "%25" * 3000}.items():
        started = time.perf_counter()
        classify_request(url, "a" * 1000)
        timings["web_rule_" + name] = round(time.perf_counter() - started, 4)
    rule = SuspiciousProcessRule()
    for name, command in {"spaces": "powershell" + " " * 8192 + "-e", "enc_prefix": "powershell " + "-e " * 3000,
                          "certutil": "certutil " * 1000, "mshta": "mshta " * 1500, "iex": "iex " * 2000,
                          "hidden": " -w" * 2700}.items():
        started = time.perf_counter()
        rule.score("C:\\a\\Temp\\x.exe", command, None)
        timings["process_" + name] = round(time.perf_counter() - started, 4)
    return {"seconds": timings, "slow": {k: v for k, v in timings.items() if v > SLOW_SECONDS}}


def pipeline_fuzz(lines_per_source: int, seed: int) -> dict:
    work = Path(tempfile.mkdtemp(prefix="soc_fuzz_"))
    try:
        settings = replace(Settings(), db_path=work / "fuzz.db", allowed_input_dirs=(work,),
                           syslog_default_year=2026, batch_size=3000)
        db = Database(settings.db_path)
        db.init_schema()
        mutator = Mutator(seed)
        result: dict = {}
        for source, (_parse, _normalize, file_name) in SOURCES.items():
            seeds = seeds_for(file_name)
            lines = [line if mutator.rng.random() < 0.4 else mutator.line(source, line)
                     for line in (mutator.rng.choice(seeds) for _ in range(lines_per_source))]
            # surrogatepass keeps lone surrogates as (invalid) UTF-8 bytes, like a damaged file would
            (work / file_name).write_bytes("\n".join(lines).encode("utf-8", errors="surrogatepass") + b"\n")
            ingest = ingest_file(db, settings, source, work / file_name)
            result[source] = {"lines": ingest.total_lines, "new_events": ingest.new_events,
                              "rejected": ingest.rejected, "duplicates": ingest.duplicates}
        detection = run_detection(db, settings)
        with db.connection() as conn:
            batches = {row[0]: row[1] for row in
                       conn.execute("SELECT status, COUNT(*) FROM import_batches GROUP BY status")}
            unexpected = conn.execute("SELECT COUNT(*) FROM raw_events WHERE error LIKE 'unexpected_error%'").fetchone()[0]
        integrity = db.integrity_report()
        result.update({"batches": batches, "unexpected_errors": unexpected, "rule_errors": detection.rule_errors,
                       "alerts_new": detection.alerts_new, "integrity": integrity["integrity_check"],
                       "foreign_key_violations": len(integrity["foreign_key_violations"])})
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=20000, help="mutations per source (unit fuzz)")
    parser.add_argument("--pipeline-lines", type=int, default=30000, help="lines per source file (pipeline fuzz)")
    parser.add_argument("--seed", type=int, default=1234)
    args = parser.parse_args()
    report = {"seed": args.seed, "unit": unit_fuzz(args.iterations, args.seed), "redos": redos_checks(),
              "pipeline": pipeline_fuzz(args.pipeline_lines, args.seed)}
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "fuzz_results.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(json.dumps(report, indent=2, default=str))
    pipeline = report["pipeline"]
    ok = (report["unit"]["crash_count"] == 0 and not report["unit"]["slow_calls"] and not report["redos"]["slow"]
          and set(pipeline["batches"]) == {"completed"} and pipeline["unexpected_errors"] == 0
          and not pipeline["rule_errors"] and pipeline["integrity"] == ["ok"] and not pipeline["foreign_key_violations"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
