"""Configuration and command-line tests (smoke tests of the application entry point)."""
from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import main as cli
from config import PROJECT_ROOT, ConfigError, Settings, load_settings


# ------------------------------------------------------------------ settings
def test_defaults_match_the_specification() -> None:
    settings = load_settings(env={})
    assert (settings.ssh_bruteforce.threshold, settings.ssh_bruteforce.window_seconds) == (5, 60)
    assert (settings.port_scan.threshold, settings.port_scan.window_seconds) == (15, 30)
    assert settings.pivot.window_seconds == 300
    assert settings.db_path == PROJECT_ROOT / "data" / "soc.db"      # relative to the project, not a personal path
    assert settings.allowed_input_dirs == (PROJECT_ROOT / "datasets",)


def test_json_file_and_environment_overrides(tmp_path) -> None:
    config = tmp_path / "settings.json"
    config.write_text(json.dumps({"db_path": str(tmp_path / "x.db"), "batch_size": 100,
                                  "ssh_bruteforce": {"threshold": 3},
                                  "suspicious_process": {"allow_image_patterns": ["\\\\corp\\\\"]},
                                  "allowed_input_dirs": [str(tmp_path)], "syslog_default_year": 2025}))
    settings = load_settings(config, env={})
    assert settings.db_path == tmp_path / "x.db" and settings.batch_size == 100
    assert settings.ssh_bruteforce.threshold == 3 and settings.ssh_bruteforce.window_seconds == 60
    assert settings.suspicious_process.allow_image_patterns == ("\\\\corp\\\\",)
    assert settings.allowed_input_dirs == (tmp_path,) and settings.syslog_default_year == 2025
    settings = load_settings(config, env={"SOC_DB_PATH": str(tmp_path / "env.db")})
    assert settings.db_path == tmp_path / "env.db"
    assert load_settings(env={"SOC_DB_PATH": "relative/soc.db"}).db_path == PROJECT_ROOT / "relative" / "soc.db"


@pytest.mark.parametrize("content,message", [
    ("{not json", "cannot read"),
    ("[1, 2]", "JSON object"),
    (json.dumps({"unknown_key": 1}), "unknown configuration key"),
    (json.dumps({"ssh_bruteforce": {"threshold": 0}}), "must be >= 1"),
    (json.dumps({"ssh_bruteforce": {"threshold": "five"}}), "must be an integer"),
    (json.dumps({"port_scan": {"internal_only": "yes"}}), "true/false"),
    (json.dumps({"batch_size": True}), "must be an integer"),
    (json.dumps({"db_path": 5}), "expected a path"),
    (json.dumps({"port_scan": 5}), "JSON object"),
])
def test_invalid_configuration_is_reported_clearly(tmp_path, content: str, message: str) -> None:
    config = tmp_path / "settings.json"
    config.write_text(content)
    with pytest.raises(ConfigError, match=message):
        load_settings(config, env={})


def test_missing_explicit_configuration_file(tmp_path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "missing.json", env={})
    with pytest.raises(ConfigError, match="not found"):
        load_settings(env={"SOC_CONFIG_FILE": str(tmp_path / "missing.json")})


# ---------------------------------------------------------------------- smoke
@pytest.mark.parametrize("module", [
    "config", "logging_setup", "pipeline", "reporting", "main", "ingest.base", "ingest.linux_auth",
    "ingest.suricata", "ingest.sysmon", "normalizer.models", "normalizer.linux_normalizer",
    "normalizer.suricata_normalizer", "normalizer.sysmon_normalizer", "storage.database",
    "storage.repository", "engine.rule_engine", "engine.correlation", "engine.incident_manager",
    "engine.rules.ssh_bruteforce", "engine.rules.port_scan", "engine.rules.suspicious_process",
    "engine.rules.network_host_pivot", "ui.data_access", "datasets.generate_dataset", "datasets.synth"])
def test_modules_import(module: str) -> None:
    importlib.import_module(module)


def test_rule_registry_has_four_documented_rules() -> None:
    from engine.rule_engine import RuleEngine, build_default_rules
    rules = build_default_rules(Settings())
    assert [r.rule_id for r in rules] == ["SOC-001", "SOC-002", "SOC-003", "SOC-004"]
    for rule in rules:
        meta = rule.metadata()
        assert meta["name"] and meta["description"] and 1 <= meta["severity"] <= 5 and meta["mitre"]
        assert meta["window_seconds"] and meta["threshold"]
    with pytest.raises(ValueError):
        RuleEngine([rules[0], rules[0]])


# ------------------------------------------------------------------------ CLI
@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    config = tmp_path / "settings.json"
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    config.write_text(json.dumps({"db_path": str(tmp_path / "cli.db"), "reports_dir": str(tmp_path / "reports"),
                                  "allowed_input_dirs": [str(inputs)], "syslog_default_year": 2026}))
    monkeypatch.delenv("SOC_DB_PATH", raising=False)
    monkeypatch.delenv("SOC_ALLOWED_INPUT_DIRS", raising=False)
    return config, inputs, tmp_path


def run(config: Path, *args: str) -> int:
    return cli.main(["--config", str(config), *args])


def test_cli_full_workflow(cli_env, capsys) -> None:
    from datasets import synth as s
    config, inputs, tmp = cli_env
    assert run(config, "init-db") == 0 and (tmp / "cli.db").is_file()
    log = inputs / "auth.log"
    log.write_text("\n".join(s.linux_failed(s.at(i * 5), "web01", "root", "203.0.113.10", 40000 + i, i)
                             for i in range(6)) + "\nbroken line\n")
    capsys.readouterr()
    assert run(config, "ingest", "--source", "linux_auth", "--file", str(log)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["new_events"] == 6 and result["rejected"] == 1
    assert run(config, "detect") == 0
    assert json.loads(capsys.readouterr().out)["incidents_created"] == 1
    assert run(config, "stats") == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["counts"]["incidents"] == 1 and stats["database"]["integrity_check"] == ["ok"]
    assert run(config, "incidents") == 0
    assert "SSH Brute Force" in capsys.readouterr().out
    assert run(config, "update-status", "--id", "1", "--status", "IN_PROGRESS", "--note", "checking") == 0
    assert run(config, "incidents", "--status", "IN_PROGRESS") == 0
    assert "#1" in capsys.readouterr().out
    assert run(config, "report", "--id", "1") == 0
    report = (tmp / "reports" / "incident_1.md").read_text(encoding="utf-8")
    assert "Incident Report #1" in report and "IN_PROGRESS" in report and "checking" in report


@pytest.mark.parametrize("args,message", [
    (["detect"], "database file not found"),
    (["stats"], "database file not found"),
    (["ingest", "--source", "linux_auth", "--file", "/etc/passwd"], "database file not found"),
])
def test_cli_before_init_reports_missing_database(cli_env, capsys, args, message: str) -> None:
    config, _inputs, tmp = cli_env
    assert run(config, *args) == 2
    assert message in capsys.readouterr().err and not (tmp / "cli.db").exists()


def test_cli_error_paths_return_code_2_without_traceback(cli_env, capsys) -> None:
    config, inputs, tmp = cli_env
    run(config, "init-db")
    capsys.readouterr()
    cases = [
        (["ingest", "--source", "linux_auth", "--file", str(inputs / "missing.log")], "input file not found"),
        (["ingest", "--source", "linux_auth", "--file", "/etc/passwd"], "outside the allowed input folders"),
        (["update-status", "--id", "99", "--status", "CLOSED"], "incident 99 not found"),
        (["report", "--id", "99"], "incident 99 not found"),
    ]
    for args, message in cases:
        assert run(config, *args) == 2
        err = capsys.readouterr().err
        assert message in err and "Traceback" not in err
    assert cli.main(["--config", str(tmp / "nope.json"), "stats"]) == 2
    assert "configuration file not found" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        run(config, "update-status", "--id", "1", "--status", "BOGUS")
    with pytest.raises(SystemExit):
        run(config, "ingest", "--source", "firewall", "--file", "x")


def test_cli_run_sample_as_subprocess(tmp_path) -> None:
    """Start the real program in a new process: generate data, import, detect, then query again."""
    env = {**__import__("os").environ, "SOC_DB_PATH": str(tmp_path / "sample.db"), "PYTHONIOENCODING": "utf-8"}
    env.pop("SOC_CONFIG_FILE", None)
    first = subprocess.run([sys.executable, str(PROJECT_ROOT / "main.py"), "run-sample"], env=env,
                           capture_output=True, text=True, encoding="utf-8", timeout=300, cwd=str(tmp_path))
    assert first.returncode == 0, first.stderr[-2000:]
    output = json.loads(first.stdout)
    assert output["counts"]["events"] == 921 and output["counts"]["incidents"] == 7
    assert output["detection"]["rule_errors"] == {}
    second = subprocess.run([sys.executable, str(PROJECT_ROOT / "main.py"), "run-sample"], env=env,
                            capture_output=True, text=True, encoding="utf-8", timeout=300, cwd=str(tmp_path))
    again = json.loads(second.stdout)
    assert again["counts"] == output["counts"]                         # restart + re-import adds nothing
    assert all(item["new_events"] == 0 for item in again["ingest"])
    stats = subprocess.run([sys.executable, str(PROJECT_ROOT / "main.py"), "stats"], env=env,
                           capture_output=True, text=True, encoding="utf-8", timeout=60, cwd=str(tmp_path))
    assert json.loads(stats.stdout)["database"]["integrity_check"] == ["ok"]
