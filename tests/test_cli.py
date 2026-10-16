import pytest

from yemu import cli, paths
from yemu import config as yemu_config
from yemu.core import yara_sync
from yemu.logging_setup import log_file

from .test_yara_sync import REPO, _sources_get


def _with_sources(*sources):
    cfg = yemu_config.load()
    cfg["rules"]["sources"] = list(sources)
    yemu_config.save(cfg)


def test_sync_rules_syncs_every_source_and_fails_loudly(monkeypatch, capsys):
    _with_sources(yemu_config.DEFAULTS["rules"]["sources"][0], REPO)
    monkeypatch.setattr(yara_sync.requests, "get", _sources_get([], fail=("Yara-Rules/rules/archive",)))
    assert cli.main(["sync-rules"]) == 1
    out, err = capsys.readouterr()
    assert "yara-forge-core @ 20261001: 1 rule file(s), 0 skipped" in out
    assert "Yara-Rules-rules: sync failed: network down" in err

    monkeypatch.setattr(yara_sync.requests, "get", _sources_get([]))
    assert cli.main(["sync-rules"]) == 0
    assert "Yara-Rules-rules @ " in capsys.readouterr().out


def test_sync_rules_adhoc_source_is_kept_until_the_next_full_sync(monkeypatch, capsys):
    monkeypatch.setattr(yara_sync.requests, "get", _sources_get([]))
    assert cli.main(["sync-rules", "--repo", "https://github.com/Yara-Rules/rules", "--ref", "v1"]) == 0
    out = capsys.readouterr().out
    assert "Yara-Rules-rules @ v1" in out and "next full sync removes it" in out
    assert cli.main(["sync-rules"]) == 0
    assert "Removed Yara-Rules-rules" in capsys.readouterr().out
    assert set(yara_sync.synced_sets()) == {"yara-forge-core"}


@pytest.mark.parametrize("argv", [["sync-rules", "--ref", "v1"], ["sync-rules", "--branch", "main"]])
def test_sync_rules_branch_or_ref_alone_is_an_argument_error(argv):
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 2


def test_update_rules_lists_every_source(capsys, monkeypatch):
    _with_sources(yemu_config.DEFAULTS["rules"]["sources"][0], REPO)
    monkeypatch.setattr(yara_sync.requests, "get", _sources_get([]))
    assert cli.main(["update", "rules"]) == 0
    capsys.readouterr()
    assert cli.main(["update", "rules"]) == 0
    out = capsys.readouterr().out
    assert "yara-forge-core: 20261001 (synced" in out and "Yara-Rules-rules: " + "a" * 40 in out
    assert "up to date" in out


def _broken_config():
    paths.config_file().write_text('[analysis]\ntimeout = "900"\n', encoding="utf-8")


def test_config_error_exits_2_with_one_line(capsys):
    _broken_config()
    assert cli.main(["doctor"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("Config error: ") and "timeout" in err
    assert len(err.strip().splitlines()) == 1 and "Traceback" not in err
    assert "Config error" in log_file().read_text(encoding="utf-8")


def test_paths_and_config_init_work_with_a_broken_config(capsys):
    _broken_config()
    assert cli.main(["paths"]) == 0
    assert "config" in capsys.readouterr().out
    assert cli.main(["config", "--init"]) == 0  # does not overwrite without --force
    assert cli.main(["config"]) == 2
    assert cli.main(["config", "--init", "--force"]) == 0
    assert cli.main(["config"]) == 0


def test_command_crash_prints_one_line_and_logs_the_traceback(monkeypatch, capsys):
    def boom(args, cfg):
        raise RuntimeError("qemu-system-x86_64 not found")

    monkeypatch.setattr(cli, "cmd_reports", boom)
    assert cli.main(["reports"]) == 1
    err = capsys.readouterr().err
    assert err.strip() == f"Error: RuntimeError: qemu-system-x86_64 not found (details in {log_file()})"
    log = log_file().read_text(encoding="utf-8")
    assert "Traceback" in log and "qemu-system-x86_64 not found" in log


def test_ctrl_c_exits_130(monkeypatch, capsys):
    def interrupted(args, cfg):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_reports", interrupted)
    assert cli.main(["reports"]) == 130
    assert capsys.readouterr().err.strip() == "Interrupted."
