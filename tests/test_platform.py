import inspect
import json

import pytest

from yemu import config as yemu_config
from yemu import paths
from yemu.cli import main as cli_main
from yemu.core.threat_scorer import ThreatScorer
from yemu.core.vm_backend import VMBackend, create_backend
from yemu.core.vm_manager import MockVMManager, VMManager


def test_paths_live_under_yemu_home(isolated_yemu_home):
    for name, value in paths.summary().items():
        if name == "builtin_rules":
            assert value.is_file()
            continue
        assert isolated_yemu_home in value.parents, (name, value)


def test_config_defaults_and_overrides(isolated_yemu_home):
    assert yemu_config.load()["vm"]["backend"] == "auto"
    paths.config_file().write_text(
        '[vm]\nbackend = "mock"\n[scoring]\nmalicious_threshold = 50\n[bogus]\nx = 1\n', encoding="utf-8"
    )
    cfg = yemu_config.load()
    assert cfg["vm"]["backend"] == "mock"
    assert cfg["vm"]["default_snapshot"] == "clean-baseline"  # untouched defaults survive
    assert cfg["scoring"]["malicious_threshold"] == 50
    assert "bogus" not in cfg


def test_config_template_round_trips():
    path, written = yemu_config.write_template()
    assert written
    assert yemu_config.load(path) == yemu_config.DEFAULTS


def test_scorer_uses_configured_thresholds():
    scorer = ThreatScorer({"malicious_threshold": 40})
    assert scorer.get_verdict(scorer.compute({"yara_count": 1})) == "malicious"


@pytest.mark.parametrize("cls", [VMManager, MockVMManager])
def test_backends_implement_full_interface(cls):
    assert issubclass(cls, VMBackend)
    assert not inspect.isabstract(cls)
    for name, member in inspect.getmembers(VMBackend, inspect.isfunction):
        if name.startswith("_"):
            continue
        base_sig = inspect.signature(member)
        impl_sig = inspect.signature(getattr(cls, name))
        assert list(impl_sig.parameters)[: len(base_sig.parameters)] == list(base_sig.parameters), name


def test_create_backend():
    assert create_backend("mock").name == "mock"
    with pytest.raises(ValueError):
        create_backend("hyperv")


def test_cli_analyze_mock_end_to_end(tmp_path, capsys):
    sample = tmp_path / "sample.txt"
    sample.write_text("encrypt decrypt .locked", encoding="utf-8")
    rc = cli_main(["analyze", str(sample), "--backend", "mock", "--json"])
    record = json.loads(capsys.readouterr().out)
    assert rc in (0, 3)
    assert record["verdict"] in ("clean", "suspicious", "malicious")
    assert (paths.reports_dir() / f"report_{record['id']}.json").is_file()

    assert cli_main(["reports", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["id"] == record["id"]


def test_cli_missing_sample_returns_error(tmp_path):
    assert cli_main(["analyze", str(tmp_path / "nope.bin"), "--backend", "mock"]) == 2
