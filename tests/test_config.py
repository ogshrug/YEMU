import logging

from yemu import config as yemu_config
from yemu import paths

REPO = {"source": "github-repo", "repo_url": "https://github.com/Yara-Rules/rules", "branch": "main", "ref": ""}


def _write(text):
    path = paths.config_file()
    path.write_text(text, encoding="utf-8")
    return path


def test_legacy_single_rule_source_loads_as_one_entry(caplog):
    _write(
        '[rules]\nsource = "github-repo"\nrepo_url = "https://github.com/Yara-Rules/rules"\nbranch = "master"\n'
        "update_interval_days = 3\n"
    )
    with caplog.at_level(logging.INFO, logger="yemu.config"):
        cfg = yemu_config.load()
    assert cfg["rules"]["sources"] == [
        {"source": "github-repo", "repo_url": "https://github.com/Yara-Rules/rules", "branch": "master", "ref": ""}
    ]
    assert cfg["rules"]["update_interval_days"] == 3
    assert "source" not in cfg["rules"]
    assert not any("Unknown config key" in r.message for r in caplog.records)
    assert any("Converted" in r.message for r in caplog.records)

    # the next save writes the new format
    text = yemu_config.save(cfg).read_text(encoding="utf-8")
    assert "[[rules.sources]]" in text and "\nsource = " in text.split("[[rules.sources]]", 1)[1]
    assert yemu_config.load() == cfg


def test_dumps_and_load_round_trip_two_sources():
    cfg = yemu_config.load()
    cfg["rules"]["sources"].append({**REPO, "ref": "v1.0"})
    cfg["qemu"]["extra_args"] = ["-m", "4096"]
    text = yemu_config.dumps(cfg)
    # arrays of tables must follow the [rules] scalars, or TOML would put them in the wrong table
    rules = text.split("[rules]", 1)[1].split("[updates]", 1)[0]
    assert rules.index("update_interval_days") < rules.index("[[rules.sources]]")
    assert rules.count("[[rules.sources]]") == 2
    yemu_config.save(cfg)
    assert yemu_config.load() == cfg


def test_template_uses_rule_sources():
    path, written = yemu_config.write_template()
    assert written and "[[rules.sources]]" in path.read_text(encoding="utf-8")
    assert yemu_config.load() == yemu_config.DEFAULTS
