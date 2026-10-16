import pytest

yara = pytest.importorskip("yara")

from yemu.core import yara_engine  # noqa: E402
from yemu.core.yara_engine import YaraEngine  # noqa: E402

GOOD_RULE = 'rule good_marker { strings: $a = "YEMU_GOOD_MARKER" condition: $a }\n'
BROKEN_RULE = 'rule broken_marker { strings: $a = "YEMU_BROKEN" condition: $b }\n'


def _count_compiles(monkeypatch):
    calls = []
    real = yara.compile

    def counting(*args, **kwargs):
        calls.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(yara_engine.yara, "compile", counting)
    return calls


def test_valid_rules_compile_once(tmp_path, monkeypatch):
    (tmp_path / "good.yar").write_text(GOOD_RULE, encoding="utf-8")
    calls = _count_compiles(monkeypatch)
    engine = YaraEngine(rules_dir=tmp_path)
    assert len(calls) == 1 and set(calls[0]["filepaths"]) == {"builtin", "ns_0"}
    assert engine.rules is not None


def test_broken_rule_file_is_skipped(tmp_path):
    (tmp_path / "a_broken.yar").write_text(BROKEN_RULE, encoding="utf-8")
    (tmp_path / "good.yar").write_text(GOOD_RULE, encoding="utf-8")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"xx YEMU_GOOD_MARKER YEMU_BROKEN xx")
    rules = {m["rule"] for m in YaraEngine(rules_dir=tmp_path).scan_file(str(sample))}
    assert "good_marker" in rules and "broken_marker" not in rules
