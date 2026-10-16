import io
import json
import os
import zipfile
from unittest.mock import MagicMock

import pytest

from yemu.core import yara_sync
from yemu.core.yara_sync import RuleSyncError, YaraRuleSync

SHA = "a" * 40


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def _fake_get(archive, requested):
    def get(url, **kwargs):
        requested.append(url)
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda s, *a: None
        if "api.github.com" in url:
            resp.ok, resp.status_code, resp.text = True, 200, SHA
        else:
            resp.headers = {"content-length": str(len(archive))}
            resp.iter_content.return_value = [archive]
            resp.raise_for_status.return_value = None
        return resp

    return get


@pytest.fixture
def rules_dir(tmp_path):
    return tmp_path / "rules"


def test_sync_pins_commit_validates_and_replaces(rules_dir, monkeypatch):
    requested = []
    archive = _zip(
        {
            "rules-abc/malware/good.yar": "rule good { condition: true }",
            "rules-abc/broken.yar": "rule broken { condition: nope }",
            "rules-abc/readme.txt": "not a rule",
        }
    )
    monkeypatch.setattr(yara_sync.requests, "get", _fake_get(archive, requested))
    sync = YaraRuleSync(rules_dir=rules_dir)

    # a stale rule from an earlier sync must disappear after the swap
    os.makedirs(sync.target_dir)
    open(os.path.join(sync.target_dir, "stale.yar"), "w").write("rule stale { condition: true }")

    manifest = sync.sync()
    assert manifest["commit"] == SHA and not manifest["pinned"]
    assert manifest["file_count"] == 1
    assert [s["file"] for s in manifest["skipped_files"]] == ["rules-abc/broken.yar"]
    assert os.path.isfile(os.path.join(sync.target_dir, "malware", "good.yar"))
    assert not os.path.exists(os.path.join(sync.target_dir, "stale.yar"))
    assert requested[-1].endswith(f"/archive/{SHA}.zip")
    with open(os.path.join(sync.target_dir, ".sync_manifest.json"), encoding="utf-8") as f:
        assert json.load(f)["commit"] == SHA
    assert not (rules_dir / ".sync_manifest.json").exists()  # per-set manifests only


def test_pinned_ref_skips_resolution(rules_dir, monkeypatch):
    requested = []
    monkeypatch.setattr(
        yara_sync.requests, "get", _fake_get(_zip({"r-v1/x.yar": "rule x { condition: true }"}), requested)
    )
    manifest = YaraRuleSync(rules_dir=rules_dir, ref="v1.2").sync()
    assert manifest["pinned"] and manifest["commit"] == "v1.2"
    assert not any("api.github.com" in u for u in requested)


def test_zip_slip_entries_are_rejected(rules_dir, monkeypatch):
    archive = _zip(
        {
            "r-x/../../evil.yar": "rule evil { condition: true }",
            "r-x/ok.yar": "rule ok { condition: true }",
        }
    )
    monkeypatch.setattr(yara_sync.requests, "get", _fake_get(archive, []))
    manifest = YaraRuleSync(rules_dir=rules_dir).sync()
    assert manifest["file_count"] == 1
    assert "unsafe path" in manifest["skipped_files"][0]["error"]
    assert not (rules_dir.parent / "evil.yar").exists()


def test_download_size_limit(rules_dir, monkeypatch):
    archive = _zip({"r-x/big.yar": "x" * 2_000_000})
    monkeypatch.setattr(yara_sync.requests, "get", _fake_get(archive, []))
    sync = YaraRuleSync(rules_dir=rules_dir, max_download_mb=0)
    with pytest.raises(RuleSyncError):
        sync.sync()
    assert not os.path.exists(sync.target_dir)


@pytest.mark.parametrize("url", ["https://evil.example/owner/repo", "file:///etc/passwd", "https://github.com/a"])
def test_rejects_non_github_urls(url):
    with pytest.raises(RuleSyncError):
        YaraRuleSync(repo_url=url)


def test_rejects_bad_ref():
    with pytest.raises(RuleSyncError):
        YaraRuleSync(ref="../../x")


FORGE = {"source": "yara-forge", "package": "core", "ref": ""}
REPO = {"source": "github-repo", "repo_url": "https://github.com/Yara-Rules/rules", "branch": "master", "ref": ""}


def _rules_cfg(*sources):
    return {"sources": list(sources), "max_download_mb": 100}


def _sources_get(requested, fail=()):
    """Fake requests.get for a YARA Forge release plus a GitHub repo archive; URLs containing `fail` error out."""
    forge = _zip({"packages/core/yara-rules-core.yar": "rule forge_rule { condition: true }"})
    repo = _zip({"rules-abc/malware/x.yar": "rule repo_rule { condition: true }"})

    def get(url, **kwargs):
        requested.append(url)
        if any(f in url for f in fail):
            raise yara_sync.requests.ConnectionError("network down")
        resp = MagicMock()
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda s, *a: None
        resp.raise_for_status.return_value = None
        if url.endswith("/releases/latest"):
            resp.json.return_value = {"tag_name": "20261001"}
        elif "api.github.com" in url:
            resp.ok, resp.status_code, resp.text = True, 200, SHA
        else:
            archive = forge if "yara-forge" in url else repo
            resp.headers = {"content-length": str(len(archive))}
            resp.iter_content.return_value = [archive]
        return resp

    return get


def test_sync_sources_puts_each_source_in_its_own_folder(rules_dir, monkeypatch):
    requested = []
    monkeypatch.setattr(yara_sync.requests, "get", _sources_get(requested))
    progress = []
    result = yara_sync.sync_sources(
        _rules_cfg(FORGE, REPO), rules_dir=rules_dir, progress_callback=lambda c, t, n: progress.append(n)
    )
    assert [m["set_name"] for m in result["synced"]] == ["yara-forge-core", "Yara-Rules-rules"]
    assert result["failed"] == [] and result["removed"] == []
    assert (rules_dir / "yara-forge-core" / "core" / "yara-rules-core.yar").is_file()
    assert (rules_dir / "Yara-Rules-rules" / "malware" / "x.yar").is_file()
    assert not (rules_dir / ".sync_manifest.json").exists()
    assert set(yara_sync.synced_sets(rules_dir)) == {"yara-forge-core", "Yara-Rules-rules"}
    assert any(n.startswith("yara-forge-core: ") for n in progress)
    assert any(n.startswith("Yara-Rules-rules: ") for n in progress)


def test_sync_sources_removes_unconfigured_sets_but_keeps_custom(rules_dir, monkeypatch):
    stale = rules_dir / "old-owner-old-rules"
    stale.mkdir(parents=True)
    (stale / yara_sync.MANIFEST).write_text("{}", encoding="utf-8")
    custom = rules_dir / "custom"
    custom.mkdir()
    (custom / "mine.yar").write_text("rule mine { condition: true }", encoding="utf-8")
    (rules_dir / yara_sync.MANIFEST).write_text("{}", encoding="utf-8")  # top-level file from older versions
    monkeypatch.setattr(yara_sync.requests, "get", _sources_get([]))

    result = yara_sync.sync_sources(_rules_cfg(FORGE), rules_dir=rules_dir)
    assert result["removed"] == ["old-owner-old-rules"] and not stale.exists()
    assert (custom / "mine.yar").is_file()
    assert set(yara_sync.synced_sets(rules_dir)) == {"yara-forge-core"}


def test_failed_source_keeps_its_old_set_and_the_others_still_sync(rules_dir, monkeypatch):
    old = rules_dir / "Yara-Rules-rules"
    old.mkdir(parents=True)
    (old / yara_sync.MANIFEST).write_text('{"commit": "old"}', encoding="utf-8")
    (old / "old.yar").write_text("rule old { condition: true }", encoding="utf-8")
    monkeypatch.setattr(yara_sync.requests, "get", _sources_get([], fail=("Yara-Rules/rules/archive",)))

    result = yara_sync.sync_sources(_rules_cfg(FORGE, REPO), rules_dir=rules_dir)
    assert [m["set_name"] for m in result["synced"]] == ["yara-forge-core"]
    assert [f["set_name"] for f in result["failed"]] == ["Yara-Rules-rules"]
    assert "network down" in result["failed"][0]["error"]
    assert (old / "old.yar").is_file() and result["removed"] == []
    assert yara_sync.synced_sets(rules_dir)["Yara-Rules-rules"]["commit"] == "old"


@pytest.mark.parametrize(
    "sources,message",
    [
        ([], "No rule sources configured"),
        ([FORGE, {**FORGE, "ref": "v2"}], "Rule source 2: same rule set as source 1"),
        ([{"source": "svn"}], "Rule source 1: unknown source"),
        ([FORGE, {**FORGE, "package": "huge"}], "Rule source 2: Unknown YARA Forge package"),
        ([{**REPO, "repo_url": "https://gitlab.com/a/b"}], "Rule source 1: Not a GitHub repository"),
        ([{**REPO, "ref": "../x"}], "Rule source 1: Invalid branch/ref"),
    ],
)
def test_syncs_from_config_rejects_bad_sources(sources, message):
    with pytest.raises(RuleSyncError, match=message):
        yara_sync.syncs_from_config(_rules_cfg(*sources))


def test_describe_source():
    assert yara_sync.describe_source(FORGE) == "YARA Forge core"
    assert yara_sync.describe_source({**REPO, "branch": "main"}) == "github.com/Yara-Rules/rules (main)"
