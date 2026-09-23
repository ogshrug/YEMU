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
    with open(rules_dir / ".sync_manifest.json", encoding="utf-8") as f:
        assert json.load(f)["commit"] == SHA


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
