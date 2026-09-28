import datetime
import hashlib
import io
import json
import os
import zipfile
from unittest.mock import MagicMock

import pytest

from yemu import config as yemu_config
from yemu import paths
from yemu.core import updates, yara_sync
from yemu.core.yara_sync import YaraRuleSync


def _resp(json_data=None, text="", content=b""):
    r = MagicMock()
    r.__enter__ = lambda s: s
    r.__exit__ = lambda s, *a: None
    r.ok = True
    r.status_code = 200
    r.json.return_value = json_data
    r.text = text
    r.headers = {"content-length": str(len(content))}
    r.iter_content.return_value = [content]
    r.raise_for_status.return_value = None
    return r


# --- versions ------------------------------------------------------------------------------
def test_version_ordering():
    assert updates.is_newer("v0.7.0", "0.6.1")
    assert updates.is_newer("0.6.10", "0.6.9")
    assert not updates.is_newer("v0.6.1", "0.6.1")
    assert updates.is_newer("0.7.0", "0.7.0rc1")  # final beats its pre-release
    assert not updates.is_newer("0.7.0rc1", "0.7.0")
    assert not updates.is_newer("garbage", "0.6.1")


RELEASES = [
    {"tag_name": "v0.8.0-rc1", "prerelease": True, "draft": False, "assets": []},
    {"tag_name": "v0.9.0", "prerelease": False, "draft": True, "assets": []},
    {
        "tag_name": "v0.7.0",
        "prerelease": False,
        "draft": False,
        "html_url": "https://x/r/0.7.0",
        "body": "notes",
        "published_at": "2026-10-01T00:00:00Z",
        "assets": [
            {"name": "YEMU-0.7.0-windows-x64-setup.exe", "browser_download_url": "https://dl/setup.exe"},
            {"name": "yemu-0.7.0-py3-none-any.whl", "browser_download_url": "https://dl/yemu.whl"},
            {"name": "SHA256SUMS.txt", "browser_download_url": "https://dl/sums"},
        ],
    },
    {"tag_name": "v0.6.1", "prerelease": False, "draft": False, "assets": []},
]


def test_check_for_app_update_picks_newest_stable(monkeypatch):
    monkeypatch.setattr(updates.requests, "get", lambda *a, **k: _resp(RELEASES))
    rel = updates.check_for_app_update(current="0.6.1")
    assert rel["version"] == "0.7.0" and rel["notes"] == "notes"
    assert "last_app_check" in updates.load_state()
    # drafts are never offered; pre-releases only when asked for
    assert updates.check_for_app_update(include_prereleases=True, current="0.6.1")["version"] == "0.8.0-rc1"
    assert updates.check_for_app_update(current="0.7.0") is None


def test_pick_asset_by_install_kind():
    rel = {"assets": {a["name"]: a["browser_download_url"] for a in RELEASES[2]["assets"]}}
    assert updates.pick_asset(rel, "installer") == "YEMU-0.7.0-windows-x64-setup.exe"
    assert updates.pick_asset(rel, "pip") == "yemu-0.7.0-py3-none-any.whl"
    assert updates.pick_asset(rel, "bundle-linux") is None
    assert updates.install_kind() == "pip"  # tests never run frozen


@pytest.mark.parametrize("tamper", [False, True])
def test_download_update_verifies_checksum(monkeypatch, tmp_path, tamper):
    payload = b"installer bytes"
    digest = hashlib.sha256(b"something else" if tamper else payload).hexdigest()
    sums = f"{digest}  YEMU-0.7.0-windows-x64-setup.exe\n{'0' * 64}  other.zip\n"

    def get(url, **kwargs):
        return _resp(text=sums) if url.endswith("sums") else _resp(content=payload)

    monkeypatch.setattr(updates.requests, "get", get)
    rel = {
        "tag": "v0.7.0",
        "assets": {"YEMU-0.7.0-windows-x64-setup.exe": "https://dl/setup.exe", "SHA256SUMS.txt": "https://dl/sums"},
    }
    if tamper:
        with pytest.raises(updates.UpdateError, match="Checksum mismatch"):
            updates.download_update(rel, "YEMU-0.7.0-windows-x64-setup.exe", tmp_path)
        assert list(tmp_path.iterdir()) == []  # nothing unverified is left behind
    else:
        path = updates.download_update(rel, "YEMU-0.7.0-windows-x64-setup.exe", tmp_path)
        assert path.read_bytes() == payload


def test_download_refuses_release_without_checksums(tmp_path):
    rel = {"tag": "v0.7.0", "assets": {"a.exe": "https://dl/a"}}
    with pytest.raises(updates.UpdateError, match="SHA256SUMS"):
        updates.download_update(rel, "a.exe", tmp_path)


def test_app_check_respects_setting_and_interval():
    cfg = yemu_config.load()
    assert updates.app_check_due(cfg)
    updates.save_state(last_app_check=datetime.datetime.now().isoformat())
    assert not updates.app_check_due(cfg)
    cfg["updates"]["check_on_startup"] = False
    updates.save_state(last_app_check="2000-01-01T00:00:00")
    assert not updates.app_check_due(cfg)


# --- rules --------------------------------------------------------------------------------
def _write_manifest(set_name, days_ago):
    ts = (datetime.datetime.now() - datetime.timedelta(days=days_ago)).isoformat()
    (paths.synced_rules_dir() / yara_sync.MANIFEST).write_text(
        json.dumps({"set_name": set_name, "timestamp": ts, "commit": "x"}), encoding="utf-8"
    )


def test_rules_update_due():
    cfg = yemu_config.load()
    assert updates.rules_update_due(cfg)  # never synced
    _write_manifest("yara-forge-core", days_ago=1)
    assert not updates.rules_update_due(cfg)
    _write_manifest("yara-forge-core", days_ago=8)
    assert updates.rules_update_due(cfg)  # older than the 7-day default
    _write_manifest("Yara-Rules-rules", days_ago=0)
    assert updates.rules_update_due(cfg)  # configured source changed
    cfg["rules"]["auto_update"] = False
    assert not updates.rules_update_due(cfg)


def test_from_config_builds_yara_forge_and_repo_sources():
    forge = YaraRuleSync.from_config(yemu_config.DEFAULTS["rules"])
    assert (forge.set_name, forge.release_asset) == ("yara-forge-core", "yara-forge-rules-core.zip")
    ext = YaraRuleSync.from_config(yemu_config.DEFAULTS["rules"], package="extended")
    assert ext.release_asset == "yara-forge-rules-extended.zip"
    repo = YaraRuleSync.from_config({**yemu_config.DEFAULTS["rules"], "source": "github-repo"})
    assert repo.set_name == "Yara-Rules-rules" and not repo.release_asset
    with pytest.raises(yara_sync.RuleSyncError):
        YaraRuleSync.from_config({**yemu_config.DEFAULTS["rules"], "package": "nope"})


def test_yara_forge_sync_replaces_older_sets_but_keeps_custom(monkeypatch):
    rules = paths.synced_rules_dir()
    old = rules / "Yara-Rules-rules"
    old.mkdir()
    (old / yara_sync.MANIFEST).write_text("{}", encoding="utf-8")
    custom = rules / "custom"
    custom.mkdir()
    (custom / "mine.yar").write_text("rule mine { condition: true }", encoding="utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("packages/core/yara-rules-core.yar", "rule forge_rule { condition: true }\n" * 1)
    archive = buf.getvalue()
    requested = []

    def get(url, **kwargs):
        requested.append(url)
        if url.endswith("/releases/latest"):
            return _resp({"tag_name": "20260927"})
        return _resp(content=archive)

    monkeypatch.setattr(yara_sync.requests, "get", get)
    manifest = updates.update_rules(yemu_config.load())
    assert manifest["commit"] == "20260927" and manifest["set_name"] == "yara-forge-core"
    assert requested[-1].endswith("/releases/download/20260927/yara-forge-rules-core.zip")
    assert os.path.isfile(rules / "yara-forge-core" / "core" / "yara-rules-core.yar")
    assert manifest["replaced_sets"] == ["Yara-Rules-rules"] and not old.exists()
    assert (custom / "mine.yar").is_file()
    assert not updates.rules_update_due(yemu_config.load())
