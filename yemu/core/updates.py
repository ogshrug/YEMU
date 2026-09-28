"""
Update checks for the YEMU app itself and for the synced YARA rules.

App updates: query GitHub Releases for ogshrug/YEMU, compare versions, and (on request)
download the package that matches how YEMU was installed, verified against the
release's SHA256SUMS.txt. Nothing is downloaded or installed without the user asking.

Rule updates: re-sync the configured rule source when the last sync is older than
[rules].update_interval_days, or when the configured source changed.
"""

import datetime
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

from yemu import __version__, paths
from yemu.core.yara_sync import YaraRuleSync, last_sync

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

RELEASES_API = "https://api.github.com/repos/ogshrug/YEMU/releases"
RELEASES_PAGE = "https://github.com/ogshrug/YEMU/releases"
MAX_UPDATE_BYTES = 600 * 1024 * 1024
VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-.]?([A-Za-z]+)\.?(\d*))?$")


class UpdateError(RuntimeError):
    pass


# --- versions -------------------------------------------------------------------------------
def parse_version(text):
    """'v0.6.1' -> (0, 6, 1, 1, 0); pre-releases ('0.7.0rc1') sort before the final release."""
    m = VERSION.match((text or "").strip())
    if not m:
        return None
    major, minor, patch, pre, pre_n = m.groups()
    return (int(major), int(minor), int(patch), 0 if pre else 1, int(pre_n or 0))


def is_newer(candidate, current=__version__):
    a, b = parse_version(candidate), parse_version(current)
    return bool(a and b and a > b)


# --- persisted state (last check, skipped version) ------------------------------------------
def _state_file():
    return paths.data_dir() / "update_state.json"


def load_state():
    try:
        return json.loads(_state_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(**changes):
    state = {**load_state(), **changes}
    _state_file().write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state


def _older_than(iso_timestamp, delta):
    try:
        then = datetime.datetime.fromisoformat(iso_timestamp)
    except (TypeError, ValueError):
        return True
    return datetime.datetime.now() - then >= delta


# --- how was YEMU installed? ------------------------------------------------------------------
def install_kind():
    """'installer' | 'portable-windows' | 'bundle-linux' | 'pip'"""
    if not getattr(sys, "frozen", False):
        return "pip"
    exe_dir = Path(sys.executable).resolve().parent
    if sys.platform == "win32":
        return "installer" if any(exe_dir.glob("unins*.exe")) else "portable-windows"
    return "bundle-linux"


ASSET_PATTERNS = {
    "installer": re.compile(r"^YEMU-.+-windows-x64-setup\.exe$"),
    "portable-windows": re.compile(r"^YEMU-.+-windows-x64\.zip$"),
    "bundle-linux": re.compile(r"^YEMU-.+-linux-x86_64\.tar\.gz$"),
    "pip": re.compile(r"^yemu-.+-py3-none-any\.whl$"),
}


# --- app updates ------------------------------------------------------------------------------
def app_check_due(cfg):
    ucfg = cfg["updates"]
    if not ucfg["check_on_startup"]:
        return False
    return _older_than(load_state().get("last_app_check"), datetime.timedelta(hours=ucfg["check_interval_hours"]))


def check_for_app_update(include_prereleases=False, current=__version__, timeout=15):
    """Newest release newer than `current`, as a dict, or None if up to date."""
    if requests is None:
        raise UpdateError("requests is not installed")
    try:
        resp = requests.get(
            RELEASES_API, params={"per_page": 20}, timeout=timeout, headers={"Accept": "application/vnd.github+json"}
        )
        resp.raise_for_status()
        releases = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise UpdateError(f"Could not reach GitHub to check for updates: {e}") from e
    save_state(last_app_check=datetime.datetime.now().isoformat())

    best = None
    for rel in releases:
        if rel.get("draft") or (rel.get("prerelease") and not include_prereleases):
            continue
        ver = parse_version(rel.get("tag_name", ""))
        if ver and (best is None or ver > best[0]):
            best = (ver, rel)
    if not best or not is_newer(best[1]["tag_name"], current):
        return None
    rel = best[1]
    return {
        "version": rel["tag_name"].lstrip("v"),
        "tag": rel["tag_name"],
        "name": rel.get("name") or rel["tag_name"],
        "url": rel.get("html_url") or RELEASES_PAGE,
        "notes": (rel.get("body") or "").strip(),
        "published": rel.get("published_at", ""),
        "assets": {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])},
    }


def pick_asset(release, kind=None):
    pattern = ASSET_PATTERNS[kind or install_kind()]
    return next((name for name in release["assets"] if pattern.match(name)), None)


def _download(url, dest, progress=None, limit=MAX_UPDATE_BYTES):
    with requests.get(url, stream=True, timeout=30) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        if total > limit:
            raise UpdateError(f"Download is {total / 1048576:.0f} MB, over the {limit // 1048576} MB limit")
        done = 0
        with open(dest, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1 << 20):
                done += len(chunk)
                if done > limit:
                    raise UpdateError("Download exceeds the size limit")
                f.write(chunk)
                if progress:
                    progress(done, total)


def download_update(release, asset_name, dest_dir=None, progress=None):
    """Download `asset_name` from the release and verify it against SHA256SUMS.txt. Returns the path."""
    if asset_name not in release["assets"]:
        raise UpdateError(f"{asset_name} is not part of release {release['tag']}")
    if "SHA256SUMS.txt" not in release["assets"]:
        raise UpdateError("The release has no SHA256SUMS.txt, so the download can't be verified")
    dest_dir = Path(dest_dir or paths.cache_dir() / "updates")
    dest_dir.mkdir(parents=True, exist_ok=True)

    sums = requests.get(release["assets"]["SHA256SUMS.txt"], timeout=15)
    sums.raise_for_status()
    expected = None
    for line in sums.text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == asset_name:
            expected = parts[0].lower()
    if not expected or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise UpdateError(f"No checksum for {asset_name} in SHA256SUMS.txt")

    target = dest_dir / asset_name
    partial = target.with_name(target.name + ".part")
    try:
        _download(release["assets"][asset_name], partial, progress)
        digest = hashlib.sha256()
        with open(partial, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise UpdateError(f"Checksum mismatch for {asset_name}; the download was discarded")
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)
    return target


def launch_installer(path):
    """Start the downloaded Windows installer; the caller should quit YEMU so files can be replaced."""
    if sys.platform != "win32":
        raise UpdateError("The installer only runs on Windows")
    subprocess.Popen([str(path)], creationflags=getattr(subprocess, "DETACHED_PROCESS", 0), close_fds=True)


def manual_update_hint(release, kind=None):
    kind = kind or install_kind()
    asset = pick_asset(release, kind)
    if kind == "pip" and asset:
        return f'pip install --upgrade "{release["assets"][asset]}"'
    if kind == "bundle-linux":
        return "Download the Linux tarball, unpack it and run ./install.sh again."
    return f"Download it from {release['url']}"


# --- rule updates -----------------------------------------------------------------------------
def expected_rule_set(rules_cfg):
    return YaraRuleSync.from_config(rules_cfg).set_name


def rules_update_due(cfg, rules_dir=None):
    rcfg = cfg["rules"]
    if not rcfg["auto_update"]:
        return False
    manifest = last_sync(rules_dir)
    if not manifest:
        return True
    try:
        if manifest.get("set_name") != expected_rule_set(rcfg):
            return True  # the configured source changed since the last sync
    except Exception:
        return False
    return _older_than(manifest.get("timestamp"), datetime.timedelta(days=rcfg["update_interval_days"]))


def update_rules(cfg, progress=None, rules_dir=None):
    """Sync the configured rule source now. Returns the sync manifest."""
    return YaraRuleSync.from_config(cfg["rules"], rules_dir=rules_dir).sync(progress_callback=progress)
