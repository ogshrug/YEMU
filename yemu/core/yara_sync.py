"""
Download YARA rule sets from GitHub into the synced-rules folder.

Two kinds of source:
  - a repository archive (any GitHub repo, e.g. Yara-Rules/rules), pinned to a commit
  - a release asset (e.g. YARA Forge's weekly yara-forge-rules-core.zip), pinned to a tag

Hardening: the version is resolved (or a pinned `ref` is used) and recorded in the
manifest; the download and every file are size-capped; archive paths are confined to
the target folder (no zip-slip); each rule file must compile; and the new set replaces
the old one atomically, so a failed sync never leaves a half-updated set.
"""

import datetime
import io
import json
import logging
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from yemu import paths

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

try:
    import yara
except ImportError:
    yara = None

MAX_RULE_FILE_BYTES = 2 * 1024 * 1024
# curated bundles ship thousands of rules in one file (YARA Forge core is ~8 MB)
MAX_BUNDLE_FILE_BYTES = 64 * 1024 * 1024
GITHUB_REPO = re.compile(r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
REF = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
ASSET = re.compile(r"^[A-Za-z0-9._-]{1,100}\.zip$")
MANIFEST = ".sync_manifest.json"

YARA_FORGE_REPO = "https://github.com/YARAHQ/yara-forge"
YARA_FORGE_PACKAGES = ("core", "extended", "full")
SOURCES = ("yara-forge", "github-repo")


class RuleSyncError(RuntimeError):
    pass


class YaraRuleSync:
    def __init__(
        self,
        repo_url="https://github.com/Yara-Rules/rules",
        branch="master",
        rules_dir=None,
        ref="",
        max_download_mb=100,
        release_asset="",
        set_name="",
    ):
        self.repo_url = repo_url.strip().rstrip('/')
        self.branch = branch or "master"
        self.ref = (ref or "").strip()
        self.release_asset = (release_asset or "").strip()
        self.max_download = int(max_download_mb) * 1024 * 1024
        self.rules_dir = str(rules_dir or paths.synced_rules_dir())
        self.logger = logging.getLogger(__name__)

        m = GITHUB_REPO.match(self.repo_url)
        if not m:
            raise RuleSyncError(f"Not a GitHub repository URL: {self.repo_url}")
        self.owner, self.repo_name = m.groups()
        for value in (self.branch, self.ref):
            if value and (not REF.match(value) or ".." in value):
                raise RuleSyncError(f"Invalid branch/ref: {value!r}")
        if self.release_asset and not ASSET.match(self.release_asset):
            raise RuleSyncError(f"Invalid release asset name: {self.release_asset!r}")
        self.set_name = set_name or f"{self.owner}-{self.repo_name}"
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", self.set_name) or self.set_name.startswith("."):
            raise RuleSyncError(f"Invalid rule set name: {self.set_name!r}")

    @classmethod
    def from_config(cls, rules_cfg, rules_dir=None, **overrides):
        """Build a sync for the configured [rules] source (YARA Forge package or a GitHub repo)."""
        cfg = {**rules_cfg, **{k: v for k, v in overrides.items() if v is not None}}
        if cfg.get("source", "yara-forge") == "yara-forge":
            package = cfg.get("package", "core")
            if package not in YARA_FORGE_PACKAGES:
                raise RuleSyncError(
                    f"Unknown YARA Forge package {package!r}; use one of {', '.join(YARA_FORGE_PACKAGES)}"
                )
            return cls(
                repo_url=YARA_FORGE_REPO,
                rules_dir=rules_dir,
                ref=cfg.get("ref", ""),
                max_download_mb=cfg.get("max_download_mb", 100),
                release_asset=f"yara-forge-rules-{package}.zip",
                set_name=f"yara-forge-{package}",
            )
        return cls(
            repo_url=cfg.get("repo_url", ""),
            branch=cfg.get("branch", "master"),
            rules_dir=rules_dir,
            ref=cfg.get("ref", ""),
            max_download_mb=cfg.get("max_download_mb", 100),
        )

    @property
    def target_dir(self):
        return os.path.join(self.rules_dir, self.set_name)

    @property
    def max_file_bytes(self):
        return MAX_BUNDLE_FILE_BYTES if self.release_asset else MAX_RULE_FILE_BYTES

    def resolve_commit(self):
        """Pinned ref if set, else the current commit SHA of the branch (falls back to the branch name)."""
        if self.ref:
            return self.ref
        url = f"https://api.github.com/repos/{self.owner}/{self.repo_name}/commits/{self.branch}"
        try:
            resp = requests.get(url, headers={"Accept": "application/vnd.github.sha"}, timeout=15)
            if resp.ok and re.fullmatch(r"[0-9a-f]{40}", resp.text.strip()):
                return resp.text.strip()
            self.logger.warning(
                f"Could not resolve {self.branch} to a commit (HTTP {resp.status_code}); using branch head"
            )
        except requests.RequestException as e:
            self.logger.warning(f"Could not resolve {self.branch} to a commit ({e}); using branch head")
        return self.branch

    def resolve_release(self):
        """Pinned tag if set, else the tag of the latest (non-prerelease) release."""
        if self.ref:
            return self.ref
        url = f"https://api.github.com/repos/{self.owner}/{self.repo_name}/releases/latest"
        try:
            resp = requests.get(url, headers={"Accept": "application/vnd.github+json"}, timeout=15)
            resp.raise_for_status()
            tag = resp.json().get("tag_name", "")
        except (requests.RequestException, ValueError) as e:
            raise RuleSyncError(f"Could not find the latest {self.repo_name} release: {e}") from e
        if not REF.match(tag or "") or ".." in tag:
            raise RuleSyncError(f"Unexpected release tag {tag!r}")
        return tag

    def latest_version(self):
        """Version the next sync would install (release tag or commit), without downloading."""
        return self.resolve_release() if self.release_asset else self.resolve_commit()

    def _download(self, ref, progress_callback):
        if self.release_asset:
            zip_url = f"https://github.com/{self.owner}/{self.repo_name}/releases/download/{ref}/{self.release_asset}"
        else:
            zip_url = f"https://github.com/{self.owner}/{self.repo_name}/archive/{ref}.zip"
        self.logger.info(f"Downloading YARA rules from {zip_url}")
        with requests.get(zip_url, stream=True, timeout=30) as response:
            response.raise_for_status()
            total = int(response.headers.get("content-length", 0))
            if total > self.max_download:
                raise RuleSyncError(
                    f"Archive is {total / 1048576:.0f} MB, over the {self.max_download // 1048576} MB limit"
                )
            data = io.BytesIO()
            for chunk in response.iter_content(chunk_size=65536):
                data.write(chunk)
                if data.tell() > self.max_download:
                    raise RuleSyncError(f"Archive exceeds the {self.max_download // 1048576} MB limit")
                if progress_callback and total:
                    progress_callback(data.tell(), total, f"Downloading: {data.tell() / 1024:.0f} KB")
        data.seek(0)
        return data

    @staticmethod
    def safe_relative_path(zip_name):
        """Strip the archive's top folder; reject absolute paths and '..' (zip-slip)."""
        parts = PurePosixPath(zip_name.replace("\\", "/")).parts[1:]
        if not parts or any(p in ("..", "") or ":" in p for p in parts) or zip_name.startswith("/"):
            return None
        return os.path.join(*parts)

    def _remove_other_managed_sets(self):
        """Drop rule sets from earlier syncs of *other* sources; hand-written rules are never touched."""
        removed = []
        for entry in Path(self.rules_dir).iterdir():
            if (
                entry.is_dir()
                and not entry.name.startswith(".")
                and entry.name != self.set_name
                and (entry / MANIFEST).is_file()
            ):
                shutil.rmtree(entry, ignore_errors=True)
                removed.append(entry.name)
        if removed:
            self.logger.info(f"Removed previously synced rule sets: {', '.join(removed)}")
        return removed

    def sync(self, progress_callback=None, replace_other_sets=True):
        """
        Synchronize YARA rules from the remote source.
        progress_callback: function(current, total, filename)
        """
        if not requests:
            raise ImportError("requests module not found. Please install requests.")
        if not yara:
            self.logger.warning("YARA module not found. Rules will be downloaded but NOT validated.")
        if progress_callback:
            progress_callback(0, 100, "Resolving version...")

        version = self.latest_version()
        archive = self._download(version, progress_callback)
        os.makedirs(self.rules_dir, exist_ok=True)
        staging = tempfile.mkdtemp(prefix=".sync-", dir=self.rules_dir)
        try:
            synced, skipped = 0, []
            with zipfile.ZipFile(archive) as z:
                members = [i for i in z.infolist() if i.filename.endswith((".yar", ".yara")) and not i.is_dir()]
                for n, info in enumerate(members, 1):
                    rel = self.safe_relative_path(info.filename)
                    try:
                        if rel is None:
                            raise RuleSyncError("unsafe path in archive")
                        if info.file_size > self.max_file_bytes:
                            raise RuleSyncError(f"file is {info.file_size} bytes (limit {self.max_file_bytes})")
                        content = z.read(info)
                        if yara:
                            yara.compile(source=content.decode("utf-8", errors="ignore"))
                        dest = Path(staging, rel).resolve()
                        if Path(staging).resolve() not in dest.parents:
                            raise RuleSyncError("unsafe path in archive")
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(content)
                        synced += 1
                    except Exception as e:
                        skipped.append({"file": info.filename, "error": str(e)[:300]})
                    if progress_callback:
                        progress_callback(n, len(members), info.filename)
            if synced == 0:
                raise RuleSyncError("No usable rule files in the download; keeping the current rules")

            manifest = {
                "timestamp": datetime.datetime.now().isoformat(),
                "repo_url": self.repo_url,
                "branch": None if self.release_asset else self.branch,
                "release_asset": self.release_asset or None,
                "set_name": self.set_name,
                "commit": version,
                "pinned": bool(self.ref),
                "file_count": synced,
                "skipped_files": skipped,
            }
            with open(os.path.join(staging, MANIFEST), "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=4)

            # swap in the new set atomically-ish: rename old aside, move new in, then delete old
            old = self.target_dir + ".old"
            shutil.rmtree(old, ignore_errors=True)
            if os.path.exists(self.target_dir):
                os.replace(self.target_dir, old)
            os.replace(staging, self.target_dir)
            shutil.rmtree(old, ignore_errors=True)
            if replace_other_sets:
                manifest["replaced_sets"] = self._remove_other_managed_sets()
            # one manifest at the top level too, for "last sync" displays and the auto-update schedule
            with open(os.path.join(self.rules_dir, MANIFEST), "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=4)
            self.logger.info(f"Sync complete at {version}: {synced} rule files, {len(skipped)} skipped.")
            return manifest
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise


def last_sync(rules_dir=None):
    """The top-level manifest of the most recent successful sync, or None."""
    path = Path(rules_dir or paths.synced_rules_dir()) / MANIFEST
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
