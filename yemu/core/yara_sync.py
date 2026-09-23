"""
Download YARA rule sets from GitHub into the synced-rules folder.

Hardening: the branch is resolved to an exact commit (or a pinned `ref` is used) and
recorded in the manifest; the download and every file are size-capped; archive paths
are confined to the target folder (no zip-slip); each rule must compile; and the new
set replaces the old one atomically, so a failed sync never leaves a half-updated set.
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
    requests = None

try:
    import yara
except ImportError:
    yara = None

MAX_RULE_FILE_BYTES = 2 * 1024 * 1024
GITHUB_REPO = re.compile(r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
REF = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")


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
    ):
        self.repo_url = repo_url.strip().rstrip('/')
        self.branch = branch or "master"
        self.ref = (ref or "").strip()
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

    @property
    def target_dir(self):
        return os.path.join(self.rules_dir, f"{self.owner}-{self.repo_name}")

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

    def _download(self, ref, progress_callback):
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

    def sync(self, progress_callback=None):
        """
        Synchronize YARA rules from the remote repository.
        progress_callback: function(current, total, filename)
        """
        if not requests:
            raise ImportError("requests module not found. Please install requests.")
        if not yara:
            self.logger.warning("YARA module not found. Rules will be downloaded but NOT validated.")
        if progress_callback:
            progress_callback(0, 100, "Resolving commit...")

        commit = self.resolve_commit()
        archive = self._download(commit, progress_callback)
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
                        if info.file_size > MAX_RULE_FILE_BYTES:
                            raise RuleSyncError(f"file is {info.file_size} bytes (limit {MAX_RULE_FILE_BYTES})")
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

            manifest = {
                "timestamp": datetime.datetime.now().isoformat(),
                "repo_url": self.repo_url,
                "branch": self.branch,
                "commit": commit,
                "pinned": bool(self.ref),
                "file_count": synced,
                "skipped_files": skipped,
            }
            with open(os.path.join(staging, ".sync_manifest.json"), "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=4)

            # swap in the new set atomically-ish: rename old aside, move new in, then delete old
            old = self.target_dir + ".old"
            shutil.rmtree(old, ignore_errors=True)
            if os.path.exists(self.target_dir):
                os.replace(self.target_dir, old)
            os.replace(staging, self.target_dir)
            shutil.rmtree(old, ignore_errors=True)
            # one manifest at the top level too, for the GUI/CLI "last sync" display
            with open(os.path.join(self.rules_dir, ".sync_manifest.json"), "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=4)
            self.logger.info(f"Sync complete at {commit}: {synced} rules, {len(skipped)} skipped.")
            return manifest
        except Exception:
            shutil.rmtree(staging, ignore_errors=True)
            raise
