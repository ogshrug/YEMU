import os
import zipfile
import io
import json
import datetime
import logging

try:
    import requests
except ImportError:
    requests = None

try:
    import yara
except ImportError:
    yara = None

class YaraRuleSync:
    def __init__(self, repo_url="https://github.com/Yara-Rules/rules", branch="master", rules_dir="rules/yara-rules/"):
        self.repo_url = repo_url.rstrip('/')
        self.branch = branch
        self.rules_dir = rules_dir
        self.logger = logging.getLogger(__name__)

        # Parse owner and repo from URL
        try:
            parts = self.repo_url.split('/')
            self.repo_name = parts[-1]
            self.owner = parts[-2]
        except (IndexError, AttributeError):
            # Fallback or error
            self.owner = "Yara-Rules"
            self.repo_name = "rules"

    def sync(self, progress_callback=None):
        """
        Synchronize YARA rules from the remote repository.
        progress_callback: function(current, total, filename)
        """
        if not requests:
            raise ImportError("requests module not found. Please install requests.")
        if not yara:
            self.logger.warning("YARA module not found. Rules will be downloaded but NOT validated.")

        zip_url = f"https://github.com/{self.owner}/{self.repo_name}/archive/refs/heads/{self.branch}.zip"
        self.logger.info(f"Downloading YARA rules from {zip_url}")

        if progress_callback:
            progress_callback(0, 100, "Initiating download...")

        try:
            response = requests.get(zip_url, stream=True, timeout=30)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0

            zip_data = io.BytesIO()
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    break
                zip_data.write(chunk)
                downloaded += len(chunk)
                if progress_callback and total_size > 0:
                    # Map 0-100% of download to some initial progress if we want,
                    # but maybe just show download progress.
                    progress_callback(downloaded, total_size, f"Downloading: {downloaded/1024:.1f} KB")

            zip_data.seek(0)
            with zipfile.ZipFile(zip_data) as z:
                all_files = z.namelist()
                yar_files = [f for f in all_files if f.endswith(('.yar', '.yara'))]
                total_files = len(yar_files)
                processed_count = 0
                synced_count = 0
                skipped_files = []

                os.makedirs(self.rules_dir, exist_ok=True)

                for zip_path in yar_files:
                    # Extract content
                    try:
                        content_bytes = z.read(zip_path)
                        content_str = content_bytes.decode('utf-8', errors='ignore')

                        # Validate
                        if yara:
                            yara.compile(source=content_str)

                        # Determine local path
                        # Remove the first component of the zip path (the archive root)
                        path_parts = zip_path.split('/')
                        if len(path_parts) > 1:
                            relative_path = os.path.join(*path_parts[1:])
                        else:
                            relative_path = zip_path

                        local_path = os.path.join(self.rules_dir, relative_path)
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)

                        with open(local_path, "wb") as f:
                            f.write(content_bytes)

                        synced_count += 1
                    except Exception as e:
                        skipped_files.append({"file": zip_path, "error": str(e)})
                        self.logger.warning(f"Skipping {zip_path} due to error: {e}")

                    processed_count += 1
                    if progress_callback:
                        progress_callback(processed_count, total_files, zip_path)

                manifest = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "repo_url": self.repo_url,
                    "branch": self.branch,
                    "file_count": synced_count,
                    "skipped_files": skipped_files
                }

                manifest_path = os.path.join(self.rules_dir, ".sync_manifest.json")
                with open(manifest_path, "w") as f:
                    json.dump(manifest, f, indent=4)

                self.logger.info(f"Sync complete. {synced_count} rules synced, {len(skipped_files)} skipped.")
                return manifest

        except Exception as e:
            self.logger.error(f"Sync failed: {e}")
            raise
