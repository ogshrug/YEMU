"""
Per-user locations for YEMU data, resolved per platform:

  Linux:   ~/.local/share/yemu, ~/.config/yemu, ~/.cache/yemu   (XDG vars respected)
  Windows: %LOCALAPPDATA%\\YEMU\\...

Set YEMU_HOME to put everything under one directory instead (portable installs, tests).
"""

import os
from pathlib import Path

try:
    import platformdirs
except ImportError:
    platformdirs = None  # type: ignore[assignment]

APP_NAME = "YEMU"
PACKAGE_DIR = Path(__file__).resolve().parent
BUILTIN_RULES_FILE = PACKAGE_DIR / "rules" / "default.yar"


def _fallback_dirs():
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_NAME
        return base / "data", base / "config", base / "cache"
    home = Path.home()
    return (
        Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share")) / "yemu",
        Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "yemu",
        Path(os.environ.get("XDG_CACHE_HOME", home / ".cache")) / "yemu",
    )


def _base_dirs():
    override = os.environ.get("YEMU_HOME")
    if override:
        root = Path(override).expanduser()
        return root / "data", root / "config", root / "cache"
    if platformdirs is not None:
        # appauthor=False keeps Windows paths as %LOCALAPPDATA%\YEMU rather than ...\<author>\YEMU
        dirs = platformdirs.PlatformDirs(appname=APP_NAME if os.name == "nt" else "yemu", appauthor=False)
        return Path(dirs.user_data_dir), Path(dirs.user_config_dir), Path(dirs.user_cache_dir)
    return _fallback_dirs()


def _ensure(path):
    path.mkdir(parents=True, exist_ok=True)
    return path


def data_dir():
    return _ensure(_base_dirs()[0])


def config_dir():
    return _ensure(_base_dirs()[1])


def cache_dir():
    return _ensure(_base_dirs()[2])


def config_file():
    return config_dir() / "config.toml"


def db_path():
    return data_dir() / "yemu.db"


def reports_dir():
    return _ensure(data_dir() / "reports")


def logs_dir():
    return _ensure(data_dir() / "logs")


def captures_dir():
    return _ensure(data_dir() / "captures")


def synced_rules_dir():
    return _ensure(data_dir() / "rules")


def vm_storage_dir():
    """
    VM disks, cloud-init seeds and base images. On Linux, qemu:///system runs QEMU as a
    separate user that usually cannot read $HOME, so this lives in /var/tmp (survives
    reboots, world-traversable). Override with YEMU_VM_DIR.
    """
    override = os.environ.get("YEMU_VM_DIR")
    if override:
        return _ensure(Path(override).expanduser())
    if os.environ.get("YEMU_HOME") or os.name == "nt":
        return _ensure(data_dir() / "vms")
    import getpass

    return _ensure(Path("/var/tmp") / f"yemu-{getpass.getuser()}")


def images_dir():
    """Downloaded ISOs / cloud images (backing files, so they must be readable by QEMU too)."""
    return _ensure(vm_storage_dir() / "images")


def summary():
    return {
        "data": data_dir(),
        "config": config_file(),
        "database": db_path(),
        "reports": reports_dir(),
        "captures": captures_dir(),
        "logs": logs_dir(),
        "synced_rules": synced_rules_dir(),
        "builtin_rules": BUILTIN_RULES_FILE,
        "vm_storage": vm_storage_dir(),
        "images": images_dir(),
    }
