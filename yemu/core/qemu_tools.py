"""Locating QEMU binaries and picking an accelerator on Linux and Windows."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

WINDOWS_DEFAULT_DIRS = [
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "qemu",
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "qemu",
    Path.home() / "scoop" / "apps" / "qemu" / "current",
]


def find_binary(name, bin_dir=""):
    """Find a QEMU tool (e.g. 'qemu-img', 'qemu-system-x86_64') in bin_dir, PATH, or the usual install dirs."""
    exe = name + (".exe" if os.name == "nt" else "")
    if bin_dir:
        candidate = Path(bin_dir).expanduser() / exe
        if candidate.is_file():
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt":
        for d in WINDOWS_DEFAULT_DIRS:
            candidate = d / exe
            if candidate.is_file():
                return str(candidate)
    return None


def supported_accels(qemu_system):
    try:
        out = subprocess.run([qemu_system, "-accel", "help"], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [line.strip() for line in out.splitlines()[1:] if line.strip()]


def choose_accel(qemu_system, preferred="auto"):
    """Return the -accel value: explicit preference, else whpx (Windows) / kvm (Linux) / hvf (macOS), else tcg."""
    if preferred and preferred != "auto":
        return preferred
    available = supported_accels(qemu_system)
    if sys.platform == "win32" and "whpx" in available:
        return "whpx"
    if sys.platform.startswith("linux") and "kvm" in available and os.access("/dev/kvm", os.R_OK | os.W_OK):
        return "kvm"
    if sys.platform == "darwin" and "hvf" in available:
        return "hvf"
    return "tcg"
