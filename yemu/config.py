"""
User settings loaded from paths.config_file() (config.toml). Every key is optional;
missing keys fall back to DEFAULTS. `yemu config --init` writes a commented template.
"""
import copy
import logging

try:
    import tomllib
except ImportError:  # Python < 3.11
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

from yemu import paths

logger = logging.getLogger(__name__)

DEFAULTS = {
    "vm": {
        "backend": "auto",              # auto | libvirt | mock
        "default_vm": "ubuntu-clean",
        "default_snapshot": "clean-baseline",
        "agent_timeout": 300,           # seconds to wait for qemu-guest-agent
    },
    "network": {
        "name": "malware-analysis",
        "allow_internet": False,        # silence the isolation warning when True
    },
    "analysis": {
        "execution_wait": 5,            # seconds the sample runs before logs are collected
    },
    "scoring": {
        "yara_match": 40,
        "yara_many_bonus": 10,
        "yara_many_threshold": 3,
        "suspicious_syscall_each": 5,
        "suspicious_syscall": 20,
        "network_c2": 30,
        "file_persistence": 10,
        "suspicious_threshold": 30,
        "malicious_threshold": 70,
    },
    "rules": {
        "repo_url": "https://github.com/Yara-Rules/rules",
        "branch": "master",
    },
}

TEMPLATE = """# YEMU configuration. Every key is optional; defaults are shown.

[vm]
backend = "auto"            # auto | libvirt | mock
default_vm = "ubuntu-clean"
default_snapshot = "clean-baseline"
agent_timeout = 300

[network]
name = "malware-analysis"
allow_internet = false

[analysis]
execution_wait = 5

[scoring]
yara_match = 40
yara_many_bonus = 10
yara_many_threshold = 3
suspicious_syscall_each = 5
suspicious_syscall = 20
network_c2 = 30
file_persistence = 10
suspicious_threshold = 30
malicious_threshold = 70

[rules]
repo_url = "https://github.com/Yara-Rules/rules"
branch = "master"
"""


def _merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        elif key in base:
            base[key] = value
        else:
            logger.warning(f"Unknown config key ignored: {key}")
    return base


def load(path=None):
    cfg = copy.deepcopy(DEFAULTS)
    path = path or paths.config_file()
    if not path.exists():
        return cfg
    if tomllib is None:
        logger.warning("tomllib/tomli not available; using default config")
        return cfg
    try:
        with open(path, "rb") as f:
            return _merge(cfg, tomllib.load(f))
    except (OSError, ValueError) as e:
        logger.error(f"Failed to read config {path}: {e}. Using defaults.")
        return cfg


def write_template(path=None, overwrite=False):
    path = path or paths.config_file()
    if path.exists() and not overwrite:
        return path, False
    path.write_text(TEMPLATE, encoding="utf-8")
    return path, True
