"""
User settings loaded from paths.config_file() (config.toml). Every key is optional;
missing keys fall back to DEFAULTS. `yemu config --init` writes a commented template.
"""
import copy
import json
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
        "backend": "auto",              # auto | libvirt | qemu | mock
        "default_vm": "ubuntu-clean",
        "default_snapshot": "clean-baseline",
        "agent_timeout": 300,           # seconds to wait for qemu-guest-agent
    },
    "qemu": {
        "bin_dir": "",                  # folder with qemu-system-x86_64 / qemu-img; empty = PATH + usual dirs
        "accel": "auto",                # auto | whpx | kvm | hvf | tcg
        "extra_args": [],
    },
    "network": {
        "name": "malware-analysis",
        "allow_internet": False,        # silence the isolation warning when True
    },
    "analysis": {
        "execution_wait": 5,            # seconds the sample runs before logs are collected
        "timeout": 900,                 # hard limit for a whole analysis; the VM is powered off after it
        "max_sample_mb": 256,           # refuse larger samples
        "max_events": 20000,            # behaviour events stored per analysis (the rest are counted, not stored)
        "max_pcap_mb": 200,             # captures larger than this are not copied back to the host
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
        "ref": "",                      # pin to a commit SHA or tag; empty = latest commit of `branch`
        "max_download_mb": 100,
    },
    "ui": {
        "theme": "system",              # system | light | dark
    },
}

TEMPLATE = r"""# YEMU configuration. Every key is optional; defaults are shown.

[vm]
backend = "auto"            # auto | libvirt | qemu | mock
default_vm = "ubuntu-clean"
default_snapshot = "clean-baseline"
agent_timeout = 300

[qemu]
bin_dir = ""                # e.g. 'C:\Program Files\qemu'; empty = PATH + usual install dirs
accel = "auto"              # auto | whpx | kvm | hvf | tcg
extra_args = []

[network]
name = "malware-analysis"
allow_internet = false

[analysis]
execution_wait = 5
timeout = 900               # seconds; the VM is powered off when it expires
max_sample_mb = 256
max_events = 20000
max_pcap_mb = 200

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
ref = ""                    # pin a commit SHA or tag; empty = latest commit of branch
max_download_mb = 100

[ui]
theme = "system"            # system | light | dark
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


def _toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    return json.dumps(str(value))  # JSON string escaping is valid TOML basic-string escaping


def dumps(cfg):
    """Serialise a config dict (tables of scalars/lists) to TOML."""
    lines = ["# YEMU configuration (written by YEMU; `yemu config --init --force` restores the commented template)"]
    for section, values in cfg.items():
        lines.append("")
        lines.append(f"[{section}]")
        for key, value in values.items():
            lines.append(f"{key} = {_toml_value(value)}")
    return "\n".join(lines) + "\n"


def save(cfg, path=None):
    path = path or paths.config_file()
    path.write_text(dumps(cfg), encoding="utf-8")
    return path
