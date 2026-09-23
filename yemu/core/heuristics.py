"""
Turns raw behaviour events into scored findings with human-readable reasons.

Only activity attributable to the sample's process tree (strace) counts; guest OS
background traffic seen in the PCAP is reported as IOCs but never scored.
"""

import ipaddress
import os
import re

SENSITIVE_READ = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/.ssh/",
    "/.aws/credentials",
    "/.bash_history",
    "/.gnupg",
    "/etc/ssh/ssh_host_",
)
PERSISTENCE = (
    "/etc/cron",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/.config/systemd/user",
    "/etc/init.d",
    "/etc/rc.local",
    "/etc/profile",
    "/.bashrc",
    "/.bash_profile",
    "/.profile",
    "/etc/ld.so.preload",
    "/.ssh/authorized_keys",
    "/etc/xdg/autostart",
    "/.config/autostart",
)
SUSPICIOUS_EXEC = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "python",
    "python3",
    "perl",
    "base64",
    "chmod",
    "crontab",
    "systemctl",
    "useradd",
    "passwd",
    "iptables",
    "nohup",
    "setsid",
    "dd",
    "shred",
}
SHELLS = {"sh", "bash", "dash", "zsh", "ash"}
WRITE_FLAGS = re.compile(r"O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)")


def _is_public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def analyse(events, sample_name="malware_sample"):
    """
    events: parsed behaviour events (dicts from BehaviourMonitor).
    Returns {"network_alerts", "persistence_detected", "syscall_alerts", "reasons": [...]}.
    """
    reasons = []
    seen = set()
    suspicious = 0
    persistence = False
    public_dests = set()

    def add(kind, text):
        nonlocal suspicious
        if (kind, text) in seen:
            return
        seen.add((kind, text))
        reasons.append({"kind": kind, "text": text})
        if kind in ("suspicious", "persistence"):
            suspicious += 1

    for ev in events:
        etype, path = ev.get("type"), ev.get("path") or ""
        raw = ev.get("raw", "")
        if etype == "file":
            writes = ev.get("action") in ("write", "delete") or bool(WRITE_FLAGS.search(raw))
            if any(p in path for p in PERSISTENCE) and writes:
                persistence = True
                add("persistence", f"Modified persistence location {path}")
            elif any(p in path for p in SENSITIVE_READ):
                add("suspicious", f"Accessed sensitive file {path}")
            elif ev.get("action") == "delete" and path and not path.startswith(("/tmp/", "/proc/", "/dev/")):
                add("suspicious", f"Deleted {path}")
        elif etype == "process" and ev.get("action") == "execute":
            name = os.path.basename(path)
            if name in SUSPICIOUS_EXEC:
                add("suspicious", f"Ran {name}: {ev.get('cmdline', '')[:160]}")
            elif name in SHELLS and ev.get("ppid") not in ("unknown", None):
                add("suspicious", f"Spawned a shell: {ev.get('cmdline', '')[:160]}")
        elif etype == "network" and ev.get("action") == "connect":
            ip = ev.get("dst_ip", "")
            if _is_public(ip):
                dest = f"{ip}:{ev.get('dst_port', '?')}"
                public_dests.add(dest)
                add("network", f"Connected to {dest} ({ev.get('process_name', '?')})")

    return {
        "network_alerts": len(public_dests),
        "persistence_detected": persistence,
        "syscall_alerts": suspicious,
        "reasons": reasons,
    }
