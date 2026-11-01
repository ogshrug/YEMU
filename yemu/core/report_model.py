"""
Turns the raw DB rows of an analysis into one normalized report structure,
shared by the GUI, the CLI and the PDF export.
"""

import json
from collections import Counter


def _loads(value, default):
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return value if value is not None else default


def describe_event(event_type, det):
    """One-line human description of a behaviour event."""
    if event_type == "process":
        if det.get("msg"):
            return det["msg"]
        action = det.get("action", "")
        if action == "execute":
            return f"exec {det.get('cmdline') or det.get('path', '')}"
        if action == "fork":
            return f"{det.get('process_name', 'process')} spawned PID {det.get('child_pid', '?')}"
        return f"{action} {det.get('path', '')}".strip()
    failed = f" (failed: {det['result']})" if det.get("result") else ""
    if event_type == "network":
        if det.get("source") == "pcap":
            return f"{det.get('type', 'ioc')}: {det.get('value', '')}"
        if det.get("action") == "dns":
            return f"DNS lookup {det.get('query', '?')}"
        return f"connect {det.get('dst_ip', '?')}:{det.get('dst_port', '?')}{failed}"
    if event_type == "file":
        action, path = det.get("action", "access"), det.get("path", "")
        if action == "rename":
            return f"rename {det.get('src', '?')} -> {path}{failed}"
        if action == "link":
            return f"link {path} -> {det.get('target', '?')}{failed}"
        if action == "chmod":
            return f"chmod {det.get('mode', '')} {path}{failed}".replace("  ", " ")
        if det.get("source") == "fsdiff":
            return f"changed on disk: {path}"
        return f"{action} {path}{failed}"
    if event_type == "yara":
        return f"YARA {det.get('rule', '?')} ({det.get('source', '?')})"
    if event_type == "error":
        return det.get("error", str(det))
    return json.dumps(det)[:200]


CHANGING = {"write", "rename", "delete", "mkdir", "chmod", "link"}


def _changed_files(parsed):
    out, seen = [], set()
    for e in parsed:
        det = e["details"]
        if e["type"] != "file" or det.get("result"):
            continue
        action, source = det.get("action"), "fsdiff" if det.get("source") == "fsdiff" else "strace"
        if (source == "strace" and action not in CHANGING) or (source, det.get("path")) in seen:
            continue
        seen.add((source, det.get("path")))
        out.append({"path": det.get("path", ""), "action": action, "process": e["process"], "source": source})
    return out


def build_report(details, events):
    """
    details: row from Database.get_analysis_details; events: rows from get_analysis_events.
    Returns a dict with parsed yara matches, parsed events, IOCs and counts.
    """
    details = dict(details or {})
    yara_matches = _loads(details.get("yara_matches"), [])
    scoring = _loads(details.get("scoring"), {}) or {}
    parsed = []
    for ev in events or []:
        det = _loads(ev.get("details"), {})
        if not isinstance(det, dict):
            det = {"value": det}
        etype = ev.get("event_type", "unknown")
        parsed.append(
            {
                "id": ev.get("id"),
                "type": etype,
                "severity": ev.get("severity", "INFO"),
                "timestamp": ev.get("timestamp") or 0,
                "pid": det.get("pid", ""),
                "process": det.get("process_name", ""),
                "description": describe_event(etype, det),
                "details": det,
            }
        )

    behaviour = [e for e in parsed if e["type"] in ("process", "file", "network")]
    # one row per indicator; seen by both strace (the sample's processes) and the PCAP, it lists both
    by_key: dict[tuple, dict] = {}
    for e in parsed:
        det = e["details"]
        if e["type"] != "network":
            continue
        if det.get("source") == "pcap":
            key = (det.get("type", "ioc"), det.get("value", ""))
        elif det.get("action") == "dns":
            key = ("domain", det.get("query", ""))
        else:
            key = ("ip:port", f"{det.get('dst_ip', '?')}:{det.get('dst_port', '?')}")
        ioc = by_key.setdefault(key, {"type": key[0], "value": key[1], "sources": [], "processes": []})
        source = det.get("source", "strace")
        if source not in ioc["sources"]:
            ioc["sources"].append(source)
        if source != "pcap" and e["process"] and e["process"] not in ioc["processes"]:
            ioc["processes"].append(e["process"])
    iocs = []
    for ioc in by_key.values():
        sources, processes = sorted(ioc.pop("sources"), key=lambda s: s == "pcap"), ioc.pop("processes")
        iocs.append({**ioc, "source": ", ".join(sources), "process": ", ".join(processes)})
    # what the sample did first; PCAP-only rows can be the guest OS's own traffic
    iocs.sort(key=lambda i: not i["process"])

    processes = []
    for e in parsed:
        det = e["details"]
        if e["type"] == "process" and det.get("action") == "execute":
            processes.append(
                {
                    "pid": det.get("pid", ""),
                    "ppid": det.get("ppid", ""),
                    "name": det.get("process_name", ""),
                    "cmdline": det.get("cmdline", ""),
                }
            )

    return {
        "id": details.get("id"),
        "filename": details.get("filename") or "unknown",
        "sha256": details.get("sha256") or "",
        "md5": details.get("md5") or "",
        "size_bytes": details.get("size_bytes") or 0,
        "started_at": details.get("started_at"),
        "finished_at": details.get("finished_at"),
        "verdict": details.get("verdict") or "unknown",
        "status": details.get("status") or ("completed" if details.get("finished_at") else "running"),
        "error": details.get("error") or "",
        "guest_os": details.get("guest_os") or "",
        "findings": (scoring.get("findings") or {}).get("reasons", []),
        "score": details.get("threat_score") or 0,
        "yara_matches": yara_matches if isinstance(yara_matches, list) else [],
        "events": parsed,
        "behaviour": behaviour,
        "iocs": iocs,
        "processes": processes,
        "counts": dict(Counter(e["type"] for e in parsed)),
        # what the sample's own processes created, wrote, moved or deleted (strace), then the disk diff
        "changed_files": _changed_files(parsed),
        "errors": [e["description"] for e in parsed if e["type"] == "error"],
        "raw_details": details,
    }
