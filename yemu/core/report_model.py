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
    if event_type == "network":
        if det.get("source") == "pcap":
            return f"{det.get('type', 'ioc')}: {det.get('value', '')}"
        return f"connect {det.get('dst_ip', '?')}:{det.get('dst_port', '?')}"
    if event_type == "file":
        return f"{det.get('action', 'access')} {det.get('path', '')}"
    if event_type == "yara":
        return f"YARA {det.get('rule', '?')} ({det.get('source', '?')})"
    if event_type == "error":
        return det.get("error", str(det))
    return json.dumps(det)[:200]


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
        parsed.append({
            "id": ev.get("id"),
            "type": etype,
            "severity": ev.get("severity", "INFO"),
            "timestamp": ev.get("timestamp") or 0,
            "pid": det.get("pid", ""),
            "process": det.get("process_name", ""),
            "description": describe_event(etype, det),
            "details": det,
        })

    behaviour = [e for e in parsed if e["type"] in ("process", "file", "network")]
    iocs = []
    seen = set()
    for e in parsed:
        det = e["details"]
        if e["type"] != "network":
            continue
        if det.get("source") == "pcap":
            key = (det.get("type", "ioc"), det.get("value", ""))
        else:
            key = ("ip:port", f"{det.get('dst_ip', '?')}:{det.get('dst_port', '?')}")
        if key not in seen:
            seen.add(key)
            iocs.append({"type": key[0], "value": key[1], "source": det.get("source", "strace")})

    processes = []
    for e in parsed:
        det = e["details"]
        if e["type"] == "process" and det.get("action") == "execute":
            processes.append({"pid": det.get("pid", ""), "ppid": det.get("ppid", ""),
                              "name": det.get("process_name", ""), "cmdline": det.get("cmdline", "")})

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
        "errors": [e["description"] for e in parsed if e["type"] == "error"],
        "raw_details": details,
    }
