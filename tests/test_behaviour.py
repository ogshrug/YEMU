import pytest

from yemu.core import heuristics
from yemu.core.behaviour_monitor import BehaviourMonitor, _unescape, dns_query_name
from yemu.core.orchestrator import sample_kind
from yemu.core.report_model import build_report

# glibc's resolver as strace prints it: the 12-byte label length comes out as \f
DNS_SEND = (
    '10:00:01.000000 sendmmsg(5, [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\\22\\4\\1\\0\\0\\1\\0\\0'
    '\\0\\0\\0\\0\\6update\\4code\\fvisualstudio\\3com\\0\\0\\1\\0\\1", iov_len=45}], msg_iovlen=1, msg_controllen=0, '
    "msg_flags=0}, msg_len=45}], 1, MSG_NOSIGNAL) = 1"
)


def parse(lines, pid="100"):
    return BehaviourMonitor().parse_strace(lines, pid=pid)


def test_dns_lookups_are_decoded_from_the_resolver_payload():
    (ev,) = parse([DNS_SEND])
    assert ev["type"] == "network" and ev["action"] == "dns" and ev["query"] == "update.code.visualstudio.com"
    assert dns_query_name(_unescape("\\1\\0\\1\\0\\0\\1")) is None  # too short to be a query
    assert dns_query_name(b"\x00" * 12 + b"\x03abc\x00") is None  # qdcount 0


def test_file_changes_carry_paths_and_writes_are_reported_once_per_file():
    events = parse(
        [
            '10:00:00.1 openat(AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY|O_CLOEXEC) = 3',
            '10:00:00.2 openat(AT_FDCWD, "/etc/apt/sources.list.d/x.list", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4',
            "10:00:00.3 write(4, \"deb https://x\\n\", 14) = 14",
            '10:00:00.4 write(4, "more", 4) = 4',
            '10:00:00.5 renameat2(AT_FDCWD, "/usr/bin/code.new", AT_FDCWD, "/usr/bin/code", RENAME_NOREPLACE) = 0',
            '10:00:00.6 symlinkat("/usr/share/code/bin/code", AT_FDCWD, "/usr/bin/code") = 0',
            '10:00:00.7 fchmodat(AT_FDCWD, "/usr/share/code/chrome-sandbox", 04755) = 0',
            '10:00:00.8 unlinkat(AT_FDCWD, "/tmp/x", 0) = -1 ENOENT (No such file or directory)',
            '10:00:00.9 mkdir("/opt/thing", 0755) = 0',
        ]
    )
    got = [(e["action"], e["path"], e.get("result")) for e in events]
    assert got == [
        ("open", "/usr/lib/libc.so.6", None),
        ("write", "/etc/apt/sources.list.d/x.list", None),
        ("write", "/etc/apt/sources.list.d/x.list", None),  # the first write() only
        ("rename", "/usr/bin/code", None),
        ("link", "/usr/bin/code", None),
        ("chmod", "/usr/share/code/chrome-sandbox", None),
        ("delete", "/tmp/x", "ENOENT"),
        ("mkdir", "/opt/thing", None),
    ]
    assert events[3]["src"] == "/usr/bin/code.new" and events[5]["mode"] == "04755"


def test_connect_handles_ipv6_and_records_failures():
    (v4, v6) = parse(
        [
            '10:00:00.1 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("13.107.6.1")}, 16)'
            " = -1 ENETUNREACH (Network is unreachable)",
            '10:00:00.2 connect(4, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), '
            'inet_pton(AF_INET6, "2620:1ec:c11::200", &sin6_addr), sin6_scope_id=0}, 28) = 0',
        ]
    )
    assert (v4["dst_ip"], v4["dst_port"], v4["result"]) == ("13.107.6.1", "443", "ENETUNREACH")
    assert (v6["dst_ip"], v6["dst_port"], v6.get("result")) == ("2620:1ec:c11::200", "443", None)


def test_failed_execve_is_marked_and_keeps_the_parent_identity():
    (ev,) = parse(
        ['10:00:00.1 execve("/tmp/x.deb", ["/tmp/x.deb"], 0x7ffd /* 10 vars */) = -1 ENOEXEC (Exec format error)']
    )
    assert ev["action"] == "execute" and ev["result"] == "ENOEXEC" and ev["process_name"] == "unknown"


def test_disk_diff_is_reported_but_never_scored():
    events = [{"type": "file", "action": "changed", "path": "/etc/cron.d/x", "source": "fsdiff"}]
    assert heuristics.analyse(events)["persistence_detected"] is False
    rows = [{"event_type": "file", "details": '{"action": "changed", "path": "/etc/cron.d/x", "source": "fsdiff"}'}]
    rows.append({"event_type": "network", "details": '{"action": "dns", "query": "evil.example", "process_name": "x"}'})
    report = build_report({}, rows)
    assert report["changed_files"] == [
        {"path": "/etc/cron.d/x", "action": "changed", "process": "", "source": "fsdiff"}
    ]
    assert {"type": "domain", "value": "evil.example", "source": "strace", "process": "x"} in report["iocs"]


def test_an_indicator_seen_by_strace_and_pcap_is_one_row_crediting_the_process():
    rows = [
        {"event_type": "network", "details": '{"type": "domain", "value": "ntp.ubuntu.com", "source": "pcap"}'},
        {"event_type": "network", "details": '{"type": "domain", "value": "x.example", "source": "pcap"}'},
        {"event_type": "network", "details": '{"action": "dns", "query": "x.example", "process_name": "curl"}'},
    ]
    iocs = build_report({}, rows)["iocs"]
    assert iocs == [
        {"type": "domain", "value": "x.example", "source": "strace, pcap", "process": "curl"},
        {"type": "domain", "value": "ntp.ubuntu.com", "source": "pcap", "process": ""},
    ]


@pytest.mark.parametrize(
    "head,kind",
    [
        (b"!<arch>\ndebian-binary   ", "deb"),
        (b"\x7fELF\x02\x01", "elf"),
        (b"#!/bin/sh\n", "script"),
        (b"PK\x03\x04", "unknown"),
    ],
)
def test_sample_kind(tmp_path, head, kind):
    p = tmp_path / "s"
    p.write_bytes(head + b"\0" * 64)
    assert sample_kind(str(p)) == kind


def test_event_cap_keeps_processes_over_file_churn():
    from yemu.core.orchestrator import _keep_events

    churn = [{"type": "file", "action": "write", "path": f"/usr/share/x/{i}", "timestamp": i} for i in range(50)]
    failed = [{"type": "file", "action": "delete", "path": "/x", "result": "ENOENT", "timestamp": 1}]
    late = [{"type": "process", "action": "execute", "path": "/bin/ln", "timestamp": 99}]
    kept = _keep_events(failed + churn + late, 10)
    assert len(kept) == 10 and kept[-1] is late[0] and failed[0] not in kept
    assert [e["timestamp"] for e in kept] == sorted(e["timestamp"] for e in kept)


def test_relative_paths_follow_chdir_and_fork():
    m = BehaviourMonitor()
    m.parse_strace(['10:00:00.1 chdir("/var/lib/dpkg/tmp.ci") = 0', "10:00:00.2 vfork() = 7"], pid="5")
    (ev,) = m.parse_strace(['10:00:00.3 unlinkat(AT_FDCWD, "control", 0) = 0'], pid="7")
    assert ev["path"] == "/var/lib/dpkg/tmp.ci/control"
    (ev,) = m.parse_strace(['10:00:00.4 openat(9, "x", O_WRONLY|O_CREAT, 0644) = 3'], pid="7")
    assert ev["path"] == "x"  # relative to an fd YEMU can't resolve


def test_failed_probe_of_a_sensitive_file_is_not_a_finding():
    probe = {"type": "file", "action": "open", "path": "/root/.gnupg/gpg.conf", "result": "ENOENT"}
    denied = {"type": "file", "action": "open", "path": "/etc/shadow", "result": "EACCES"}
    assert heuristics.analyse([probe])["reasons"] == []
    assert heuristics.analyse([denied])["reasons"] == [
        {"kind": "suspicious", "text": "Accessed sensitive file /etc/shadow"}
    ]


def test_writes_through_an_fd_keep_the_resolved_path():
    events = parse(
        [
            '10:00:00.1 chdir("/var/lib/dpkg/tmp.ci") = 0',
            '10:00:00.2 openat(AT_FDCWD, "control", O_WRONLY|O_CREAT, 0600) = 3',
            '10:00:00.3 write(3, "Package: code", 13) = 13',
        ]
    )
    assert [e["path"] for e in events] == ["/var/lib/dpkg/tmp.ci/control"] * 2


def test_event_cap_keeps_sensitive_reads():
    from yemu.core.orchestrator import _keep_events

    reads = [{"type": "file", "action": "open", "path": f"/usr/lib/{i}.so"} for i in range(20)]
    shadow = {"type": "file", "action": "open", "path": "/etc/shadow"}
    assert shadow in _keep_events(reads + [shadow], 5)
