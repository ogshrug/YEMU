import logging
import os
import posixpath
import re

# one strace -tt line: "10:15:30.123456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3"
LINE = re.compile(r"^(?:(\d{2}):(\d{2}):(\d{2}(?:\.\d+)?)\s+)?(\w+)\((.*)$")
RESULT = re.compile(r"\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?")
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
WRITE_FLAGS = re.compile(r"O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)")
OPEN = {"open", "openat", "openat2", "creat"}
RENAME = {"rename", "renameat", "renameat2"}
LINK = {"link", "linkat", "symlink", "symlinkat"}
DELETE = {"unlink", "unlinkat", "rmdir"}
CHMOD = {"chmod", "fchmodat", "fchmodat2"}
SEND = {"sendto", "sendmmsg", "sendmsg", "send"}
# a hostname as it appears in a DNS question
HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$", re.I)


def _unescape(s):
    """Bytes of a strace string literal (C escapes: \\n, \\x41, \\101, \\\\ ...)."""
    out, i = bytearray(), 0
    while i < len(s):
        c = s[i]
        if c != "\\" or i + 1 == len(s):
            out += c.encode("utf-8", "surrogateescape")
            i += 1
            continue
        n = s[i + 1]
        if n == "x":
            out.append(int(s[i + 2 : i + 4], 16))
            i += 4
        elif n.isdigit():
            j = i + 1
            while j < len(s) and j < i + 4 and s[j] in "01234567":
                j += 1
            out.append(int(s[i + 1 : j], 8) & 0xFF)
            i = j
        else:
            out.append({"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8}.get(n, ord(n)))
            i += 2
    return bytes(out)


def dns_query_name(payload):
    """The name asked for in a DNS query packet, or None if payload isn't one."""
    if len(payload) < 17 or payload[2] & 0x80 or int.from_bytes(payload[4:6], "big") != 1:
        return None
    labels: list[str] = []
    i = 12
    while i < len(payload):
        n = payload[i]
        if n == 0:
            name = ".".join(labels)
            return name.lower() if HOSTNAME.match(name) else None
        if n > 63 or i + 1 + n > len(payload):
            return None
        labels.append(payload[i + 1 : i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return None


class BehaviourMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.process_info = {}  # pid -> name/exe/cmdline/ppid
        self.fds = {}  # (pid, fd) -> path opened for writing
        self.cwd = {}  # pid -> working directory, from chdir; children inherit it

    def parse_strace(self, log_lines, pid=None):
        """Events from one strace -ff -tt log (the log of one PID)."""
        events = []
        current_pid = pid
        for line in log_lines:
            m = LINE.match(line.strip()) if line else None
            if not m:
                continue
            h, mi, s, syscall, rest = m.groups()
            timestamp = int(h) * 3600 + int(mi) * 60 + float(s) if h else 0.0
            r = RESULT.search(rest)
            result, errno = (r.group(1), r.group(2)) if r else ("?", None)
            ok = result != "?" and not result.startswith("-")
            strings = STRING.findall(rest)

            proc = self.process_info.get(
                current_pid,
                {"process_name": "unknown", "exe_path": "[unreadable]", "cmdline": "[unreadable]", "ppid": "unknown"},
            )
            base = {
                "pid": current_pid or "N/A",
                "ppid": proc.get("ppid", "unknown"),
                "process_name": proc["process_name"],
                "exe_path": proc["exe_path"],
                "cmdline": proc["cmdline"],
                "timestamp": timestamp,
                "syscall": syscall,
                "raw": line.strip(),
            }
            if not ok:
                base["result"] = errno or result

            # relative names are relative to the working directory, unless a directory fd is given (unknown here)
            cwd = self.cwd.get(current_pid) if not re.match(r"\d+,", rest) else None

            def resolve(path, cwd=cwd):
                return posixpath.normpath(posixpath.join(cwd, path)) if cwd and path and path[0] != "/" else path

            def file_event(action, path, base=base, **extra):
                events.append({**base, "type": "file", "action": action, "path": resolve(path), **extra})

            if syscall in ("execve", "execveat") and strings:
                exe_path = _unescape(strings[0]).decode(errors="replace")
                args = re.search(r"\[(.*?)\]", rest)
                cmdline = (
                    " ".join(_unescape(a).decode(errors="replace") for a in STRING.findall(args.group(1)))
                    if args
                    else exe_path
                )
                if ok:
                    self.process_info[current_pid] = {
                        "process_name": os.path.basename(exe_path),
                        "exe_path": exe_path,
                        "cmdline": cmdline or exe_path,
                        "ppid": proc.get("ppid", "unknown"),
                    }
                    base.update(self.process_info[current_pid])
                events.append({**base, "type": "process", "action": "execute", "path": exe_path, "cmdline": cmdline})
            elif syscall in OPEN and strings:
                path = _unescape(strings[0]).decode(errors="replace")
                writes = syscall == "creat" or bool(WRITE_FLAGS.search(rest))
                if writes and ok:
                    self.fds[(current_pid, result)] = resolve(path)
                if writes or not path.startswith(("/proc/", "/sys/", "/dev/")):
                    file_event("write" if writes else "open", path)
            elif syscall in ("write", "pwrite64", "writev") and ok:
                fd = rest.split(",", 1)[0].strip()
                path = self.fds.pop((current_pid, fd), None)  # one event per file, not per write() call
                if path:
                    file_event("write", path, fd=fd)
            elif syscall == "chdir" and ok and strings:
                target = _unescape(strings[0]).decode(errors="replace")
                base_dir = self.cwd.get(current_pid, "")
                if target.startswith("/") or base_dir:
                    self.cwd[current_pid] = posixpath.normpath(posixpath.join(base_dir, target))
            elif syscall == "close":
                self.fds.pop((current_pid, rest.split(")", 1)[0].strip()), None)
            elif syscall in RENAME and len(strings) >= 2:
                src, dst = (_unescape(x).decode(errors="replace") for x in strings[:2])
                file_event("rename", dst, src=src)
            elif syscall in DELETE and strings:
                file_event("delete", _unescape(strings[0]).decode(errors="replace"))
            elif syscall in ("mkdir", "mkdirat") and strings:
                file_event("mkdir", _unescape(strings[0]).decode(errors="replace"))
            elif syscall in CHMOD and strings:
                mode = re.search(r",\s*(0[0-7]+)", rest)
                file_event("chmod", _unescape(strings[0]).decode(errors="replace"), mode=mode.group(1) if mode else "")
            elif syscall in LINK and len(strings) >= 2:
                target, path = (_unescape(x).decode(errors="replace") for x in strings[:2])
                file_event("link", path, target=target)
            elif syscall == "connect":
                ip = re.search(r'inet_addr\("([^"]+)"\)', rest) or re.search(r'inet_pton\(AF_INET6,\s*"([^"]+)"', rest)
                port = re.search(r"sin6?_port=htons\((\d+)\)", rest)
                if ip:
                    events.append(
                        {
                            **base,
                            "type": "network",
                            "action": "connect",
                            "dst_ip": ip.group(1),
                            "dst_port": port.group(1) if port else "unknown",
                        }
                    )
            elif syscall in SEND:
                for raw in strings:
                    name = dns_query_name(_unescape(raw))
                    if name:
                        events.append({**base, "type": "network", "action": "dns", "query": name})
            elif syscall in ("clone", "clone3", "fork", "vfork") and ok:
                if current_pid in self.cwd:
                    self.cwd[result] = self.cwd[current_pid]
                self.process_info[result] = {
                    "process_name": proc["process_name"],  # the child keeps the parent's image until it execs
                    "exe_path": proc["exe_path"],
                    "cmdline": proc["cmdline"],
                    "ppid": current_pid,
                }
                events.append({**base, "type": "process", "action": "fork", "child_pid": result})
        return events

    def parse_procmon_csv(self, csv_lines):
        # Placeholder for Windows Procmon parser
        return []
