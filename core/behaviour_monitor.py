import re
import logging

class BehaviourMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def parse_strace(self, log_lines, pid=None):
        """
        Parsed strace log lines.
        Example line: 10:15:30.123456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
        """
        events = []
        for line in log_lines:
            # Extract timestamp if present (-tt)
            timestamp = 0
            ts_match = re.match(r'^(\d{2}:\d{2}:\d{2}\.\d+)\s+', line)
            if ts_match:
                ts_str = ts_match.group(1)
                # Convert HH:MM:SS.mmmmmm to seconds since start or just use float representation
                try:
                    h, m, s = ts_str.split(':')
                    timestamp = int(h) * 3600 + int(m) * 60 + float(s)
                except:
                    pass

            base_event = {
                "pid": pid,
                "timestamp": timestamp,
                "raw": line.strip()
            }

            if 'openat' in line or 'open(' in line:
                match = re.search(r'open(?:at)?\(.*?"(.*?)"', line)
                if match:
                    events.append({**base_event,
                        "type": "file",
                        "action": "open",
                        "path": match.group(1),
                        "syscall": "openat" if "openat" in line else "open"
                    })
            elif 'execve' in line:
                match = re.search(r'execve\("(.*?)"', line)
                if match:
                    events.append({**base_event,
                        "type": "process",
                        "action": "execute",
                        "path": match.group(1),
                        "syscall": "execve"
                    })
            elif 'connect' in line:
                # connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16)
                match = re.search(r'inet_addr\("(.*?)"\)', line)
                port_match = re.search(r'sin_port=htons\((\d+)\)', line)
                if match:
                    events.append({**base_event,
                        "type": "network",
                        "action": "connect",
                        "dst_ip": match.group(1),
                        "dst_port": port_match.group(1) if port_match else "unknown",
                        "syscall": "connect"
                    })
            elif 'clone' in line or 'fork' in line:
                events.append({**base_event,
                    "type": "process",
                    "action": "fork",
                    "syscall": "clone" if "clone" in line else "fork"
                })
            elif 'unlink' in line:
                match = re.search(r'unlink(?:at)?\(.*?"(.*?)"', line)
                if match:
                    events.append({**base_event,
                        "type": "file",
                        "action": "delete",
                        "path": match.group(1),
                        "syscall": "unlink"
                    })
            elif 'write' in line:
                # Simplistic check for writes to files
                match = re.search(r'write\((\d+),', line)
                if match:
                    events.append({**base_event,
                        "type": "file",
                        "action": "write",
                        "fd": match.group(1),
                        "syscall": "write"
                    })
        return events

    def parse_procmon_csv(self, csv_lines):
        # Placeholder for Windows Procmon parser
        return []
