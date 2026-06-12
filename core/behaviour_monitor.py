import re
import logging

class BehaviourMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def parse_strace(self, log_lines):
        """
        Simplistic strace parser.
        Example line: openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
        """
        events = []
        # Regex for common syscalls
        # openat, execve, connect, write, unlink
        for line in log_lines:
            if 'openat' in line:
                match = re.search(r'openat\(.*?"(.*?)"', line)
                if match:
                    events.append({
                        "type": "file",
                        "action": "open",
                        "path": match.group(1),
                        "raw": line.strip()
                    })
            elif 'execve' in line:
                match = re.search(r'execve\("(.*?)"', line)
                if match:
                    events.append({
                        "type": "process",
                        "action": "execute",
                        "path": match.group(1),
                        "raw": line.strip()
                    })
            elif 'connect' in line:
                # connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16)
                match = re.search(r'inet_addr\("(.*?)"\)', line)
                port_match = re.search(r'sin_port=htons\((\d+)\)', line)
                if match:
                    events.append({
                        "type": "network",
                        "action": "connect",
                        "dst_ip": match.group(1),
                        "dst_port": port_match.group(1) if port_match else "unknown",
                        "raw": line.strip()
                    })
        return events

    def parse_procmon_csv(self, csv_lines):
        # Placeholder for Windows Procmon parser
        return []
