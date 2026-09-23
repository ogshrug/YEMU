import re
import logging
import os

class BehaviourMonitor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.process_info = {} # Store info about PIDs

    def parse_strace(self, log_lines, pid=None):
        """
        Parsed strace log lines.
        Example line: 10:15:30.123456 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
        """
        events = []
        current_pid = pid
        for line in log_lines:
            if not line: continue
            # Extract timestamp if present (-tt)
            timestamp = 0
            ts_match = re.match(r'^(\d{2}:\d{2}:\d{2}\.\d+)\s+', line)
            if ts_match:
                ts_str = ts_match.group(1)
                # Convert HH:MM:SS.mmmmmm to seconds since start or just use float representation
                try:
                    h, m, s = ts_str.split(':')
                    timestamp = int(h) * 3600 + int(m) * 60 + float(s)
                except Exception as e:
                    self.logger.warning(f"Failed to parse timestamp {ts_str}: {e}")

            proc_info = self.process_info.get(current_pid, {
                "process_name": "unknown",
                "exe_path": "[unreadable]",
                "cmdline": "[unreadable]",
                "ppid": "unknown"
            })

            base_event = {
                "pid": current_pid or "N/A",
                "ppid": proc_info.get("ppid", "unknown"),
                "process_name": proc_info["process_name"],
                "exe_path": proc_info["exe_path"],
                "cmdline": proc_info["cmdline"],
                "timestamp": timestamp,
                "raw": line.strip()
            }

            if 'execve' in line:
                match = re.search(r'execve\("(.*?)"', line)
                if match:
                    exe_path = match.group(1)
                    process_name = os.path.basename(exe_path)

                    # Try to extract cmdline from arguments
                    cmdline = exe_path
                    args_match = re.search(r'execve\(".*?", \[(.*?)\]', line)
                    if args_match:
                        args = args_match.group(1).replace('"', '').split(', ')
                        cmdline = " ".join(args)

                    self.process_info[current_pid] = {
                        "process_name": process_name,
                        "exe_path": exe_path,
                        "cmdline": cmdline,
                        "ppid": proc_info.get("ppid", "unknown")
                    }
                    # Update base_event for the current line
                    base_event.update(self.process_info[current_pid])

                    events.append({**base_event,
                        "type": "process",
                        "action": "execute",
                        "path": exe_path,
                        "syscall": "execve"
                    })
            elif 'openat' in line or 'open(' in line:
                match = re.search(r'open(?:at)?\(.*?"(.*?)"', line)
                if match:
                    events.append({**base_event,
                        "type": "file",
                        "action": "open",
                        "path": match.group(1),
                        "syscall": "openat" if "openat" in line else "open"
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
                # clone(...) = 1234
                new_pid_match = re.search(r'=\s+(\d+)$', line.strip())
                new_pid = new_pid_match.group(1) if new_pid_match else "unknown"

                if new_pid != "unknown" and current_pid:
                    self.process_info[new_pid] = {
                        "process_name": proc_info["process_name"], # Initially same as parent
                        "exe_path": proc_info["exe_path"],
                        "cmdline": proc_info["cmdline"],
                        "ppid": current_pid
                    }

                events.append({**base_event,
                    "type": "process",
                    "action": "fork",
                    "child_pid": new_pid,
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
