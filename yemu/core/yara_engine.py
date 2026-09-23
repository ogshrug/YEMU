import os
from pathlib import Path
import logging
import concurrent.futures
import asyncio
import re

try:
    import yara
except ImportError:
    yara = None

from yemu import paths

# Rules shipped with the package; always loaded so a fresh install is never rule-less
BUILTIN_RULES = paths.BUILTIN_RULES_FILE

class YaraEngine:
    def __init__(self, rules_dir=None, builtin_rules=BUILTIN_RULES):
        self.rules_dir = Path(rules_dir) if rules_dir else paths.synced_rules_dir()
        self.builtin_rules = Path(builtin_rules) if builtin_rules else None
        self.rules = None
        self.logger = logging.getLogger(__name__)
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.load_rules()

    def _compiles(self, path):
        try:
            yara.compile(filepath=str(path))
            return True
        except Exception:
            return False

    def load_rules(self):
        if not yara:
            self.logger.warning("YARA module not found. Static analysis and memory scanning will be disabled.")
            return

        # namespace -> file; namespaces avoid "duplicated identifier" errors across rule sets
        rule_files = {}
        if self.builtin_rules and self.builtin_rules.is_file() and self._compiles(self.builtin_rules):
            rule_files["builtin"] = str(self.builtin_rules)

        if not self.rules_dir.is_dir():
            self.logger.warning(f"Rules directory {self.rules_dir} does not exist.")
        else:
            index_path = self.rules_dir / "index.yar"
            if index_path.exists() and self._compiles(index_path):
                rule_files["index"] = str(index_path)
            else:
                if index_path.exists():
                    self.logger.error("Failed to compile index.yar, loading rule files individually")
                idx = 0
                for file_path in sorted(self.rules_dir.rglob("*")):
                    # skip hidden dirs such as an in-progress sync's .sync-* staging folder
                    if any(part.startswith(".") for part in file_path.relative_to(self.rules_dir).parts):
                        continue
                    if file_path.suffix in (".yar", ".yara") and file_path.name != "index.yar":
                        if self._compiles(file_path):  # skip problematic files
                            rule_files[f"ns_{idx}"] = str(file_path)
                            idx += 1

        if not rule_files:
            self.logger.warning("No valid YARA rules found.")
            return

        try:
            self.rules = yara.compile(filepaths=rule_files)
            self.logger.info(f"Successfully loaded {len(rule_files)} YARA rule files with namespaces.")
        except Exception as e:
            self.logger.error(f"Bulk YARA compilation with namespaces failed: {e}")
            # Last resort: keep *something* loaded
            fallback = rule_files.get("builtin") or next(iter(rule_files.values()))
            self.rules = yara.compile(filepath=fallback)

    def _format_match(self, match):
        """Helper to format a yara.Match object into a serializable dict."""
        formatted_strings = []
        # In newer yara-python, match.strings is a list of StringMatch objects
        # each having an 'instances' list.
        for s in match.strings:
            identifier = s.identifier
            for instance in s.instances:
                offset = instance.offset
                data = instance.matched_data

                # Data can be bytes, let's hexify and also provide printable ASCII
                hex_data = data.hex(' ')
                printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
                # Truncate to 64 bytes for display
                if len(data) > 64:
                    hex_data = hex_data[:191] + "..."
                    printable = printable[:64] + "..."

                formatted_strings.append({
                    "offset": hex(offset),
                    "identifier": identifier,
                    "data": hex_data,
                    "printable": printable
                })

        return {
            "rule": match.rule,
            "tags": list(match.tags),
            "meta": dict(match.meta),
            "strings": formatted_strings,
            "pid": "N/A",
            "process_name": "unknown",
            "exe_path": "[unreadable]",
            "cmdline": "[unreadable]",
            "path": "[unreadable]"
        }

    def scan_file(self, filepath):
        results = []
        if not self.rules:
            self.logger.error("No YARA rules loaded for scan_file")
            return results
        if not os.path.exists(filepath):
            self.logger.error(f"File not found for YARA scan: {filepath}")
            return results
        try:
            self.logger.info(f"Scanning file: {filepath}")
            matches = self.rules.match(filepath)
            for m in matches:
                res = self._format_match(m)
                res["path"] = filepath
                results.append(res)
        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {e}")
        return results

    async def scan_file_async(self, filepath):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._thread_pool, self.scan_file, filepath)

    def scan_memory(self, dump_path):
        results = []
        if not self.rules:
            self.logger.error("No YARA rules loaded for scan_memory")
            return results
        try:
            self.logger.info(f"Scanning memory: {dump_path}")
            matches = self.rules.match(dump_path)
            results = [self._format_match(m) for m in matches]
        except Exception as e:
            self.logger.error(f"Error scanning memory dump {dump_path}: {e}")
        return results

    def compile_to_file(self, filepath):
        """Saves the compiled rules to a binary file for use with YARA CLI."""
        if not self.rules:
            self.logger.error("No rules to save")
            return False
        try:
            self.rules.save(filepath)
            self.logger.info(f"Compiled YARA rules saved to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save compiled rules: {e}")
            return False

    HEADER = re.compile(r'^(\w+)\s+(?:\[(.*?)\]\s+)?(\S+)$')
    META_PAIR = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^,]*)')

    def parse_yara_cli_output(self, output):
        """
        Parses YARA CLI output (-m/--print-meta, -s/--print-strings). Targets can be a PID
        (process memory scan) or a path such as /proc/1234/... Headers look like:
            rule_name [author="x",description="y"] 1234
            rule_name /proc/1234/mem
        """
        matches = []
        current_match = None
        for line in output.splitlines():
            line = line.strip()
            if not line or line == "TIMEOUT":
                continue

            string_match = re.match(r'^(0x[0-9a-fA-F]+):(\$[^{}\s:]*):\s*(.*)$', line)
            if string_match and current_match:
                offset, identifier, data = string_match.groups()
                current_match["strings"].append({"offset": offset, "identifier": identifier,
                                                 "data": data, "printable": data[:64]})
                continue

            header = self.HEADER.match(line)
            if header:
                rule_name, bracket, target = header.groups()
                if current_match:
                    matches.append(current_match)
                meta, tags = {}, []
                if bracket:
                    if "=" in bracket:
                        meta = {k: v.strip('"') for k, v in self.META_PAIR.findall(bracket)}
                    else:
                        tags = [t.strip() for t in bracket.split(",") if t.strip()]
                pid = "N/A"
                if target.isdigit():
                    pid = target
                else:
                    parts = target.split("/")
                    if len(parts) > 2 and parts[1] == "proc" and parts[2].isdigit():
                        pid = parts[2]
                current_match = {
                    "rule": rule_name,
                    "tags": tags,
                    "meta": meta,
                    "strings": [],
                    "path": target,
                    "pid": pid,
                    "process_name": "unknown",
                    "exe_path": target if pid == "N/A" else "[unreadable]",
                    "cmdline": "[unreadable]",
                }
                continue

            # older CLI style: meta printed on its own lines
            meta_match = re.match(r'^(\w+)\s*[:=]\s*(.*)$', line)
            if meta_match and current_match:
                key, val = meta_match.groups()
                current_match["meta"][key] = val.strip('"')

        if current_match:
            matches.append(current_match)
        return matches
