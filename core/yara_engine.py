import yara
import os
import logging
import concurrent.futures
import asyncio
import re

class YaraEngine:
    def __init__(self, rules_dir="rules/yara-rules"):
        self.rules_dir = rules_dir
        self.rules = None
        self.logger = logging.getLogger(__name__)
        self.load_rules()

    def load_rules(self):
        # We try to compile rules one by one if they fail in bulk
        # But first, let's try to compile the main index
        index_path = os.path.join(self.rules_dir, "index.yar")

        if os.path.exists(index_path):
            try:
                self.rules = yara.compile(filepath=index_path)
                self.logger.info("Successfully loaded YARA rules from index.yar")
                return
            except Exception as e:
                self.logger.error(f"Failed to compile index.yar: {e}")

        # If index fails or doesn't exist, we'll try to load individual categories
        # to avoid "duplicated identifier" errors which often happen when including everything at once
        self.logger.info("Attempting to load rules individually to avoid collisions...")

        compiled_rules = []
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if (file.endswith(".yar") or file.endswith(".yara")) and file != "index.yar":
                    full_path = os.path.join(root, file)
                    try:
                        # Test compile individual file
                        r = yara.compile(filepath=full_path)
                        compiled_rules.append(full_path)
                    except:
                        continue # Skip problematic files

        # Now try to compile the list of "good" files
        # We still might get collisions if different files use same identifiers
        # In a real sandbox, we might want to keep them separate or use namespaces
        # For now, let's try to load them with unique namespaces if possible

        rule_files = {}
        for idx, path in enumerate(compiled_rules):
            namespace = f"ns_{idx}"
            rule_files[namespace] = path

        try:
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
                self.logger.info(f"Successfully loaded {len(rule_files)} YARA rule files with namespaces.")
            else:
                self.logger.warning("No valid YARA rules found.")
        except Exception as e:
            self.logger.error(f"Bulk YARA compilation with namespaces failed: {e}")
            # Last resort: just use the first successful one for now to ensure we have *something*
            if compiled_rules:
                self.rules = yara.compile(filepath=compiled_rules[0])

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
        if not self.rules:
            self.logger.error("No YARA rules loaded for scan_file")
            return []
        try:
            self.logger.info(f"Scanning file: {filepath}")
            matches = self.rules.match(filepath)
            results = []
            for m in matches:
                res = self._format_match(m)
                res["path"] = filepath
                results.append(res)
            return results
        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {e}")
            return []

    async def scan_file_async(self, filepath):
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return await loop.run_in_executor(pool, self.scan_file, filepath)

    def scan_memory(self, dump_path):
        if not self.rules:
            self.logger.error("No YARA rules loaded for scan_memory")
            return []
        try:
            self.logger.info(f"Scanning memory: {dump_path}")
            matches = self.rules.match(dump_path)
            return [self._format_match(m) for m in matches]
        except Exception as e:
            self.logger.error(f"Error scanning memory dump {dump_path}: {e}")
            return []

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

    def parse_yara_cli_output(self, output):
        """
        Parses YARA CLI output with --print-meta --print-strings flags.
        Example line: suspicious_rule [tag1] /proc/1234/mem
        """
        matches = []
        current_match = None

        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check for new match: rule_name [tags] path
            # Regex to match: rule [tag1,tag2] /path/to/file
            match_header = re.match(r'^(\w+)\s+\[(.*?)\]\s+(.*)$', line)
            # Or without tags: rule /path/to/file
            if not match_header:
                match_header = re.match(r'^(\w+)\s+(/.*)$', line)
                if match_header:
                    rule_name = match_header.group(1)
                    tags = []
                    path = match_header.group(2)
                else:
                    rule_name = None
            else:
                rule_name = match_header.group(1)
                tags = [t.strip() for t in match_header.group(2).split(',')]
                path = match_header.group(3)

            if rule_name:
                if current_match:
                    matches.append(current_match)

                pid = "N/A"
                if "/proc/" in path:
                    # Extract PID from /proc/<pid>/mem
                    parts = path.split('/')
                    if len(parts) > 2 and parts[1] == 'proc' and parts[2].isdigit():
                        pid = parts[2]

                current_match = {
                    "rule": rule_name,
                    "tags": tags,
                    "meta": {},
                    "strings": [],
                    "path": path,
                    "pid": pid,
                    "process_name": "unknown",
                    "exe_path": path if pid == "N/A" else "[unreadable]",
                    "cmdline": "[unreadable]"
                }
                continue

            if current_match:
                # Check for meta: key=value or key: value
                meta_match = re.match(r'^(\w+)\s*[:=]\s*(.*)$', line)
                if meta_match and not line.startswith('0x'):
                    key, val = meta_match.groups()
                    current_match["meta"][key] = val.strip('"')
                    continue

                # Check for strings: 0xoffset:identifier: data
                string_match = re.match(r'^(0x[0-9a-fA-F]+):(\$[^{}\s]*):\s*(.*)$', line)
                if string_match:
                    offset, identifier, data = string_match.groups()
                    # data might be hex or string in YARA CLI
                    current_match["strings"].append({
                        "offset": offset,
                        "identifier": identifier,
                        "data": data,
                        "printable": "" # Would need more complex parsing to get both
                    })

        if current_match:
            matches.append(current_match)

        return matches
