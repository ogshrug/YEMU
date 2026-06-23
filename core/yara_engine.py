import yara
import os
import logging
import concurrent.futures
import asyncio

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

    def scan_file(self, filepath):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(filepath)
            return [str(m) for m in matches]
        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {e}")
            return []

    async def scan_file_async(self, filepath):
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return await loop.run_in_executor(pool, self.scan_file, filepath)

    def scan_memory(self, dump_path):
        if not self.rules:
            return []
        try:
            matches = self.rules.match(dump_path)
            return [str(m) for m in matches]
        except Exception as e:
            self.logger.error(f"Error scanning memory dump {dump_path}: {e}")
            return []
