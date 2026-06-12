import random
import asyncio
from datetime import datetime

class MockOrchestrator:
    def __init__(self, db, ui_callback=None):
        self.db = db
        self.ui_callback = ui_callback # For real-time log updates

    async def run_mock_analysis(self, filename):
        # 1. Create Sample
        sample_id = await self.db.add_sample(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            filename=filename,
            file_type="ELF 64-bit LSB executable",
            size_bytes=1024
        )

        analysis_id = await self.db.create_analysis(sample_id, datetime.now())

        # 2. Simulate Log Stream
        logs = [
            ("INFO", "Initializing VM: ubuntu-clean"),
            ("INFO", "Injecting sample..."),
            ("INFO", "Starting execution..."),
            ("WARN", "Process attempted to read /etc/shadow"),
            ("CRITICAL", "Outbound connection to 194.168.1.5:4444 detected"),
            ("INFO", "YARA match: Ransomware_Generic"),
            ("INFO", "Execution finished. Cleaning up.")
        ]

        for sev, msg in logs:
            await asyncio.sleep(1)
            await self.db.add_event(analysis_id, "mock", 0, sev, {"msg": msg})
            if self.ui_callback:
                self.ui_callback(msg, sev)

        return analysis_id
