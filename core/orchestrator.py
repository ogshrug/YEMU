import asyncio
import logging
import os
from datetime import datetime
from core.vm_manager import VMManager

class Orchestrator:
    def __init__(self, db, vm_manager=None):
        self.db = db
        self.vm_manager = vm_manager or VMManager(use_mock=True)
        self.logger = logging.getLogger(__name__)

    async def run_analysis(self, sample_path, guest_os="ubuntu-clean"):
        self.logger.info(f"Starting analysis for {sample_path} on {guest_os}")

        # 0. Static Analysis
        from core.yara_engine import YaraEngine
        yara = YaraEngine()
        matches = yara.scan_file(sample_path)

        # 1. Prepare Sample metadata
        import hashlib
        with open(sample_path, "rb") as f:
            data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()

        sample_id = await self.db.add_sample(sha256, md5, os.path.basename(sample_path), "unknown", len(data))
        analysis_id = await self.db.create_analysis(sample_id, datetime.now())

        try:
            # 2. Reset VM
            await self.vm_manager.revert_to_snapshot(guest_os)
            await self.vm_manager.start_vm(guest_os)

            # 3. Inject sample
            await self.vm_manager.inject_file(guest_os, sample_path, "/tmp/sample")

            # 4. Execute with monitoring
            await self.db.add_event(analysis_id, "process", 0.1, "INFO", {"msg": "Execution started"})

            # Start strace in background if possible, or just wrap execution
            strace_cmd = "chmod +x /tmp/sample && strace -tt -o /tmp/strace.log /tmp/sample"
            await self.vm_manager.run_command(guest_os, strace_cmd)

            # 5. Collect and Parse results
            strace_log = await self.vm_manager.run_command(guest_os, "cat /tmp/strace.log")
            from core.behaviour_monitor import BehaviourMonitor
            monitor = BehaviourMonitor()
            events = monitor.parse_strace(strace_log.splitlines())

            for ev in events:
                await self.db.add_event(analysis_id, ev['type'], 0, "WARN", ev)

            # 6. Threat Scoring
            from core.threat_scorer import ThreatScorer
            scorer = ThreatScorer()
            findings = {
                "yara_count": len(matches),
                "syscall_alerts": len(events)
            }
            score = scorer.compute(findings)
            verdict = scorer.get_verdict(score)

            # Update analysis record
            # (Requires a method in Database to update analysis)

            # 7. Cleanup
            await self.vm_manager.stop_vm(guest_os)

        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            await self.db.add_event(analysis_id, "error", 0, "CRITICAL", {"error": str(e)})
            try:
                await self.vm_manager.stop_vm(guest_os)
            except Exception as stop_err:
                self.logger.error(f"Failed to stop VM after analysis error: {stop_err}")

        return analysis_id
