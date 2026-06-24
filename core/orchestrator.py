import asyncio
import logging
import os
from datetime import datetime
from core.vm_manager import VMManager

class Orchestrator:
    def __init__(self, db, vm_manager=None, ui_callback=None):
        self.db = db
        self.vm_manager = vm_manager or VMManager()
        self.logger = logging.getLogger(__name__)
        self.ui_callback = ui_callback

    def _notify_ui(self, message, severity="INFO"):
        if self.ui_callback:
            self.ui_callback(message, severity)

    async def run_analysis(self, sample_path, guest_os="ubuntu-clean", snapshot_name="clean-baseline", run_gui=False):
        self.logger.info(f"Starting analysis for {sample_path} on {guest_os} (Snapshot: {snapshot_name}, GUI: {run_gui})")
        self._notify_ui(f"Starting analysis on {guest_os} (Snapshot: {snapshot_name})...")

        # 0. Static Analysis
        from core.yara_engine import YaraEngine
        yara = YaraEngine()
        self._notify_ui("Running YARA static analysis...")
        matches = await yara.scan_file_async(sample_path)
        for match in matches:
            self._notify_ui(f"YARA Match: {match}", "WARN")

        # 1. Prepare Sample metadata
        import hashlib
        with open(sample_path, "rb") as f:
            data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()

        sample_id = await self.db.add_sample(sha256, md5, os.path.basename(sample_path), "unknown", len(data))
        analysis_id = await self.db.create_analysis(sample_id, datetime.now())

        try:
            # 2. Verify and Reset VM
            self._notify_ui("Verifying VM environment...")
            ok, msg = await self.vm_manager.verify_environment(guest_os)
            if not ok:
                raise RuntimeError(msg)

            self._notify_ui(f"Reverting VM to snapshot {snapshot_name}...")
            await self.vm_manager.revert_to_snapshot(guest_os, snapshot_name=snapshot_name)

            self._notify_ui("Injecting sample into VM...")
            # We explicitly tell VMManager to name it 'malware_sample' in /
            guest_sample_path = "/malware_sample"
            await self.vm_manager.inject_file(guest_os, sample_path, guest_sample_path)

            self._notify_ui("Starting VM and waiting for guest agent...")
            started = await self.vm_manager.start_vm(guest_os)
            if not started:
                raise RuntimeError("Failed to start VM or guest agent timed out.")

            if run_gui:
                self._notify_ui("Opening VM GUI...")
                await self.vm_manager.open_gui(guest_os)
                self._notify_ui("Manual analysis started. VM will remain open.", "INFO")
                await self.db.update_analysis(
                    analysis_id,
                    finished_at=datetime.now(),
                    verdict="manual",
                    yara_matches=matches
                )
                return analysis_id

            # 4. Execute with monitoring
            self._notify_ui("Executing sample with strace monitoring...")
            await self.db.add_event(analysis_id, "process", 0.1, "INFO", {"msg": "Execution started"})

            strace_cmd = f"chmod +x {guest_sample_path} && strace -tt -o /tmp/strace.log {guest_sample_path}"
            await self.vm_manager.run_command(guest_os, strace_cmd)

            # 5. Collect and Parse results
            self._notify_ui("Collecting behavioral logs...")
            strace_log = await self.vm_manager.run_command(guest_os, "cat /tmp/strace.log")
            from core.behaviour_monitor import BehaviourMonitor
            monitor = BehaviourMonitor()
            events = monitor.parse_strace(strace_log.splitlines())

            for ev in events:
                await self.db.add_event(analysis_id, ev['type'], 0, "WARN", ev)
                self._notify_ui(f"Behavior: {ev.get('syscall', 'unknown')}", "WARN")

            # 6. Threat Scoring
            self._notify_ui("Computing threat score...")
            from core.threat_scorer import ThreatScorer
            scorer = ThreatScorer()
            findings = {
                "yara_count": len(matches),
                "syscall_alerts": len(events)
            }
            score = scorer.compute(findings)
            verdict = scorer.get_verdict(score)
            self._notify_ui(f"Analysis complete. Verdict: {verdict} (Score: {score})", "CRITICAL" if score > 70 else "INFO")

            await self.db.update_analysis(
                analysis_id,
                finished_at=datetime.now(),
                threat_score=score,
                verdict=verdict,
                yara_matches=matches
            )

            # 7. Cleanup
            self._notify_ui("Cleaning up VM...")
            await self.vm_manager.stop_vm(guest_os)

        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            self._notify_ui(f"Error: {str(e)}", "CRITICAL")
            await self.db.add_event(analysis_id, "error", 0, "CRITICAL", {"error": str(e)})
            try:
                await self.vm_manager.stop_vm(guest_os)
            except Exception as stop_err:
                self.logger.error(f"Failed to stop VM after analysis error: {stop_err}")

        return analysis_id
