import asyncio
import logging
import os
from datetime import datetime
from core.vm_manager import VMManager

class Orchestrator:
    def __init__(self, db, vm_manager=None, ui_callback=None):
        self.db = db
        self.vm_manager = vm_manager or VMManager(ui_callback=ui_callback)
        self.logger = logging.getLogger(__name__)
        self.ui_callback = ui_callback

    def _notify_ui(self, message, severity="INFO"):
        if self.ui_callback:
            self.ui_callback(message, severity)

    async def run_analysis(self, sample_path, guest_os="ubuntu-clean", snapshot_name="clean-baseline", run_gui=False, run_pcap=False):
        self.logger.info(f"Starting analysis for {sample_path} on {guest_os} (Snapshot: {snapshot_name}, GUI: {run_gui}, PCAP: {run_pcap})")
        self._notify_ui(f"Starting analysis on {guest_os} (Snapshot: {snapshot_name})...")

        # 0. Static Analysis
        from core.yara_engine import YaraEngine
        self.yara_engine = YaraEngine()
        self._notify_ui("Running YARA static analysis...")
        matches = await self.yara_engine.scan_file_async(sample_path)
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
            try:
                ok, msg = await self.vm_manager.verify_environment(guest_os)
                if not ok:
                    self._notify_ui(f"VM verification failed: {msg}", "CRITICAL")
                    raise RuntimeError(msg)

                self._notify_ui(f"Reverting VM to snapshot {snapshot_name}...")
                await self.vm_manager.revert_to_snapshot(guest_os, snapshot_name=snapshot_name)

                self._notify_ui("Injecting sample into VM...")
                # We explicitly tell VMManager to name it 'malware_sample' in /
                guest_sample_path = "/malware_sample"
                if not await self.vm_manager.inject_file(guest_os, sample_path, guest_sample_path):
                    self._notify_ui("Failed to inject sample. Continuing anyway...", "WARN")

                self._notify_ui("Starting VM and waiting for guest agent...")
                started = await self.vm_manager.start_vm(guest_os)
                if not started:
                    self._notify_ui("Failed to start VM.", "CRITICAL")
                    raise RuntimeError("Failed to start VM.")

                await self.vm_manager.wait_for_guest_agent(guest_os)
            except Exception as e:
                self._notify_ui(f"VM Preparation error: {e}", "CRITICAL")
                raise

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
            tcpdump_proc = None
            if run_pcap:
                self._notify_ui("Starting packet capture...")
                # We need to run tcpdump on the host for the specific VM interface or inside the guest
                # For simplicity, let's assume we run it inside the guest if possible,
                # or we just use the host-side capture if we know the interface.
                # Here we will try to run it inside the guest in background.
                await self.vm_manager.run_command(guest_os, "tcpdump -i any -w /tmp/capture.pcap &")

            self._notify_ui("Executing sample with strace monitoring...")
            await self.db.add_event(analysis_id, "process", 0.1, "INFO", {"msg": "Execution started"})

            strace_cmd = f"chmod +x {guest_sample_path} && strace -ff -tt -o /tmp/strace.log {guest_sample_path} &"
            await self.vm_manager.run_command(guest_os, strace_cmd)

            # 5. Memory Scanning and Metadata Extraction
            self._notify_ui("Running in-guest YARA memory scan...")

            # Prepare rules for injection
            rules_local_path = "/tmp/analysis_rules.yar"
            if self.yara_engine.compile_to_file(rules_local_path):
                self._notify_ui("YARA rules compiled for in-guest scan.")
            else:
                self._notify_ui("Failed to compile YARA rules for in-guest scan.", "WARN")

            rules_guest_path = "/tmp/rules.yar"
            await self.vm_manager.inject_file(guest_os, rules_local_path, rules_guest_path)

            # Ensure YARA is in guest
            check_yara = await self.vm_manager.run_command(guest_os, "which yara")
            if not check_yara.strip():
                self._notify_ui("YARA not found in guest, attempting installation...")
                await self.vm_manager.run_command(guest_os, "apt-get update && apt-get install -y yara")

            # Scan memory via /proc. Note: using -C for compiled rules
            yara_cmd = f"yara -C --print-meta --print-strings -r {rules_guest_path} /proc"
            yara_output = await self.vm_manager.run_command(guest_os, yara_cmd)
            yara_matches = self.yara_engine.parse_yara_cli_output(yara_output)

            # Enrich matches with process metadata
            for match in yara_matches:
                pid = match.get('pid')
                if pid and pid != "N/A":
                    # Get process name
                    match['process_name'] = (await self.vm_manager.run_command(guest_os, f"cat /proc/{pid}/comm")).strip() or "[unreadable]"
                    # Get exe path
                    match['exe_path'] = (await self.vm_manager.run_command(guest_os, f"readlink -f /proc/{pid}/exe")).strip() or "[unreadable]"
                    # Get cmdline
                    cmdline_raw = await self.vm_manager.run_command(guest_os, f"cat /proc/{pid}/cmdline")
                    match['cmdline'] = cmdline_raw.replace('\0', ' ').strip() or "[unreadable]"

                self._notify_ui(f"YARA Memory Match: {match['rule']} (PID: {match['pid']})", "WARN")
                await self.db.add_event(analysis_id, "yara", 0, "WARN", match)

            # 6. Collect and Parse results
            self._notify_ui("Collecting behavioral logs...")
            # Wait a bit for sample to finish if it hasn't
            await asyncio.sleep(5)

            if run_pcap:
                self._notify_ui("Stopping packet capture and collecting PCAP...")
                await self.vm_manager.run_command(guest_os, "killall tcpdump")
                await self.vm_manager.run_command(guest_os, "sync")

                # Pull PCAP from VM
                local_pcap = f"storage/captures/{analysis_id}.pcap"
                os.makedirs("storage/captures", exist_ok=True)
                # Need a method to pull file from VM
                if hasattr(self.vm_manager, 'pull_file'):
                    await self.vm_manager.pull_file(guest_os, "/tmp/capture.pcap", local_pcap)

                    from core.network_capture import NetworkCapture
                    net_cap = NetworkCapture()
                    iocs = net_cap.analyze_pcap(local_pcap)
                    for ioc_type, value in iocs:
                        await self.db.add_event(analysis_id, "network", 0, "INFO", {"type": ioc_type, "value": value, "source": "pcap"})
            # With -ff, strace creates multiple files: /tmp/strace.log.<pid>
            # We need to find all of them and parse them
            pids_str = await self.vm_manager.run_command(guest_os, "ls /tmp/strace.log*")
            log_files = pids_str.strip().split()

            from core.behaviour_monitor import BehaviourMonitor
            monitor = BehaviourMonitor()
            all_events = []

            for log_file in log_files:
                pid = log_file.split('.')[-1]
                content = await self.vm_manager.run_command(guest_os, f"cat {log_file}")
                events = monitor.parse_strace(content.splitlines(), pid=pid)
                all_events.extend(events)

            # Sort events by timestamp if available
            all_events.sort(key=lambda x: x.get('timestamp', 0))

            for ev in all_events:
                await self.db.add_event(analysis_id, ev['type'], ev.get('timestamp', 0), "WARN", ev)
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
                yara_matches=yara_matches if 'yara_matches' in locals() else matches
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
