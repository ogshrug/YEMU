import asyncio
import hashlib
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

        strace_output = ""
        verdict = None
        static_matches = []
        memory_matches = []
        all_yara_matches = []
        score = 0
        analysis_id = None

        # 0. Static Analysis
        try:
            from core.yara_engine import YaraEngine
            self.yara_engine = YaraEngine()
            self._notify_ui("Running YARA static analysis...")
            static_matches = await self.yara_engine.scan_file_async(sample_path)
        except Exception as e:
            self._notify_ui(f"Static analysis failed: {e}", "WARN")
            static_matches = []

        # 1. Prepare Sample metadata
        try:
            size_bytes = 0
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            with open(sample_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
                    size_bytes += len(chunk)
            sha256 = sha256_hash.hexdigest()
            md5 = md5_hash.hexdigest()

            sample_id = await self.db.add_sample(sha256, md5, os.path.basename(sample_path), "unknown", size_bytes)
            if sample_id:
                analysis_id = await self.db.create_analysis(sample_id, datetime.now())
                if not analysis_id:
                    self._notify_ui("Failed to create analysis record in database.", "CRITICAL")
                    return None

                # Add static matches to database
                for match in static_matches:
                    match['source'] = 'static'
                    self._notify_ui(f"YARA Static Match: {match['rule']}", "WARN")
                    await self.db.add_event(analysis_id, "yara", 0, "WARN", match)
            else:
                self._notify_ui("Failed to create sample record in database.", "CRITICAL")
                return None
        except Exception as e:
            self._notify_ui(f"Failed to initialize analysis in database: {e}", "CRITICAL")
            return None

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

                self._notify_ui("Starting VM...")
                started = await self.vm_manager.start_vm(guest_os)
                if not started:
                    self._notify_ui("Failed to start VM.", "CRITICAL")
                    raise RuntimeError("Failed to start VM.")

                self._notify_ui("Waiting for guest agent...")
                await self.vm_manager.wait_for_guest_agent(guest_os)

                self._notify_ui("Injecting sample into VM...")
                # We explicitly tell VMManager to name it 'malware_sample' in /
                guest_sample_path = "/malware_sample"

                # Try agent injection first as it's faster and works on running VM
                if hasattr(self.vm_manager, 'inject_file_via_agent'):
                    success = await self.vm_manager.inject_file_via_agent(guest_os, sample_path, guest_sample_path)
                else:
                    success = await self.vm_manager.inject_file(guest_os, sample_path, guest_sample_path)

                if not success:
                    # Fallback to offline injection if agent fails (might need to stop VM)
                    self._notify_ui("Agent injection failed, trying offline injection...", "WARN")
                    await self.vm_manager.stop_vm(guest_os)
                    if await self.vm_manager.inject_file(guest_os, sample_path, guest_sample_path):
                        await self.vm_manager.start_vm(guest_os)
                        await self.vm_manager.wait_for_guest_agent(guest_os)
                    else:
                        self._notify_ui("Failed to inject sample. Continuing anyway...", "WARN")
            except Exception as e:
                self._notify_ui(f"VM Preparation error: {e}", "CRITICAL")

            if run_gui:
                self._notify_ui("Opening VM GUI...")
                await self.vm_manager.open_gui(guest_os)
                self._notify_ui("Manual analysis started. VM will remain open.", "INFO")
                if analysis_id:
                    await self.db.update_analysis(
                        analysis_id,
                        finished_at=datetime.now(),
                        verdict="manual",
                        yara_matches=static_matches
                    )
                return analysis_id

            # 4. Execute with monitoring
            try:
                if run_pcap:
                    self._notify_ui("Starting packet capture...")
                    await self.vm_manager.run_command(guest_os, "tcpdump -i any -w /tmp/capture.pcap &")

                self._notify_ui("Executing sample with strace monitoring...")
                if analysis_id:
                    await self.db.add_event(analysis_id, "process", 0.1, "INFO", {"msg": "Execution started"})

                strace_cmd = f"chmod +x {guest_sample_path} && strace -ff -tt -o /tmp/strace.log {guest_sample_path} &"
                await self.vm_manager.run_command(guest_os, strace_cmd)
            except Exception as e:
                self._notify_ui(f"Execution failed: {e}", "CRITICAL")

            # 5. Memory Scanning and Metadata Extraction
            try:
                self._notify_ui("Running in-guest YARA memory scan...")

                # Prepare rules for injection
                rules_local_path = "/tmp/analysis_rules.yar"
                if self.yara_engine.compile_to_file(rules_local_path):
                    self._notify_ui("YARA rules compiled for in-guest scan.")
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
                    memory_matches = self.yara_engine.parse_yara_cli_output(yara_output)

                    # Enrich matches with process metadata
                    for match in memory_matches:
                        match['source'] = 'memory'
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
                        if analysis_id:
                            await self.db.add_event(analysis_id, "yara", 0, "WARN", match)
                else:
                    self._notify_ui("Failed to compile YARA rules for in-guest scan.", "WARN")
            except Exception as e:
                self._notify_ui(f"Memory scan failed: {e}", "WARN")
                memory_matches = []

            # 6. Collect and Parse results
            try:
                self._notify_ui("Collecting behavioral logs...")
                # Wait a bit for sample to finish if it hasn't
                await asyncio.sleep(5)

                if run_pcap:
                    try:
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
                                if analysis_id:
                                    await self.db.add_event(analysis_id, "network", 0, "INFO", {"type": ioc_type, "value": value, "source": "pcap"})
                    except Exception as e:
                        self._notify_ui(f"PCAP collection failed: {e}", "WARN")

                # With -ff, strace creates multiple files: /tmp/strace.log.<pid>
                # We need to find all of them and parse them
                try:
                    pids_str = await self.vm_manager.run_command(guest_os, "ls /tmp/strace.log*")
                    log_files = pids_str.strip().split()

                    from core.behaviour_monitor import BehaviourMonitor
                    monitor = BehaviourMonitor()

                    for log_file in log_files:
                        if not log_file.startswith("/tmp/strace.log"): continue
                        pid = log_file.split('.')[-1]
                        content = await self.vm_manager.run_command(guest_os, f"cat {log_file}")
                        events_chunk = monitor.parse_strace(content.splitlines(), pid=pid)
                        events_chunk.sort(key=lambda x: x.get('timestamp', 0))
                        for ev in events_chunk:
                            if analysis_id:
                                await self.db.add_event(analysis_id, ev['type'], ev.get('timestamp', 0), "WARN", ev)
                            self._notify_ui(f"Behavior: {ev.get('syscall', 'unknown')}", "WARN")
                except Exception as e:
                    self._notify_ui(f"Strace collection failed: {e}", "WARN")
                    all_events = []
            except Exception as e:
                self._notify_ui(f"Result collection failed: {e}", "WARN")

            # 6. Threat Scoring
            try:
                self._notify_ui("Computing threat score...")
                from core.threat_scorer import ThreatScorer
                scorer = ThreatScorer()

                all_yara_matches = static_matches + memory_matches

                findings = {
                    "yara_count": len(all_yara_matches),
                    "syscall_alerts": len(all_events)
                }
                score = scorer.compute(findings)
                verdict = scorer.get_verdict(score)
                self._notify_ui(f"Analysis complete. Verdict: {verdict} (Score: {score})", "CRITICAL" if score > 70 else "INFO")

                if analysis_id:
                    await self.db.update_analysis(
                        analysis_id,
                        finished_at=datetime.now(),
                        threat_score=score,
                        verdict=verdict,
                        yara_matches=all_yara_matches
                    )
            except Exception as e:
                self._notify_ui(f"Threat scoring failed: {e}", "WARN")

            # 7. Save Report
            try:
                if analysis_id:
                    self._notify_ui("Saving report...")
                    report_data = {
                        "filename": os.path.basename(sample_path),
                        "sha256": sha256,
                        "md5": md5,
                        "score": score,
                        "verdict": verdict,
                        "yara_matches": all_yara_matches,
                    }
                    await self.db.update_analysis(analysis_id, report_json=report_data)

                    from storage.report_store import ReportStore
                    store = ReportStore()
                    store.save_json(analysis_id, report_data)
                    store.generate_pdf(analysis_id, report_data)
                    self._notify_ui("Report saved successfully.", "INFO")
            except Exception as e:
                self._notify_ui(f"Failed to save report: {e}", "WARN")

            # 8. Cleanup
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
