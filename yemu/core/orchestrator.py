import asyncio
import hashlib
import logging
import os
import re
import secrets
import shlex
import tempfile
from collections import Counter
from datetime import datetime

from yemu import config as yemu_config
from yemu import paths
from yemu.core import heuristics
from yemu.core.vm_backend import create_backend

q = shlex.quote
STRACE_LOG = re.compile(r"^strace\.(\d+)$")
MAX_SCAN_PIDS = 10


class AnalysisAborted(RuntimeError):
    """The VM could not be prepared safely; the sample was not (fully) executed."""


class _Run:
    def __init__(self, sample_path, guest_os, snapshot, run_gui, run_pcap):
        self.sample_path = sample_path
        self.guest_os = guest_os
        self.snapshot = snapshot
        self.run_gui = run_gui
        self.run_pcap = run_pcap
        self.analysis_id = None
        self.sha256 = self.md5 = ""
        self.size = 0
        self.static_matches = []
        self.memory_matches = []
        self.events = []
        self.dropped_events = 0
        self.keep_vm = False
        # per-run guest paths; random so a sample can't predict or pre-plant them
        self.workdir = f"/tmp/yemu-{secrets.token_hex(4)}"
        base = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(sample_path))[:64].lstrip(".") or "sample"
        self.guest_sample = f"{self.workdir}/{base}"
        self.guest_strace = f"{self.workdir}/strace"
        self.guest_pcap = f"{self.workdir}/capture.pcap"
        self.guest_rules = f"{self.workdir}/rules.yarc"


class Orchestrator:
    def __init__(self, db, vm_manager=None, ui_callback=None, config=None):
        self.db = db
        self.config = config or yemu_config.load()
        self.vm_manager = vm_manager or create_backend(self.config["vm"]["backend"], ui_callback=ui_callback)
        self.logger = logging.getLogger(__name__)
        self.ui_callback = ui_callback

    def _notify_ui(self, message, severity="INFO"):
        # the progress stream goes to the log file via "yemu.analysis"; the UI/CLI shows it through ui_callback
        level = {"CRITICAL": logging.ERROR, "WARN": logging.WARNING}.get(severity, logging.INFO)
        logging.getLogger("yemu.analysis").log(level, message)
        if self.ui_callback:
            try:
                self.ui_callback(message, severity)
            except Exception as e:  # a broken UI (closed pipe, destroyed window) must not abort the analysis
                self.logger.debug(f"ui_callback failed: {e}")

    async def _cmd(self, run, command):
        return await self.vm_manager.run_command(run.guest_os, command)

    # ------------------------------------------------------------------ entry point
    async def run_analysis(self, sample_path, guest_os="ubuntu-clean", snapshot_name="clean-baseline", run_gui=False, run_pcap=False):
        acfg = self.config["analysis"]
        run = _Run(sample_path, guest_os, snapshot_name, run_gui, run_pcap)
        self._notify_ui(f"Starting analysis on {guest_os} (Snapshot: {snapshot_name})...")

        try:
            size = os.path.getsize(sample_path)
        except OSError as e:
            self._notify_ui(f"Cannot read sample: {e}", "CRITICAL")
            return None
        if size > acfg["max_sample_mb"] * 1024 * 1024:
            self._notify_ui(f"Sample is {size / 1048576:.0f} MB; the limit is {acfg['max_sample_mb']} MB "
                            "([analysis].max_sample_mb).", "CRITICAL")
            return None

        await self._static_scan(run)
        if not await self._create_records(run):
            return None

        status, error = "completed", None
        try:
            try:
                await asyncio.wait_for(self._pipeline(run), timeout=acfg["timeout"])
                if run.keep_vm:
                    status = "manual"
            except asyncio.TimeoutError:
                status, error = "timeout", f"Analysis exceeded {acfg['timeout']}s ([analysis].timeout)"
                self._notify_ui(error, "CRITICAL")
            except AnalysisAborted as e:
                status, error = "failed", str(e)
                self._notify_ui(f"Analysis aborted: {e}", "CRITICAL")
            except Exception as e:
                status, error = "failed", f"{type(e).__name__}: {e}"
                self.logger.exception("Analysis failed")
                self._notify_ui(f"Error: {e}", "CRITICAL")

            if error:
                await self.db.add_event(run.analysis_id, "error", 0, "CRITICAL", {"error": error})
            if status != "manual":
                await self._score_and_save(run, status)
        finally:
            if not run.keep_vm:
                # always power off, whatever happened above; the next run reverts anyway
                self._notify_ui("Cleaning up VM...")
                try:
                    await self.vm_manager.stop_vm(guest_os)
                except Exception as stop_err:
                    self._notify_ui(f"Failed to stop VM: {stop_err}", "CRITICAL")
            await self.db.update_analysis(run.analysis_id, finished_at=datetime.now(), status=status, error=error)
        return run.analysis_id

    # ------------------------------------------------------------------ stages
    async def _static_scan(self, run):
        try:
            from yemu.core.yara_engine import YaraEngine
            self.yara_engine = YaraEngine(rules_dir=paths.synced_rules_dir())
            self._notify_ui("Running YARA static analysis...")
            run.static_matches = await self.yara_engine.scan_file_async(run.sample_path)
            for m in run.static_matches:
                m["source"] = "static"
                self._notify_ui(f"YARA Static Match: {m['rule']}", "WARN")
        except Exception as e:
            self.yara_engine = None
            self._notify_ui(f"Static analysis failed: {e}", "WARN")

    async def _create_records(self, run):
        try:
            sha256, md5 = hashlib.sha256(), hashlib.md5()
            with open(run.sample_path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 16), b""):
                    sha256.update(chunk)
                    md5.update(chunk)
                    run.size += len(chunk)
            run.sha256, run.md5 = sha256.hexdigest(), md5.hexdigest()
            sample_id = await self.db.add_sample(run.sha256, run.md5, os.path.basename(run.sample_path), "unknown", run.size)
            if not sample_id:
                self._notify_ui("Failed to create sample record in database.", "CRITICAL")
                return False
            run.analysis_id = await self.db.create_analysis(sample_id, datetime.now(), guest_os=run.guest_os,
                                                            snapshot=run.snapshot)
            if not run.analysis_id:
                self._notify_ui("Failed to create analysis record in database.", "CRITICAL")
                return False
            await self.db.add_events(run.analysis_id, [("yara", 0, "WARN", m) for m in run.static_matches])
            return True
        except Exception as e:
            self._notify_ui(f"Failed to initialize analysis in database: {e}", "CRITICAL")
            return False

    async def _pipeline(self, run):
        await self._prepare_vm(run)
        if run.run_gui:
            self._notify_ui("Opening VM GUI...")
            await self.vm_manager.open_gui(run.guest_os)
            self._notify_ui("Manual analysis started. VM will remain open.", "INFO")
            run.keep_vm = True
            await self.db.update_analysis(run.analysis_id, verdict="manual", yara_matches=run.static_matches)
            return
        await self._execute(run)
        await self._memory_scan(run)
        await self._collect(run)

    async def _prepare_vm(self, run):
        vm = self.vm_manager
        self._notify_ui("Verifying VM environment...")
        ok, msg = await vm.verify_environment(run.guest_os)
        if not ok:
            raise AnalysisAborted(f"VM verification failed: {msg}")

        exposed = await vm.find_internet_facing_networks(run.guest_os) if hasattr(vm, "find_internet_facing_networks") else []
        if exposed and not self.config["network"]["allow_internet"]:
            self._notify_ui(f"WARNING: {run.guest_os} is not isolated ({', '.join(exposed)} can reach the host "
                            "LAN/internet). Samples may contact live infrastructure.", "CRITICAL")

        self._notify_ui(f"Reverting VM to snapshot {run.snapshot}...")
        try:
            await vm.revert_to_snapshot(run.guest_os, snapshot_name=run.snapshot)
        except Exception as e:
            # never detonate on a VM that may still carry a previous infection
            raise AnalysisAborted(f"Could not revert to snapshot '{run.snapshot}': {e}")

        self._notify_ui("Starting VM...")
        if not await vm.start_vm(run.guest_os):
            raise AnalysisAborted("Failed to start VM.")

        self._notify_ui("Waiting for guest agent...")
        if not await vm.wait_for_guest_agent(run.guest_os, timeout=self.config["vm"]["agent_timeout"]):
            raise AnalysisAborted("The guest agent did not respond; cannot control the VM.")

        self._notify_ui("Injecting sample into VM...")
        await self._cmd(run, f"mkdir -p -m 700 {q(run.workdir)}")
        injected = False
        if hasattr(vm, "inject_file_via_agent"):
            injected = await vm.inject_file_via_agent(run.guest_os, run.sample_path, run.guest_sample)
        if not injected:
            self._notify_ui("Agent injection failed, trying offline injection...", "WARN")
            await vm.stop_vm(run.guest_os)
            if not await vm.inject_file(run.guest_os, run.sample_path, run.guest_sample):
                raise AnalysisAborted("Failed to copy the sample into the VM.")
            await vm.start_vm(run.guest_os)
            if not await vm.wait_for_guest_agent(run.guest_os, timeout=self.config["vm"]["agent_timeout"]):
                raise AnalysisAborted("The guest agent did not come back after offline injection.")

    async def _execute(self, run):
        if run.run_pcap:
            self._notify_ui("Starting packet capture...")
            await self._cmd(run, f"tcpdump -i any -U -w {q(run.guest_pcap)} >/dev/null 2>&1 &")
        self._notify_ui("Executing sample with strace monitoring...")
        await self.db.add_event(run.analysis_id, "process", 0.1, "INFO", {"msg": "Execution started"})
        await self._cmd(run, f"chmod +x {q(run.guest_sample)} && cd {q(run.workdir)} && "
                             f"strace -ff -tt -s 256 -o {q(run.guest_strace)} {q(run.guest_sample)} >/dev/null 2>&1 &")

    async def _memory_scan(self, run):
        try:
            self._notify_ui("Running in-guest YARA memory scan...")
            if not self.yara_engine:
                self._notify_ui("No YARA engine available; skipping memory scan.", "WARN")
                return
            fd, local_rules = tempfile.mkstemp(prefix="yemu-rules-", suffix=".yarc")
            os.close(fd)
            try:
                if not self.yara_engine.compile_to_file(local_rules):
                    self._notify_ui("Failed to compile YARA rules for in-guest scan.", "WARN")
                    return
                self._notify_ui("YARA rules compiled for in-guest scan.")
                await self.vm_manager.inject_file_via_agent(run.guest_os, local_rules, run.guest_rules)
            finally:
                try:
                    os.remove(local_rules)
                except OSError:
                    pass

            if not (await self._cmd(run, "command -v yara")).strip():
                # the analysis network is offline, so it can't be installed now
                self._notify_ui("YARA is not installed in the guest (rebuild the VM with `yemu vm create`); "
                                "skipping memory scan.", "WARN")
                return
            # scan only the sample's own process tree (PIDs from its strace logs), one bounded call each;
            # a recursive scan of /proc takes minutes and mostly scans the guest OS
            listing = await self._cmd(run, f"ls -1 {q(run.workdir)}")
            pids = sorted({m.group(1) for m in map(STRACE_LOG.match, listing.split()) if m}, key=int)[:MAX_SCAN_PIDS]
            output = []
            for pid in pids:
                output.append(await self._cmd(
                    run, f"[ -d /proc/{pid} ] && timeout 25 yara -C --print-meta --print-strings {q(run.guest_rules)} {pid} 2>/dev/null"))
            if not pids:
                self._notify_ui("The sample's processes had already exited; nothing left in memory to scan.")
            run.memory_matches = self.yara_engine.parse_yara_cli_output("\n".join(output))
            for match in run.memory_matches:
                match["source"] = "memory"
                pid = str(match.get("pid", ""))
                if pid.isdigit():
                    match["process_name"] = (await self._cmd(run, f"cat /proc/{pid}/comm")).strip() or "[unreadable]"
                    match["exe_path"] = (await self._cmd(run, f"readlink -f /proc/{pid}/exe")).strip() or "[unreadable]"
                    cmdline = await self._cmd(run, f"cat /proc/{pid}/cmdline")
                    match["cmdline"] = cmdline.replace("\0", " ").strip() or "[unreadable]"
                self._notify_ui(f"YARA Memory Match: {match['rule']} (PID: {match['pid']})", "WARN")
            await self.db.add_events(run.analysis_id, [("yara", 0, "WARN", m) for m in run.memory_matches])
        except Exception as e:
            self._notify_ui(f"Memory scan failed: {e}", "WARN")

    async def _collect(self, run):
        acfg = self.config["analysis"]
        self._notify_ui("Collecting behavioral logs...")
        await asyncio.sleep(acfg["execution_wait"])
        if run.run_pcap:
            await self._collect_pcap(run, acfg["max_pcap_mb"])
        try:
            listing = await self._cmd(run, f"ls -1 {q(run.workdir)}")
            # file names come from the guest: only accept strace.<pid>
            logs = sorted((m.group(0), m.group(1)) for m in map(STRACE_LOG.match, listing.split()) if m)
            from yemu.core.behaviour_monitor import BehaviourMonitor
            monitor = BehaviourMonitor()
            for name, pid in logs:
                content = await self._cmd(run, f"cat {q(run.workdir + '/' + name)}")
                run.events.extend(monitor.parse_strace(content.splitlines(), pid=pid))
            run.events.sort(key=lambda e: e.get("timestamp", 0))
            keep = run.events[:acfg["max_events"]]
            run.dropped_events = len(run.events) - len(keep)
            await self.db.add_events(run.analysis_id, [(e["type"], e.get("timestamp", 0), "INFO", e) for e in keep])
            counts = Counter(e["type"] for e in run.events)
            summary = ", ".join(f"{n} {t}" for t, n in counts.most_common()) or "no events"
            self._notify_ui(f"Behavior: {len(logs)} process(es), {summary}")
            if run.dropped_events:
                self._notify_ui(f"Stored the first {len(keep)} events; {run.dropped_events} more were dropped "
                                "([analysis].max_events).", "WARN")
        except Exception as e:
            self._notify_ui(f"Strace collection failed: {e}", "WARN")

    async def _collect_pcap(self, run, max_mb):
        try:
            self._notify_ui("Stopping packet capture and collecting PCAP...")
            await self._cmd(run, "pkill -INT tcpdump; sleep 1; sync")
            size = (await self._cmd(run, f"stat -c %s {q(run.guest_pcap)} 2>/dev/null")).strip()
            if not size.isdigit():
                self._notify_ui("No packet capture was produced in the guest.", "WARN")
                return
            if int(size) > max_mb * 1024 * 1024:
                self._notify_ui(f"Capture is {int(size) / 1048576:.0f} MB, over the {max_mb} MB limit; not copied.", "WARN")
                return
            local_pcap = str(paths.captures_dir() / f"{run.analysis_id}.pcap")
            if not await self.vm_manager.pull_file(run.guest_os, run.guest_pcap, local_pcap) or not os.path.exists(local_pcap):
                raise RuntimeError("no capture file came back from the guest")
            from yemu.core.network_capture import NetworkCapture
            iocs = NetworkCapture().analyze_pcap(local_pcap)
            await self.db.add_events(run.analysis_id, [("network", 0, "INFO", {"type": t, "value": v, "source": "pcap"})
                                                       for t, v in iocs])
        except Exception as e:
            self._notify_ui(f"PCAP collection failed: {e}", "WARN")

    async def _score_and_save(self, run, status):
        from yemu.core.threat_scorer import ThreatScorer
        yara_matches = run.static_matches + run.memory_matches
        verdict, score, findings = None, 0, {"reasons": []}
        try:
            self._notify_ui("Computing threat score...")
            findings = heuristics.analyse(run.events)
            scorer = ThreatScorer(self.config["scoring"])
            score = scorer.compute({**findings, "yara_count": len(yara_matches)})
            verdict = scorer.get_verdict(score)
            if status != "completed":
                self._notify_ui(f"Verdict is based on partial results (analysis {status}).", "WARN")
            self._notify_ui(f"Analysis complete. Verdict: {verdict} (Score: {score})", "CRITICAL" if score >= 70 else "INFO")
            await self.db.update_analysis(run.analysis_id, threat_score=score, verdict=verdict, yara_matches=yara_matches,
                                          scoring={"weights": scorer.weights, "findings": findings})
        except Exception as e:
            self._notify_ui(f"Threat scoring failed: {e}", "WARN")

        try:
            self._notify_ui("Saving report...")
            report = {
                "filename": os.path.basename(run.sample_path),
                "sha256": run.sha256,
                "md5": run.md5,
                "score": score,
                "verdict": verdict or "unknown",
                "status": status,
                "yara_matches": yara_matches,
                "findings": findings.get("reasons", []),
                "events_dropped": run.dropped_events,
            }
            await self.db.update_analysis(run.analysis_id, report_json=report)
            from yemu.storage.report_store import ReportStore
            store = ReportStore()
            store.save_json(run.analysis_id, report)
            store.generate_pdf(run.analysis_id, report)
            self._notify_ui("Report saved successfully.", "INFO")
        except Exception as e:
            self._notify_ui(f"Failed to save report: {e}", "WARN")
