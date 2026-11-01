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
from typing import Any

from yemu import config as yemu_config
from yemu import paths
from yemu.core import heuristics
from yemu.core.vm_backend import create_backend

q = shlex.quote
STRACE_LOG = re.compile(r"^strace\.(\d+)$")
MAX_SCAN_PIDS = 10
MAX_CHANGED_FILES = 5000
MAX_STRACE_MB = 1024
STRACE = "strace -ff -tt -s 256"
# left out of the filesystem diff: virtual filesystems and YEMU's own work folder
DIFF_PRUNE = ("/proc", "/sys", "/dev", "/run", "/tmp/yemu-*", "/var/lib/apt/lists", "/var/log/journal")


# with a desktop logged in, a package's programs start in that session as the analyst (GUI apps need a display,
# and some, like VS Code, refuse to run as root); without one they run as root with no display
DESKTOP_SESSION = (
    "as_user=; session=; if [ -S /tmp/.X11-unix/X0 ] && id -u analyst >/dev/null 2>&1; then "
    "uid=$(id -u analyst); as_user='-u analyst'; "
    "session=\"env DISPLAY=:0 XAUTHORITY=/home/analyst/.Xauthority HOME=/home/analyst "
    "XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus\"; fi; "
)


def sample_kind(path):
    """How the guest should run the sample: 'deb', 'elf', 'script' or 'unknown'."""
    with open(path, "rb") as f:
        head = f.read(64)
    if head.startswith(b"!<arch>\ndebian-binary"):
        return "deb"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"#!"):
        return "script"
    return "unknown"


def _hash_file(path):
    sha256, md5, size = hashlib.sha256(), hashlib.md5(), 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)
    return sha256.hexdigest(), md5.hexdigest(), size


def _parse_strace_logs(logs):
    from yemu.core.behaviour_monitor import BehaviourMonitor

    # one monitor for all logs: it carries parent/child process info from one log to the next
    monitor = BehaviourMonitor()
    events = []
    for content, pid in logs:
        events.extend(monitor.parse_strace(content.splitlines(), pid=pid))
    events.sort(key=lambda e: e.get("timestamp", 0))
    return events


def _read_strace_archive(path):
    """(content, pid) for each strace.<pid> log in a guest-made tar.gz. Member names come from the guest, so
    only regular files named strace.<pid> are read, and the total is capped."""
    import tarfile

    logs, total = [], 0
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            m = STRACE_LOG.match(member.name)
            if not m or not member.isfile():
                continue
            total += member.size
            if total > MAX_STRACE_MB * 1024 * 1024:
                break
            f = tar.extractfile(member)
            if f:
                logs.append((f.read().decode("utf-8", "replace"), m.group(1)))
    return sorted(logs, key=lambda log: int(log[1]))


def _event_rank(e):
    """Lower is kept first: processes, network and sensitive files, then file changes, then reads, then failed
    calls."""
    if e["type"] != "file" or any(p in e.get("path", "") for p in heuristics.SENSITIVE_READ + heuristics.PERSISTENCE):
        return 0
    if e.get("result"):
        return 3
    return 2 if e.get("action") == "open" else 1


def _keep_events(events, limit):
    """At most limit events, dropping the least telling ones first; keeps time order."""
    if len(events) <= limit:
        return events
    rank = sorted(range(len(events)), key=lambda i: _event_rank(events[i]))
    return [events[i] for i in sorted(rank[:limit])]


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
        self.kind = sample_kind(sample_path) if os.path.isfile(sample_path) else "unknown"
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
        self.marker = f"{self.workdir}/.started"  # its ctime marks the start for the filesystem diff
        self.launched = 0.0  # loop time the sample (or the package's programs) started


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
    async def run_analysis(
        self, sample_path, guest_os="ubuntu-clean", snapshot_name="clean-baseline", run_gui=False, run_pcap=False
    ):
        acfg = self.config["analysis"]
        run = _Run(sample_path, guest_os, snapshot_name, run_gui, run_pcap)
        self._notify_ui(f"Starting analysis on {guest_os} (Snapshot: {snapshot_name})...")

        try:
            size = os.path.getsize(sample_path)
        except OSError as e:
            self._notify_ui(f"Cannot read sample: {e}", "CRITICAL")
            return None
        if size > acfg["max_sample_mb"] * 1024 * 1024:
            self._notify_ui(
                f"Sample is {size / 1048576:.0f} MB; the limit is {acfg['max_sample_mb']} MB "
                "([analysis].max_sample_mb).",
                "CRITICAL",
            )
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

            self.yara_engine = await asyncio.to_thread(YaraEngine, rules_dir=paths.synced_rules_dir())
            self._notify_ui("Running YARA static analysis...")
            run.static_matches = await self.yara_engine.scan_file_async(run.sample_path)
            for m in run.static_matches:
                m["source"] = "static"
                self._notify_ui(f"YARA Static Match: {m['rule']}", "WARN")
        except Exception as e:
            self.yara_engine = None  # type: ignore[assignment]
            self._notify_ui(f"Static analysis failed: {e}", "WARN")

    async def _create_records(self, run):
        try:
            run.sha256, run.md5, run.size = await asyncio.to_thread(_hash_file, run.sample_path)
            sample_id = await self.db.add_sample(
                run.sha256, run.md5, os.path.basename(run.sample_path), "unknown", run.size
            )
            if not sample_id:
                self._notify_ui("Failed to create sample record in database.", "CRITICAL")
                return False
            run.analysis_id = await self.db.create_analysis(
                sample_id, datetime.now(), guest_os=run.guest_os, snapshot=run.snapshot
            )
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
            # the console password is only shown once at VM creation; set a fresh one for this session
            password = secrets.token_urlsafe(9)
            # VMs from the catalog have an analyst account; older ones only the image's default user
            user = "analyst" if (await self._cmd(run, "id -u analyst 2>/dev/null")).strip() else "ubuntu"
            await self._cmd(run, f"echo {q(user + ':' + password)} | chpasswd")
            await self._cmd(run, f"chmod 755 {q(run.workdir)} && chmod 644 {q(run.guest_sample)}")
            await self.vm_manager.open_gui(run.guest_os)
            self._notify_ui(
                f"Manual analysis started. VM will remain open. Log in as {user} / {password}; "
                f"the sample is at {run.guest_sample}",
                "INFO",
            )
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

        exposed = (
            await vm.find_internet_facing_networks(run.guest_os) if hasattr(vm, "find_internet_facing_networks") else []
        )
        if exposed and not self.config["network"]["allow_internet"]:
            self._notify_ui(
                f"WARNING: {run.guest_os} is not isolated ({', '.join(exposed)} can reach the host "
                "LAN/internet). Samples may contact live infrastructure.",
                "CRITICAL",
            )

        self._notify_ui(f"Reverting VM to snapshot {run.snapshot}...")
        try:
            await vm.revert_to_snapshot(run.guest_os, snapshot_name=run.snapshot)
        except Exception as e:
            # never detonate on a VM that may still carry a previous infection
            raise AnalysisAborted(f"Could not revert to snapshot '{run.snapshot}': {e}") from e

        self._notify_ui("Starting VM...")
        if not await vm.start_vm(run.guest_os, display=run.run_gui):
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
        guest_hash = (await self._cmd(run, f"sha256sum {q(run.guest_sample)} 2>/dev/null")).split()[:1]
        if guest_hash != [run.sha256]:
            raise AnalysisAborted("The sample copied into the VM does not match the original (SHA-256 differs).")

    async def _execute(self, run):
        if run.run_pcap:
            self._notify_ui("Starting packet capture...")
            await self._cmd(run, f"tcpdump -i any -U -w {q(run.guest_pcap)} >/dev/null 2>&1 &")
        await self._cmd(run, f"touch {q(run.marker)}")
        await self.db.add_event(run.analysis_id, "process", 0.1, "INFO", {"msg": "Execution started"})
        w, s, log = q(run.workdir), q(run.guest_sample), q(run.guest_strace)
        if run.kind != "deb":
            self._notify_ui("Executing sample with strace monitoring...")
            # only the traced sample goes to the background: a backgrounded `a && b` list keeps the agent's
            # output pipe open, so the agent would wait for the sample to finish
            await self._cmd(run, f"chmod +x {s} && cd {w} && ({STRACE} -o {log} {s} </dev/null >/dev/null 2>&1 &)")
            run.launched = asyncio.get_running_loop().time()
            return
        # a package: install it (its maintainer scripts run as root, which is where packaged malware acts),
        # then start every program it put on the PATH. Dependencies can't be fetched on the isolated network,
        # so install without them; programs that need a missing library or a display fail, and strace shows it.
        if not (await self._cmd(run, "command -v dpkg")).strip():
            raise AnalysisAborted(
                "This VM can't install .deb packages (it has no dpkg). Analyze it on an Ubuntu VM "
                "(`yemu vm create <name> --distro ubuntu`)."
            )
        self._notify_ui("Executing sample with strace monitoring: installing the package with dpkg...")
        script = (
            f"cd {w}; {STRACE} -o {log} dpkg --force-depends -i {s} >{w}/install.log 2>&1; "
            f"echo $? >{w}/install.rc; pkg=$(dpkg-deb -f {s} Package); {DESKTOP_SESSION}"
            'for b in $(dpkg -L "$pkg" 2>/dev/null | grep -E "/s?bin/[^/]+$|^/usr/games/" | head -n 10); '
            f'do [ -f "$b" ] && [ -x "$b" ] && echo "$b" >>{w}/launched && '
            f'({STRACE} $as_user -o {log} $session "$b" </dev/null >/dev/null 2>&1 &); done; touch {w}/done'
        )
        await self._cmd(run, f"nohup sh -c {q(script)} >/dev/null 2>&1 &")
        while not (await self._cmd(run, f"[ -f {w}/done ] && echo done")).strip():
            await asyncio.sleep(3)  # the analysis timeout bounds this
        run.launched = asyncio.get_running_loop().time()
        rc = (await self._cmd(run, f"cat {w}/install.rc")).strip()
        log_tail = (await self._cmd(run, f"tail -c 4000 {w}/install.log")).strip()
        programs = (await self._cmd(run, f"cat {w}/launched 2>/dev/null")).split()
        self._notify_ui(
            f"dpkg exited with {rc or '?'}; started {len(programs)} program(s) from the package: "
            + (", ".join(programs) or "none"),
            "INFO" if rc == "0" else "WARN",
        )
        await self.db.add_event(
            run.analysis_id, "process", 0.2, "INFO", {"msg": f"dpkg exited with {rc}", "output": log_tail}
        )

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
                self._notify_ui(
                    "YARA is not installed in the guest (rebuild the VM with `yemu vm create`); skipping memory scan.",
                    "WARN",
                )
                return
            # scan only the sample's own process tree (PIDs from its strace logs), one bounded call each;
            # a recursive scan of /proc takes minutes and mostly scans the guest OS
            listing = await self._cmd(run, f"ls -1 {q(run.workdir)}")
            pids = sorted({m.group(1) for m in map(STRACE_LOG.match, listing.split()) if m}, key=int)[:MAX_SCAN_PIDS]
            output = []
            for pid in pids:
                output.append(
                    await self._cmd(
                        run,
                        f"[ -d /proc/{pid} ] && timeout 25 "
                        f"yara -C --print-meta --print-strings {q(run.guest_rules)} {pid} 2>/dev/null",
                    )
                )
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
        # let the sample run until everything it started has exited, up to execution_wait from launch;
        # the [s] keeps the pattern from matching the shell that runs pgrep
        loop = asyncio.get_running_loop()
        traced = q(f"-o {run.workdir}/[s]trace")
        while loop.time() < run.launched + acfg["execution_wait"]:
            if not (await self._cmd(run, f"pgrep -f -- {traced} >/dev/null && echo running")).strip():
                break
            await asyncio.sleep(2)
        self._notify_ui("Collecting behavioral logs...")
        if run.run_pcap:
            await self._collect_pcap(run, acfg["max_pcap_mb"])
        try:
            # one archive through the file channel: cat-ing big logs overflows the agent's reply
            archive = f"{run.workdir}/strace.tgz"
            await self._cmd(run, f"cd {q(run.workdir)} && tar -czf strace.tgz strace.* 2>/dev/null")
            # kept next to the PCAP: the raw logs, for anything the parsed events leave out
            local = str(paths.captures_dir() / f"{run.analysis_id}-strace.tgz")
            if not await self.vm_manager.pull_file(run.guest_os, archive, local):
                raise RuntimeError("could not copy the strace logs out of the guest")
            # CPU-bound unpacking and parsing run in a worker so the loop (and the analysis timeout) stays live
            logs = await asyncio.to_thread(_read_strace_archive, local)
            run.events = await asyncio.to_thread(_parse_strace_logs, logs)
            keep = _keep_events(run.events, acfg["max_events"])
            run.dropped_events = len(run.events) - len(keep)
            await self.db.add_events(run.analysis_id, [(e["type"], e.get("timestamp", 0), "INFO", e) for e in keep])
            counts = Counter(e["type"] for e in run.events)
            summary = ", ".join(f"{n} {t}" for t, n in counts.most_common()) or "no events"
            self._notify_ui(f"Behavior: {len(logs)} process(es), {summary}")
            if run.dropped_events:
                self._notify_ui(
                    f"Stored {len(keep)} events; {run.dropped_events} more were dropped, failed calls and file "
                    "reads first ([analysis].max_events).",
                    "WARN",
                )
        except Exception as e:
            self._notify_ui(f"Strace collection failed: {e}", "WARN")
        await self._collect_changed_files(run)

        execs = [e for e in run.events if e["type"] == "process" and e.get("action") == "execute"]
        if run.kind != "deb" and execs and all(e.get("result") for e in execs):
            raise AnalysisAborted(
                f"The sample never ran: the guest refused to execute it ({execs[0]['result']}). "
                "YEMU runs Linux ELF binaries, scripts with a #! line and .deb packages."
            )

    async def _collect_changed_files(self, run):
        """Every file whose inode changed since the sample started (ctime: dpkg keeps the archive's mtimes).
        Covers writes strace can't attribute, but also includes whatever the guest OS changed meanwhile."""
        prune = " -o ".join(f"-path {q(p)}" for p in DIFF_PRUNE)
        out = await self._cmd(
            run,
            f"find / -xdev \\( {prune} \\) -prune -o ! -type d -cnewer {q(run.marker)} -print 2>/dev/null "
            f"| head -n {MAX_CHANGED_FILES + 1}",
        )
        changed = [p for p in out.splitlines() if p.startswith("/")]
        if len(changed) > MAX_CHANGED_FILES:
            changed = changed[:MAX_CHANGED_FILES]
            self._notify_ui(
                f"More than {MAX_CHANGED_FILES} files changed; storing the first {MAX_CHANGED_FILES}.", "WARN"
            )
        await self.db.add_events(
            run.analysis_id,
            [("file", 0, "INFO", {"action": "changed", "path": p, "source": "fsdiff"}) for p in changed],
        )
        self._notify_ui(f"Filesystem: {len(changed)} file(s) created or changed during the run")

    async def _collect_pcap(self, run, max_mb):
        try:
            self._notify_ui("Stopping packet capture and collecting PCAP...")
            await self._cmd(run, "pkill -INT tcpdump; sleep 1; sync")
            size = (await self._cmd(run, f"stat -c %s {q(run.guest_pcap)} 2>/dev/null")).strip()
            if not size.isdigit():
                self._notify_ui("No packet capture was produced in the guest.", "WARN")
                return
            if int(size) > max_mb * 1024 * 1024:
                self._notify_ui(
                    f"Capture is {int(size) / 1048576:.0f} MB, over the {max_mb} MB limit; not copied.", "WARN"
                )
                return
            local_pcap = str(paths.captures_dir() / f"{run.analysis_id}.pcap")
            if not await self.vm_manager.pull_file(run.guest_os, run.guest_pcap, local_pcap) or not os.path.exists(
                local_pcap
            ):
                raise RuntimeError("no capture file came back from the guest")
            from yemu.core.network_capture import NetworkCapture

            iocs = await asyncio.to_thread(NetworkCapture().analyze_pcap, local_pcap)
            await self.db.add_events(
                run.analysis_id, [("network", 0, "INFO", {"type": t, "value": v, "source": "pcap"}) for t, v in iocs]
            )
        except Exception as e:
            self._notify_ui(f"PCAP collection failed: {e}", "WARN")

    async def _score_and_save(self, run, status):
        from yemu.core.threat_scorer import ThreatScorer

        yara_matches = run.static_matches + run.memory_matches
        verdict, score = None, 0
        findings: dict[str, Any] = {"reasons": []}
        try:
            self._notify_ui("Computing threat score...")
            findings = await asyncio.to_thread(heuristics.analyse, run.events, kind=run.kind)
            scorer = ThreatScorer(self.config["scoring"])
            score = scorer.compute({**findings, "yara_count": len(yara_matches)})
            verdict = scorer.get_verdict(score)
            if status != "completed":
                self._notify_ui(f"Verdict is based on partial results (analysis {status}).", "WARN")
            self._notify_ui(
                f"Analysis complete. Verdict: {verdict} (Score: {score})", "CRITICAL" if score >= 70 else "INFO"
            )
            await self.db.update_analysis(
                run.analysis_id,
                threat_score=score,
                verdict=verdict,
                yara_matches=yara_matches,
                scoring={"weights": scorer.weights, "findings": findings},
            )
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
