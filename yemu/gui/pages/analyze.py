import hashlib
import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QGridLayout, QHBoxLayout, QProgressBar,
                               QVBoxLayout, QWidget)

from yemu.core.orchestrator import Orchestrator
from yemu.gui import theme
from yemu.gui.widgets import (DropZone, LogView, ScoreGauge, StageTracker, VerdictBadge, button, card,
                              human_size, label, page_header)

# (key, title, message prefixes that start the stage)
STAGES = [
    ("static", "Static YARA scan", ("Running YARA static analysis",)),
    ("prepare", "Revert and boot VM", ("Verifying VM environment", "Reverting VM", "Starting VM", "Waiting for guest agent")),
    ("inject", "Inject sample", ("Injecting sample",)),
    ("execute", "Execute under strace", ("Executing sample", "Starting packet capture")),
    ("memory", "In-guest memory scan", ("Running in-guest YARA memory scan",)),
    ("collect", "Collect behaviour and network", ("Collecting behavioral logs", "Stopping packet capture")),
    ("score", "Score and verdict", ("Computing threat score",)),
    ("report", "Save report", ("Saving report",)),
    ("cleanup", "Power off VM", ("Cleaning up VM",)),
]


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class AnalyzePage(QWidget):
    open_report = Signal(int)

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        self.sample_path = None
        self.current_stage = None
        self.stage_had_warning = False
        self.last_analysis_id = None

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addLayout(page_header("Analyze a sample",
                                   "Detonate a file inside an isolated VM, then review its behaviour, YARA hits and verdict."))

        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(16)
        root.addLayout(grid, 1)

        # --- left: sample + options ---
        left = QVBoxLayout()
        left.setSpacing(16)
        self.drop = DropZone()
        self.drop.browse_requested.connect(self.browse)
        self.drop.file_selected.connect(self.set_sample)
        left.addWidget(self.drop)

        self.file_card, fl = card()
        self.file_name = label("", "SectionTitle")
        self.file_meta = label("", "Muted", selectable=True)
        self.file_meta.setWordWrap(True)
        fl.addWidget(self.file_name)
        fl.addWidget(self.file_meta)
        self.file_card.hide()
        left.addWidget(self.file_card)

        opts, ol = card()
        ol.addWidget(label("Environment", "SectionTitle"))
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)
        form.setHorizontalSpacing(16)
        self.vm_combo = QComboBox()
        self.vm_combo.currentTextChanged.connect(self._load_snapshots)
        self.snap_combo = QComboBox()
        vm_row = QHBoxLayout()
        vm_row.addWidget(self.vm_combo, 1)
        refresh = button("", "refresh")
        refresh.setToolTip("Reload VMs")
        refresh.clicked.connect(self.refresh_vms)
        vm_row.addWidget(refresh)
        form.addRow("VM", vm_row)
        form.addRow("Snapshot", self.snap_combo)
        ol.addLayout(form)
        self.pcap = QCheckBox("Capture network traffic (PCAP)")
        self.pcap.setChecked(True)
        self.interactive = QCheckBox("Interactive session: open the VM console and skip automated monitoring")
        ol.addWidget(self.pcap)
        ol.addWidget(self.interactive)
        self.backend_note = label("", "Muted", wrap=True)
        ol.addWidget(self.backend_note)
        left.addWidget(opts)

        self.start_btn = button("Start analysis", "play", "Primary")
        self.start_btn.setMinimumHeight(40)
        self.start_btn.clicked.connect(self.start)
        left.addWidget(self.start_btn)
        left.addStretch(1)
        lw = QWidget()
        lw.setLayout(left)
        grid.addWidget(lw, 0, 0)

        # --- right: progress + result + log ---
        right = QVBoxLayout()
        right.setSpacing(16)
        prog, pl = card()
        head = QHBoxLayout()
        head.addWidget(label("Progress", "SectionTitle"))
        head.addStretch(1)
        self.status = label("Idle", "Muted")
        head.addWidget(self.status)
        pl.addLayout(head)
        self.bar = QProgressBar()
        self.bar.setRange(0, len(STAGES))
        self.bar.setValue(0)
        self.bar.setFixedHeight(8)
        pl.addWidget(self.bar)
        self.tracker = StageTracker([(k, t) for k, t, _ in STAGES])
        pl.addWidget(self.tracker)
        right.addWidget(prog)

        self.result_card, rl = card(horizontal=True)
        self.gauge = ScoreGauge(96)
        rl.addWidget(self.gauge)
        info = QVBoxLayout()
        self.result_title = label("", "SectionTitle")
        self.result_badge = VerdictBadge()
        self.result_meta = label("", "Muted", wrap=True)
        badge_row = QHBoxLayout()
        badge_row.addWidget(self.result_badge)
        badge_row.addStretch(1)
        info.addWidget(self.result_title)
        info.addLayout(badge_row)
        info.addWidget(self.result_meta)
        rl.addLayout(info, 1)
        self.open_btn = button("Open report", "file", "Primary")
        self.open_btn.clicked.connect(lambda: self.last_analysis_id and self.open_report.emit(self.last_analysis_id))
        rl.addWidget(self.open_btn, 0, Qt.AlignVCenter)
        self.result_card.hide()
        right.addWidget(self.result_card)

        log_card, logl = card()
        logl.addWidget(label("Live log", "SectionTitle"))
        self.log = LogView()
        self.log.setMinimumHeight(160)
        logl.addWidget(self.log, 1)
        right.addWidget(log_card, 1)
        rw = QWidget()
        rw.setLayout(right)
        grid.addWidget(rw, 0, 1)
        grid.setColumnStretch(0, 5)
        grid.setColumnStretch(1, 6)

        ctx.log.message.connect(self._on_message)
        ctx.backend_changed.connect(self.refresh_vms)
        self.refresh_vms()
        self._update_start()

    # --- sample ---
    def browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select a sample to analyze")
        if path:
            self.set_sample(path)

    def set_sample(self, path):
        if not os.path.isfile(path):
            return
        self.sample_path = path
        self.file_card.show()
        self.file_name.setText(os.path.basename(path))
        self.file_meta.setText(f"{human_size(os.path.getsize(path))}  ·  sha256: computing...")
        self.ctx.bridge.call_sync(sha256_of, path, on_result=lambda h: self._set_hash(path, h))
        self._update_start()

    def _set_hash(self, path, digest):
        if path == self.sample_path:
            self.file_meta.setText(f"{human_size(os.path.getsize(path))}  ·  sha256: {digest}")

    # --- VMs ---
    def refresh_vms(self):
        backend = self.ctx.backend
        self.backend_note.setText(f"Backend: {self.ctx.backend_label()}" +
                                  ("  ·  Mock mode returns canned results. Configure a real backend in Settings."
                                   if backend.name == "mock" else ""))
        self.ctx.bridge.call_sync(backend.list_vms, on_result=self._set_vms,
                                  on_error=lambda e: self.ctx.log(f"Could not list VMs: {e}", "WARN"))

    def _set_vms(self, vms):
        current = self.vm_combo.currentText() or self.ctx.config["vm"]["default_vm"]
        self.vm_combo.blockSignals(True)
        self.vm_combo.clear()
        self.vm_combo.addItems(sorted(vms))
        idx = self.vm_combo.findText(current)
        self.vm_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.vm_combo.blockSignals(False)
        if not vms:
            self.vm_combo.setPlaceholderText("No VMs yet: create one on the VMs page")
        self._load_snapshots(self.vm_combo.currentText())
        self._update_start()

    def _load_snapshots(self, vm):
        self.snap_combo.clear()
        if not vm:
            self._update_start()
            return
        self.ctx.bridge.call_sync(self.ctx.backend.list_snapshots, vm, on_result=self._set_snapshots)

    def _set_snapshots(self, snaps):
        self.snap_combo.clear()
        self.snap_combo.addItems(snaps)
        idx = self.snap_combo.findText(self.ctx.config["vm"]["default_snapshot"])
        if idx >= 0:
            self.snap_combo.setCurrentIndex(idx)
        self._update_start()

    def _update_start(self):
        ok = bool(self.sample_path and self.vm_combo.currentText() and self.snap_combo.currentText()
                  and not self.ctx.analysis_running)
        self.start_btn.setEnabled(ok)
        if self.ctx.analysis_running:
            self.start_btn.setText("Analysis running...")
        elif not self.sample_path:
            self.start_btn.setText("Choose a sample to start")
        elif not self.vm_combo.currentText():
            self.start_btn.setText("Create a VM first")
        else:
            self.start_btn.setText("Start analysis")

    # --- run ---
    def start(self):
        if self.ctx.analysis_running or not self.sample_path:
            return
        self.ctx.analysis_running = True
        self.tracker.reset()
        self.bar.setValue(0)
        self.current_stage = None
        self.result_card.hide()
        self.log.clear()
        self.status.setText("Running")
        self._update_start()
        orch = Orchestrator(self.ctx.db, vm_manager=self.ctx.backend, ui_callback=self.ctx.log, config=self.ctx.config)
        coro = orch.run_analysis(self.sample_path, guest_os=self.vm_combo.currentText(),
                                 snapshot_name=self.snap_combo.currentText(),
                                 run_gui=self.interactive.isChecked(), run_pcap=self.pcap.isChecked())
        self.ctx.bridge.call(coro, self._finished, self._crashed)

    def _advance(self, key):
        if self.current_stage == key:
            return
        order = [k for k, _, _ in STAGES]
        if self.current_stage:
            self.tracker.set_state(self.current_stage, "warn" if self.stage_had_warning else "done")
            # stages the pipeline jumped over were skipped
            for k in order[order.index(self.current_stage) + 1:order.index(key)]:
                if self.tracker.state(k) == "pending":
                    self.tracker.set_state(k, "skipped")
        self.current_stage = key
        self.stage_had_warning = False
        self.tracker.set_state(key, "active")
        self.bar.setValue(order.index(key))

    def _on_message(self, msg, severity):
        if not self.ctx.analysis_running:
            return
        self.log.append_line(msg, severity)
        for key, _, prefixes in STAGES:
            if msg.startswith(prefixes):
                self._advance(key)
                break
        else:
            # findings (YARA hits, behaviour) are WARN too; only problems mark the stage
            problem = any(w in msg.lower() for w in ("fail", "error", "timed out", "timeout", "not found"))
            if severity in ("WARN", "CRITICAL") and problem and self.current_stage:
                self.stage_had_warning = True
        if severity == "CRITICAL" and self.current_stage and ("failed" in msg.lower() or "error" in msg.lower()):
            self.tracker.set_state(self.current_stage, "failed")

    def _finished(self, analysis_id):
        self.ctx.analysis_running = False
        if self.current_stage and self.tracker.state(self.current_stage) == "active":
            self.tracker.set_state(self.current_stage, "warn" if self.stage_had_warning else "done")
        self.bar.setValue(len(STAGES))
        self._update_start()
        self.ctx.analyses_changed.emit()
        if not analysis_id:
            self.status.setText("Failed")
            return
        self.last_analysis_id = analysis_id
        self.ctx.bridge.call(self.ctx.db.get_analysis_details(analysis_id), self._show_result)

    def _crashed(self, error):
        self.ctx.analysis_running = False
        self.status.setText("Crashed")
        self.log.append_line(f"Analysis crashed: {error}", "CRITICAL")
        self._update_start()

    def _show_result(self, details):
        if not details:
            return
        verdict = details.get("verdict") or "unknown"
        self.status.setText(f"Done · {verdict}")
        self.gauge.set_score(details.get("threat_score") or 0, verdict)
        self.result_badge.set_verdict(verdict)
        self.result_title.setText(f"#{details['id']}  {details.get('filename')}")
        self.result_meta.setText("Analysis complete. Open the report for YARA hits, the process tree and network IOCs.")
        self.result_card.show()
