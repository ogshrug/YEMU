import contextlib
import copy
import io
from argparse import Namespace

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from yemu import config as yemu_config
from yemu import paths
from yemu.core.vm_backend import BACKENDS
from yemu.gui.widgets import button, card, label, page_header, show_status


def _spin(lo, hi, suffix=""):
    s = QSpinBox()
    s.setButtonSymbols(
        QSpinBox.ButtonSymbols.NoButtons
    )  # arrows render poorly under the stylesheet; wheel/keys still work
    s.setRange(lo, hi)
    if suffix:
        s.setSuffix(suffix)
    return s


class SettingsPage(QWidget):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)
        body = QWidget()
        body.setObjectName("Page")
        scroll.setWidget(body)
        root = QVBoxLayout(body)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addLayout(page_header("Settings", f"Saved to {paths.config_file()}"))

        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(16)
        root.addLayout(grid)

        # VM
        vm_card, vl = card()
        vl.addWidget(label("Virtual machines", "SectionTitle"))
        f = QFormLayout()
        self.backend = QComboBox()
        self.backend.addItems(BACKENDS)
        self.default_vm = QLineEdit()
        self.default_snap = QLineEdit()
        self.agent_timeout = _spin(30, 3600, " s")
        self.exec_wait = _spin(0, 3600, " s")
        self.timeout = _spin(60, 86400, " s")
        self.max_sample = _spin(1, 4096, " MB")
        f.addRow("Backend", self.backend)
        f.addRow("Default VM", self.default_vm)
        f.addRow("Default snapshot", self.default_snap)
        f.addRow("Guest agent timeout", self.agent_timeout)
        f.addRow("Run sample for", self.exec_wait)
        f.addRow("Analysis time limit", self.timeout)
        f.addRow("Largest sample", self.max_sample)
        vl.addLayout(f)
        vl.addStretch(1)
        grid.addWidget(vm_card, 0, 0)

        # QEMU
        q_card, ql = card()
        ql.addWidget(label("QEMU backend", "SectionTitle"))
        f = QFormLayout()
        self.bin_dir = QLineEdit()
        self.bin_dir.setPlaceholderText("auto-detect (PATH, Program Files, scoop)")
        browse = button("", "folder")
        browse.clicked.connect(self._browse_qemu)
        row = QHBoxLayout()
        row.addWidget(self.bin_dir, 1)
        row.addWidget(browse)
        self.accel = QComboBox()
        self.accel.addItems(["auto", "whpx", "kvm", "hvf", "tcg"])
        self.extra_args = QLineEdit()
        self.extra_args.setPlaceholderText("extra QEMU arguments, space separated")
        f.addRow("QEMU folder", row)
        f.addRow("Acceleration", self.accel)
        f.addRow("Extra arguments", self.extra_args)
        ql.addLayout(f)
        ql.addWidget(
            label("WHPX is used on Windows, KVM on Linux; tcg is slow software emulation.", "Muted", wrap=True)
        )
        ql.addStretch(1)
        grid.addWidget(q_card, 0, 1)

        # Network + UI
        n_card, nl = card()
        nl.addWidget(label("Network isolation", "SectionTitle"))
        f = QFormLayout()
        self.net_name = QLineEdit()
        f.addRow("Analysis network (libvirt)", self.net_name)
        nl.addLayout(f)
        self.allow_internet = QCheckBox("Samples are allowed to reach the internet (silences the isolation warning)")
        self.allow_internet.toggled.connect(self._warn_internet)
        nl.addWidget(self.allow_internet)
        nl.addWidget(
            label(
                "Leave this off unless you deliberately run a NAT/bridged VM. Live malware can attack "
                "other hosts and tip off its operators.",
                "Muted",
                wrap=True,
            )
        )
        nl.addStretch(1)
        grid.addWidget(n_card, 1, 0)

        u_card, ul = card()
        ul.addWidget(label("Appearance and rules", "SectionTitle"))
        f = QFormLayout()
        self.theme = QComboBox()
        self.theme.addItems(["system", "light", "dark"])
        self.repo = QLineEdit()
        self.branch = QLineEdit()
        f.addRow("Theme", self.theme)
        f.addRow("Rules repository", self.repo)
        f.addRow("Rules branch", self.branch)
        ul.addLayout(f)
        ul.addStretch(1)
        grid.addWidget(u_card, 1, 1)

        actions = QHBoxLayout()
        actions.addStretch(1)
        reset = button("Revert")
        reset.clicked.connect(self.load)
        save = button("Save settings", "save", "Primary")
        save.clicked.connect(self.save)
        actions.addWidget(reset)
        actions.addWidget(save)
        root.addLayout(actions)

        # Paths + diagnostics
        p_card, pl = card()
        pl.addWidget(label("Data locations", "SectionTitle"))
        pg = QGridLayout()
        pg.setHorizontalSpacing(12)
        for i, (name, value) in enumerate(paths.summary().items()):
            pg.addWidget(label(name.replace("_", " ").capitalize(), "Muted"), i, 0)
            pg.addWidget(label(str(value), selectable=True), i, 1)
            target = value if value.is_dir() else value.parent
            open_btn = button("Open", "folder", "Flat")
            open_btn.clicked.connect(lambda _=False, t=target: QDesktopServices.openUrl(QUrl.fromLocalFile(str(t))))
            pg.addWidget(open_btn, i, 2)
        pg.setColumnStretch(1, 1)
        pl.addLayout(pg)
        root.addWidget(p_card)

        d_card, dl = card()
        head = QHBoxLayout()
        head.addWidget(label("Diagnostics", "SectionTitle"))
        head.addStretch(1)
        run = button("Run checks", "check")
        run.clicked.connect(self._doctor)
        head.addWidget(run)
        dl.addLayout(head)
        self.doctor_out = QPlainTextEdit()
        self.doctor_out.setObjectName("Code")
        self.doctor_out.setReadOnly(True)
        self.doctor_out.setMinimumHeight(220)
        self.doctor_out.setPlaceholderText(
            "Checks Python packages, QEMU and acceleration, libvirt, and the GUI toolkit."
        )
        dl.addWidget(self.doctor_out)
        root.addWidget(d_card)
        root.addStretch(1)
        self.load()

    def load(self):
        c = self.ctx.config
        self.backend.setCurrentText(c["vm"]["backend"])
        self.default_vm.setText(c["vm"]["default_vm"])
        self.default_snap.setText(c["vm"]["default_snapshot"])
        self.agent_timeout.setValue(int(c["vm"]["agent_timeout"]))
        self.exec_wait.setValue(int(c["analysis"]["execution_wait"]))
        self.timeout.setValue(int(c["analysis"]["timeout"]))
        self.max_sample.setValue(int(c["analysis"]["max_sample_mb"]))
        self.bin_dir.setText(c["qemu"]["bin_dir"])
        self.accel.setCurrentText(c["qemu"]["accel"])
        self.extra_args.setText(" ".join(c["qemu"]["extra_args"]))
        self.net_name.setText(c["network"]["name"])
        self.allow_internet.blockSignals(True)
        self.allow_internet.setChecked(bool(c["network"]["allow_internet"]))
        self.allow_internet.blockSignals(False)
        self.theme.setCurrentText(c["ui"]["theme"])
        self.repo.setText(c["rules"]["repo_url"])
        self.branch.setText(c["rules"]["branch"])

    def _browse_qemu(self):
        d = QFileDialog.getExistingDirectory(self, "Folder containing qemu-system-x86_64")
        if d:
            self.bin_dir.setText(d)

    def _warn_internet(self, checked):
        if (
            checked
            and QMessageBox.warning(
                self,
                "Allow internet access?",
                "Samples will be able to reach real infrastructure. Only do this on a dedicated, monitored network.",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
            )
            != QMessageBox.StandardButton.Ok
        ):
            self.allow_internet.setChecked(False)

    def save(self):
        if self.ctx.analysis_running:
            QMessageBox.information(self, "YEMU", "Wait for the running analysis to finish before changing settings.")
            return
        c = copy.deepcopy(self.ctx.config)
        c["vm"].update(
            backend=self.backend.currentText(),
            default_vm=self.default_vm.text().strip(),
            default_snapshot=self.default_snap.text().strip() or "clean-baseline",
            agent_timeout=self.agent_timeout.value(),
        )
        c["analysis"].update(
            execution_wait=self.exec_wait.value(), timeout=self.timeout.value(), max_sample_mb=self.max_sample.value()
        )
        c["qemu"].update(
            bin_dir=self.bin_dir.text().strip(),
            accel=self.accel.currentText(),
            extra_args=self.extra_args.text().split(),
        )
        c["network"].update(
            name=self.net_name.text().strip() or "malware-analysis", allow_internet=self.allow_internet.isChecked()
        )
        c["ui"]["theme"] = self.theme.currentText()
        c["rules"].update(repo_url=self.repo.text().strip(), branch=self.branch.text().strip() or "master")
        path = yemu_config.save(c)
        self.ctx.reload_config()
        show_status(self, f"Settings saved to {path}. Backend: {self.ctx.backend_label()}", 6000)

    def _doctor(self):
        from yemu.cli import cmd_doctor

        def run():
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cmd_doctor(Namespace(), self.ctx.config)
            return buf.getvalue()

        self.doctor_out.setPlainText("Running checks...")
        self.ctx.bridge.call_sync(
            run,
            on_result=self.doctor_out.setPlainText,
            on_error=lambda e: self.doctor_out.setPlainText(f"Diagnostics failed: {e}"),
        )
