import re

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (QAbstractItemView, QComboBox, QDialog, QFormLayout, QHBoxLayout, QHeaderView, QLineEdit,
                               QMessageBox, QProgressBar, QSpinBox, QStackedWidget, QTableView, QVBoxLayout, QWidget)

from yemu.core.provisioning import provision_vm
from yemu.gui.widgets import EmptyState, LogView, button, card, label, page_header

STATE_COLORS = {"running": "#16a34a", "stopped": "#6b7280", "unknown": "#6b7280"}


class CreateVMDialog(QDialog):
    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.running = False
        self.setWindowTitle("Create analysis VM")
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(14)
        lay.addLayout(page_header("New analysis VM", f"Backend: {ctx.backend_label()}. Downloads a cloud image "
                                  "(cached), installs guest tools over NAT, then locks the VM onto the isolated network."))
        form = QFormLayout()
        form.setHorizontalSpacing(16)
        self.name = QLineEdit(ctx.config["vm"]["default_vm"] if ctx.config["vm"]["default_vm"] not in ctx.backend.list_vms() else "")
        self.name.setPlaceholderText("e.g. ubuntu-clean")
        self.distro = QComboBox()
        self.distro.addItems(["ubuntu", "debian"] + (["windows"] if ctx.backend.name == "libvirt" else []))
        self.ram = QSpinBox()
        self.ram.setButtonSymbols(QSpinBox.NoButtons)
        self.ram.setRange(1024, 65536)
        self.ram.setSingleStep(1024)
        self.ram.setValue(2048)
        self.ram.setSuffix(" MiB")
        self.cpus = QSpinBox()
        self.cpus.setButtonSymbols(QSpinBox.NoButtons)
        self.cpus.setRange(1, 32)
        self.cpus.setValue(2)
        self.disk = QSpinBox()
        self.disk.setButtonSymbols(QSpinBox.NoButtons)
        self.disk.setRange(10, 500)
        self.disk.setValue(20)
        self.disk.setSuffix(" GiB")
        for text, w in (("Name", self.name), ("Distribution", self.distro), ("Memory", self.ram),
                        ("CPUs", self.cpus), ("Disk", self.disk)):
            form.addRow(text, w)
        lay.addLayout(form)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setFixedHeight(8)
        self.bar.hide()
        lay.addWidget(self.bar)
        self.step = label("", "Muted")
        lay.addWidget(self.step)
        self.log = LogView()
        self.log.setMinimumHeight(180)
        self.log.hide()
        lay.addWidget(self.log, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        self.close_btn = button("Cancel")
        self.close_btn.clicked.connect(self.reject)
        self.create_btn = button("Create VM", "plus", "Primary")
        self.create_btn.clicked.connect(self._create)
        row.addWidget(self.close_btn)
        row.addWidget(self.create_btn)
        lay.addLayout(row)

    def _create(self):
        name = self.name.text().strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name or ""):
            QMessageBox.warning(self, "YEMU", "Use letters, digits, '.', '_' or '-' for the VM name.")
            return
        self.running = True
        for w in (self.name, self.distro, self.ram, self.cpus, self.disk, self.create_btn):
            w.setEnabled(False)
        self.close_btn.setEnabled(False)
        self.bar.show()
        self.log.show()
        self.bar.setValue(0)
        cfg = self.ctx.config
        coro = provision_vm(self.ctx.backend, name, distro=self.distro.currentText(), ram_mb=self.ram.value(),
                            cpus=self.cpus.value(), disk_gb=self.disk.value(),
                            analysis_network=cfg["network"]["name"], snapshot_name=cfg["vm"]["default_snapshot"],
                            progress=self._progress_threadsafe)
        self.ctx.bridge.call(coro, self._done, self._failed)

    def _progress_threadsafe(self, msg, fraction):
        # called on the runner thread
        self.ctx.bridge.post(lambda: self._progress(msg, fraction))

    def _progress(self, msg, fraction):
        if msg:
            self.log.append_line(msg)
            self.step.setText(msg)
        if fraction is not None:
            self.bar.setValue(int(fraction * 1000))

    def _done(self, password):
        self.running = False
        self.bar.setValue(1000)
        self.log.append_line(f"Guest console password: {password}")
        self.step.setText("VM is ready and isolated.")
        self.close_btn.setText("Close")
        self.close_btn.setEnabled(True)
        self.ctx.backend_changed.emit()

    def _failed(self, error):
        self.running = False
        self.log.append_line(f"VM preparation failed: {error}", "CRITICAL")
        self.step.setText("Failed. See the log above; the VM console log has more detail.")
        self.close_btn.setText("Close")
        self.close_btn.setEnabled(True)
        self.ctx.backend_changed.emit()

    def reject(self):
        if self.running:
            return  # provisioning can't be cancelled midway safely
        super().reject()


class VMsPage(QWidget):
    COLUMNS = ["Name", "State", "Snapshots", "Backend"]

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addLayout(page_header("Virtual machines",
                                   "Analysis VMs revert to their clean snapshot before every run and stay on an isolated network."))

        self.banner, bl = card(horizontal=True)
        self.banner_text = label("", wrap=True)
        bl.addWidget(self.banner_text, 1)
        root.addWidget(self.banner)

        bar = QHBoxLayout()
        self.create_btn = button("Create VM", "plus", "Primary")
        self.start_btn = button("Start", "play")
        self.stop_btn = button("Stop", "stop")
        self.console_btn = button("Console", "monitor")
        self.delete_btn = button("Delete", "trash", "Danger", color="#dc2626")
        refresh = button("Refresh", "refresh")
        for b in (self.create_btn, self.start_btn, self.stop_btn, self.console_btn, self.delete_btn):
            bar.addWidget(b)
        bar.addStretch(1)
        bar.addWidget(refresh)
        root.addLayout(bar)

        self.model = QStandardItemModel(0, len(self.COLUMNS))
        self.model.setHorizontalHeaderLabels(self.COLUMNS)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.selectionModel().selectionChanged.connect(self._update_buttons)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.table)
        self.stack.addWidget(EmptyState("vms", "No analysis VMs yet",
                                        "Click Create VM to build an isolated Ubuntu guest. It takes a few minutes the first time."))
        root.addWidget(self.stack, 1)

        self.create_btn.clicked.connect(self._create)
        self.start_btn.clicked.connect(lambda: self._act("start"))
        self.stop_btn.clicked.connect(lambda: self._act("stop"))
        self.console_btn.clicked.connect(lambda: self._act("console"))
        self.delete_btn.clicked.connect(self._delete)
        refresh.clicked.connect(self.refresh)
        ctx.backend_changed.connect(self.refresh)
        self.refresh()

    def _selected(self):
        rows = self.table.selectionModel().selectedRows()
        return self.model.item(rows[0].row(), 0).text() if rows else None

    def _update_buttons(self):
        name = self._selected()
        real = self.ctx.backend.name != "mock"
        state = self.model.item(self.table.selectionModel().selectedRows()[0].row(), 1).text() if name else ""
        self.create_btn.setEnabled(real)
        self.start_btn.setEnabled(bool(name) and real and state != "running")
        self.stop_btn.setEnabled(bool(name) and real and state != "stopped")
        self.console_btn.setEnabled(bool(name) and real)
        self.delete_btn.setEnabled(bool(name) and hasattr(self.ctx.backend, "delete_vm") and not self.ctx.analysis_running)

    def refresh(self):
        b = self.ctx.backend
        if b.name == "mock":
            self.banner_text.setText("<b>Mock mode.</b> No hypervisor was found, so VMs below are simulated. "
                                     "Install QEMU (Windows/Linux) or libvirt (Linux), then pick a backend in Settings.")
        elif b.name == "qemu":
            accel = b.accel
            speed = "hardware accelerated" if accel != "tcg" else "<b>software emulation (slow)</b>: enable WHPX/KVM for speed"
            self.banner_text.setText(f"<b>QEMU backend</b> · {accel}, {speed}. Analysis network: user-mode with "
                                     "<code>restrict=on</code> (no outside access).")
        else:
            self.banner_text.setText(f"<b>libvirt backend</b> · isolated network <code>{self.ctx.config['network']['name']}</code>.")

        async def collect():
            import asyncio
            vms = await asyncio.to_thread(b.list_vms)
            rows = []
            for vm in sorted(vms):
                snaps = await asyncio.to_thread(b.list_snapshots, vm)
                rows.append((vm, await b.vm_state(vm), snaps))
            return rows
        self.ctx.bridge.call(collect(), self._populate, lambda e: self.ctx.log(f"Could not list VMs: {e}", "WARN"))

    def _populate(self, rows):
        selected = self._selected()
        self.model.removeRows(0, self.model.rowCount())
        for name, state, snaps in rows:
            st = QStandardItem(state)
            st.setForeground(QColor(STATE_COLORS.get(state, "#6b7280")))
            self.model.appendRow([QStandardItem(name), st, QStandardItem(", ".join(snaps) or "none (not ready)"),
                                  QStandardItem(self.ctx.backend.name)])
        self.stack.setCurrentIndex(0 if rows else 1)
        for r in range(self.model.rowCount()):
            if self.model.item(r, 0).text() == selected:
                self.table.selectRow(r)
        self._update_buttons()

    def _create(self):
        CreateVMDialog(self.ctx, self).exec()
        self.refresh()

    def _act(self, action):
        name = self._selected()
        if not name:
            return
        b = self.ctx.backend
        coro = {"start": lambda: b.start_vm(name), "stop": lambda: b.stop_vm(name), "console": None}[action]
        if action == "console":
            async def console():
                if await b.vm_state(name) != "running":
                    await b.start_vm(name)
                return await b.open_gui(name)
            coro = console
        self.ctx.bridge.call(coro(), lambda _: self.refresh(),
                             lambda e: QMessageBox.warning(self, "YEMU", f"{action.capitalize()} failed: {e}"))

    def _delete(self):
        name = self._selected()
        if not name:
            return
        if QMessageBox.question(self, "Delete VM", f"Delete '{name}' and its disk? This cannot be undone.") != QMessageBox.Yes:
            return
        self.ctx.bridge.call(self.ctx.backend.delete_vm(name), lambda _: self.refresh())
