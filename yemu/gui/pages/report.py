import json
from typing import Any

from PySide6.QtCore import QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QTableView,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from yemu.core.report_model import build_report
from yemu.gui import theme
from yemu.gui.widgets import (
    ScoreGauge,
    StatCard,
    VerdictBadge,
    button,
    card,
    human_size,
    human_time,
    label,
    show_status,
)


class _EventFilter(QSortFilterProxyModel):
    """Free-text match across all columns plus an optional exact match on the type column."""

    def __init__(self):
        super().__init__()
        self.text = ""
        self.type = ""

    def set_filter(self, text, event_type):
        self.text = text.lower()
        self.type = event_type
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        m = self.sourceModel()
        if self.type and m.index(row, 1, parent).data() != self.type:
            return False
        if not self.text:
            return True
        return any(self.text in str(m.index(row, c, parent).data() or "").lower() for c in range(m.columnCount()))


def _table(headers, stretch_col):
    model = QStandardItemModel(0, len(headers))
    model.setHorizontalHeaderLabels(headers)
    proxy = _EventFilter()
    proxy.setSourceModel(model)
    view = QTableView()
    view.setModel(proxy)
    view.setSortingEnabled(True)
    view.setAlternatingRowColors(True)
    view.setShowGrid(False)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.verticalHeader().hide()
    view.verticalHeader().setDefaultSectionSize(28)
    view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    view.horizontalHeader().setSectionResizeMode(stretch_col, QHeaderView.ResizeMode.Stretch)
    return model, proxy, view


def _clock(ts):
    """strace -tt stamps are seconds since midnight; show them as wall-clock time."""
    ts = float(ts or 0)
    if ts < 1000:  # pipeline-relative markers (e.g. "Execution started")
        return f"+{ts:.3f}s"
    h, rem = divmod(ts, 3600)
    m, s = divmod(rem, 60)
    return f"{int(h):02d}:{int(m):02d}:{s:06.3f}"


def _item(value):
    it = QStandardItem()
    it.setData(value, Qt.ItemDataRole.DisplayRole)
    return it


class ReportPage(QWidget):
    back = Signal()

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        self.report = None
        self.raw: tuple[Any, list] = (None, [])

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 20, 28, 24)
        root.setSpacing(14)

        top = QHBoxLayout()
        back = button("Back", "back", "Flat")
        back.clicked.connect(self.back.emit)
        top.addWidget(back)
        top.addStretch(1)
        self.export_json = button("Export JSON", "download")
        self.export_json.clicked.connect(self._export_json)
        self.export_pdf = button("Export PDF", "download", "Primary")
        self.export_pdf.clicked.connect(self._export_pdf)
        top.addWidget(self.export_json)
        top.addWidget(self.export_pdf)
        root.addLayout(top)

        header, hl = card(margins=20, spacing=20, horizontal=True)
        self.gauge = ScoreGauge(120)
        hl.addWidget(self.gauge)
        info = QVBoxLayout()
        info.setSpacing(6)
        title_row = QHBoxLayout()
        self.title = label("", "PageTitle", selectable=True)
        self.badge = VerdictBadge()
        title_row.addWidget(self.title)
        title_row.addSpacing(8)
        title_row.addWidget(self.badge)
        title_row.addStretch(1)
        info.addLayout(title_row)
        meta = QGridLayout()
        meta.setHorizontalSpacing(16)
        meta.setVerticalSpacing(4)
        self.meta = {}
        for i, key in enumerate(("SHA-256", "MD5", "Size", "Started", "Finished")):
            meta.addWidget(label(key, "Muted"), i, 0)
            val = label("", selectable=True)
            meta.addWidget(val, i, 1)
            self.meta[key] = val
        copy = button("", "copy", "Flat")
        copy.setToolTip("Copy SHA-256")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.report["sha256"] if self.report else ""))
        meta.addWidget(copy, 0, 2)
        meta.setColumnStretch(1, 1)
        info.addLayout(meta)
        hl.addLayout(info, 1)
        root.addWidget(header)

        self.status_banner = label("", wrap=True)
        self.status_banner.hide()
        root.addWidget(self.status_banner)

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.s_yara = StatCard("YARA hits", accent=theme.VERDICT_COLORS["malicious"])
        self.s_proc = StatCard("Processes")
        self.s_file = StatCard("File operations")
        self.s_net = StatCard("Network IOCs")
        for s in (self.s_yara, self.s_proc, self.s_file, self.s_net):
            stats.addWidget(s)
        root.addLayout(stats)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)

        # Overview: process tree + errors
        ov = QWidget()
        ovl = QVBoxLayout(ov)
        ovl.setContentsMargins(12, 12, 12, 12)
        ovl.addWidget(label("Why this verdict", "SectionTitle"))
        self.findings = QTreeWidget()
        self.findings.setHeaderLabels(["Finding", "Detail"])
        self.findings.setRootIsDecorated(False)
        self.findings.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.findings.setMaximumHeight(170)
        ovl.addWidget(self.findings)
        ovl.addWidget(label("Process tree", "SectionTitle"))
        self.proc_tree = QTreeWidget()
        self.proc_tree.setHeaderLabels(["Process", "PID", "Command line"])
        self.proc_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        ovl.addWidget(self.proc_tree, 1)
        self.errors = label("", wrap=True)
        self.errors.setStyleSheet(f"color: {theme.VERDICT_COLORS['malicious']};")
        ovl.addWidget(self.errors)
        self.tabs.addTab(ov, "Overview")

        # YARA
        self.yara_tree = QTreeWidget()
        self.yara_tree.setHeaderLabels(["Rule / string", "Source", "Details"])
        self.yara_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tabs.addTab(self.yara_tree, "YARA")

        # Behaviour
        bw = QWidget()
        bl = QVBoxLayout(bw)
        bl.setContentsMargins(12, 12, 12, 12)
        bar = QHBoxLayout()
        self.b_search = QLineEdit()
        self.b_search.setPlaceholderText("Filter events (path, command, IP...)")
        self.b_search.setClearButtonEnabled(True)
        self.b_type = QComboBox()
        self.b_type.addItems(["All types", "process", "file", "network"])
        bar.addWidget(self.b_search, 1)
        bar.addWidget(self.b_type)
        bl.addLayout(bar)
        self.b_model, self.b_proxy, self.b_view = _table(["Time", "Type", "PID", "Process", "Event"], 4)
        bl.addWidget(self.b_view, 1)
        self.b_search.textChanged.connect(self._filter_behaviour)
        self.b_type.currentTextChanged.connect(self._filter_behaviour)
        self.tabs.addTab(bw, "Behaviour")

        # Network
        self.n_model, _, self.n_view = _table(["Type", "Value", "Source"], 1)
        self.tabs.addTab(self.n_view, "Network")

        # Raw
        self.raw_view = QPlainTextEdit()
        self.raw_view.setObjectName("Code")
        self.raw_view.setReadOnly(True)
        self.tabs.addTab(self.raw_view, "Raw JSON")

    # --- loading ---
    def load(self, analysis_id):
        async def fetch():
            return (
                await self.ctx.db.get_analysis_details(analysis_id),
                await self.ctx.db.get_analysis_events(analysis_id),
            )

        self.ctx.bridge.call(
            fetch(),
            self._show,
            lambda e: QMessageBox.warning(self, "YEMU", f"Could not load analysis #{analysis_id}: {e}"),
        )

    def _show(self, result):
        details, events = result
        if not details:
            QMessageBox.warning(self, "YEMU", "That analysis no longer exists.")
            self.back.emit()
            return
        self.raw = (details, events)
        r = self.report = build_report(details, events)
        self.gauge.set_score(r["score"], r["verdict"])
        self.badge.set_verdict(r["verdict"])
        self.title.setText(f"#{r['id']}  {r['filename']}")
        self.meta["SHA-256"].setText(r["sha256"] or "-")
        self.meta["MD5"].setText(r["md5"] or "-")
        self.meta["Size"].setText(human_size(r["size_bytes"]))
        self.meta["Started"].setText(human_time(r["started_at"]))
        self.meta["Finished"].setText(human_time(r["finished_at"]))
        self.s_yara.set_value(len(r["yara_matches"]))
        self.s_proc.set_value(len(r["processes"]))
        self.s_file.set_value(r["counts"].get("file", 0))
        self.s_net.set_value(len(r["iocs"]))

        self._fill_process_tree(r["processes"])
        self._fill_findings(r)
        if r["status"] in ("failed", "timeout", "interrupted", "running"):
            color = theme.VERDICT_COLORS["suspicious" if r["status"] in ("interrupted", "running") else "malicious"]
            self.status_banner.setText(
                f"<b>Analysis {r['status']}.</b> {r['error'] or ''} The verdict below may be based on partial results."
            )
            self.status_banner.setStyleSheet(
                f"QLabel {{ color: {color}; border: 1px solid {color}; border-radius: 8px; padding: 8px 12px; }}"
            )
            self.status_banner.show()
        else:
            self.status_banner.hide()
        self.errors.setText("\n".join(f"Error: {e}" for e in r["errors"]))
        self._fill_yara(r["yara_matches"])

        self.b_model.removeRows(0, self.b_model.rowCount())
        for e in r["behaviour"]:
            t = _item(_clock(e["timestamp"]))
            self.b_model.appendRow(
                [t, _item(e["type"]), _item(str(e["pid"])), _item(e["process"]), _item(e["description"])]
            )
        self.n_model.removeRows(0, self.n_model.rowCount())
        for ioc in r["iocs"]:
            self.n_model.appendRow([_item(ioc["type"]), _item(ioc["value"]), _item(ioc["source"])])
        self.b_view.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.raw_view.setPlainText(
            json.dumps({k: v for k, v in r.items() if k not in ("raw_details",)}, indent=2, default=str)
        )
        self.tabs.setCurrentIndex(0)

    def _fill_process_tree(self, processes):
        self.proc_tree.clear()
        by_pid: dict[str, dict] = {}
        for p in processes:
            by_pid.setdefault(str(p["pid"]), p)
        items = {}
        for pid, p in by_pid.items():
            it = QTreeWidgetItem([p["name"] or "?", pid, p["cmdline"]])
            items[pid] = it
        for pid, p in by_pid.items():
            parent = items.get(str(p["ppid"]))
            (
                parent.addChild(items[pid])
                if parent and parent is not items[pid]
                else self.proc_tree.addTopLevelItem(items[pid])
            )
        self.proc_tree.expandAll()
        self.proc_tree.resizeColumnToContents(0)

    def _fill_findings(self, r):
        self.findings.clear()
        colors = {
            "persistence": theme.VERDICT_COLORS["malicious"],
            "network": theme.VERDICT_COLORS["malicious"],
            "suspicious": theme.VERDICT_COLORS["suspicious"],
        }
        rows = [("yara", f"{m.get('rule')} ({m.get('source', '?')})") for m in r["yara_matches"]]
        rows += [(f["kind"], f["text"]) for f in r["findings"]]
        if not rows:
            rows = [("none", "No YARA hits or suspicious behaviour were recorded.")]
        for kind, text in rows:
            it = QTreeWidgetItem([kind.capitalize(), text])
            color = colors.get(kind) or (theme.VERDICT_COLORS["malicious"] if kind == "yara" else None)
            if color:
                it.setForeground(0, QColor(color))
            self.findings.addTopLevelItem(it)
        self.findings.resizeColumnToContents(0)

    def _fill_yara(self, matches):
        self.yara_tree.clear()
        red = QColor(theme.VERDICT_COLORS["malicious"])
        for m in matches:
            desc = (m.get("meta") or {}).get("description", "")
            where = m.get("process_name") if m.get("source") == "memory" else ""
            top = QTreeWidgetItem([m.get("rule", "?"), m.get("source", ""), desc or where])
            top.setForeground(0, red)
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            if m.get("tags"):
                top.addChild(QTreeWidgetItem(["tags", "", ", ".join(m["tags"])]))
            if m.get("source") == "memory":
                top.addChild(
                    QTreeWidgetItem(
                        ["process", f"PID {m.get('pid')}", f"{m.get('exe_path', '')} {m.get('cmdline', '')}"]
                    )
                )
            for s in m.get("strings", [])[:50]:
                top.addChild(
                    QTreeWidgetItem(
                        [s.get("identifier", ""), s.get("offset", ""), s.get("printable") or s.get("data", "")]
                    )
                )
            self.yara_tree.addTopLevelItem(top)
        self.yara_tree.expandToDepth(0)
        self.yara_tree.resizeColumnToContents(0)

    def _filter_behaviour(self):
        t = self.b_type.currentText()
        self.b_proxy.set_filter(self.b_search.text(), "" if t.startswith("All") else t)

    # --- export ---
    def _export_json(self):
        if not self.report:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", f"yemu_report_{self.report['id']}.json", "JSON (*.json)"
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({k: v for k, v in self.report.items() if k != "raw_details"}, f, indent=2, default=str)
            show_status(self, f"Saved {path}", 5000)

    def _export_pdf(self):
        if not self.report:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export PDF", f"yemu_report_{self.report['id']}.pdf", "PDF (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        from yemu.core.report_generator import PDFGenerator

        details, events = self.raw
        self.export_pdf.setEnabled(False)

        def done(_):
            self.export_pdf.setEnabled(True)
            show_status(self, f"PDF saved to {path}", 5000)

        def failed(e):
            self.export_pdf.setEnabled(True)
            QMessageBox.warning(self, "YEMU", f"PDF export failed: {e}")

        self.ctx.bridge.call_sync(PDFGenerator(path).generate, details, events, on_result=done, on_error=failed)
