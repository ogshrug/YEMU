from PySide6.QtCore import QSortFilterProxyModel, Qt, Signal
from PySide6.QtGui import QColor, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLineEdit, QStackedWidget, QTableView, QVBoxLayout, QWidget

from yemu.gui import theme
from yemu.gui.widgets import EmptyState, StatCard, button, human_time, page_header

COLUMNS = ["ID", "File", "Verdict", "Score", "Started"]


class _Filter(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.text = ""
        self.verdict = ""

    def filterAcceptsRow(self, row, parent):
        m = self.sourceModel()
        name = m.index(row, 1, parent).data() or ""
        verdict = m.index(row, 2, parent).data() or ""
        if self.verdict and verdict.lower() != self.verdict:
            return False
        return self.text.lower() in f"{name} {m.index(row, 0, parent).data()}".lower()


class HistoryPage(QWidget):
    open_report = Signal(int)

    def __init__(self, ctx, parent=None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(16)
        root.addLayout(page_header("History", "Every analysis run on this machine. Double-click a row to open its report."))

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.stat_total = StatCard("Analyses")
        self.stat_mal = StatCard("Malicious", accent=theme.VERDICT_COLORS["malicious"])
        self.stat_sus = StatCard("Suspicious", accent=theme.VERDICT_COLORS["suspicious"])
        self.stat_clean = StatCard("Clean", accent=theme.VERDICT_COLORS["clean"])
        for s in (self.stat_total, self.stat_mal, self.stat_sus, self.stat_clean):
            stats.addWidget(s)
        root.addLayout(stats)

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by file name or ID")
        self.search.setClearButtonEnabled(True)
        self.search.addAction(theme.icon("search", "#98a2b3", 16), QLineEdit.LeadingPosition)
        self.verdict = QComboBox()
        self.verdict.addItems(["All verdicts", "Malicious", "Suspicious", "Clean", "Manual", "Unknown"])
        refresh = button("Refresh", "refresh")
        refresh.clicked.connect(self.refresh)
        bar.addWidget(self.search, 1)
        bar.addWidget(self.verdict)
        bar.addWidget(refresh)
        root.addLayout(bar)

        self.model = QStandardItemModel(0, len(COLUMNS))
        self.model.setHorizontalHeaderLabels(COLUMNS)
        self.proxy = _Filter()
        self.proxy.setSourceModel(self.model)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(34)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(1, QHeaderView.Stretch)
        for col, width in ((0, 60), (2, 120), (3, 80), (4, 170)):
            h.setSectionResizeMode(col, QHeaderView.Fixed)
            self.table.setColumnWidth(col, width)
        self.table.doubleClicked.connect(self._open)

        self.stack = QStackedWidget()
        self.stack.addWidget(self.table)
        self.stack.addWidget(EmptyState("history", "No analyses yet", "Run one from the Analyze page and it will show up here."))
        root.addWidget(self.stack, 1)

        self.search.textChanged.connect(self._filter)
        self.verdict.currentTextChanged.connect(self._filter)
        ctx.analyses_changed.connect(self.refresh)

    def _filter(self):
        self.proxy.text = self.search.text()
        v = self.verdict.currentText().lower()
        self.proxy.verdict = "" if v.startswith("all") else v
        self.proxy.invalidateFilter()

    def refresh(self):
        if not self.ctx.db_ready:
            return
        self.ctx.bridge.call(self.ctx.db.get_recent_analyses(limit=1000), self._populate)

    def _populate(self, rows):
        self.model.removeRows(0, self.model.rowCount())
        counts = {"malicious": 0, "suspicious": 0, "clean": 0}
        for r in rows or []:
            verdict = (r.get("verdict") or "unknown").lower()
            counts[verdict] = counts.get(verdict, 0) + 1
            id_item = QStandardItem()
            id_item.setData(r["id"], Qt.DisplayRole)
            score = QStandardItem()
            score.setData(r.get("threat_score") or 0, Qt.DisplayRole)
            v_item = QStandardItem(verdict.capitalize())
            v_item.setForeground(QColor(theme.VERDICT_COLORS.get(verdict, theme.VERDICT_COLORS["unknown"])))
            f = v_item.font()
            f.setBold(True)
            v_item.setFont(f)
            self.model.appendRow([id_item, QStandardItem(r.get("filename") or ""), v_item, score,
                                  QStandardItem(human_time(r.get("started_at")))])
        self.table.sortByColumn(0, Qt.DescendingOrder)
        self.stat_total.set_value(len(rows or []))
        self.stat_mal.set_value(counts["malicious"])
        self.stat_sus.set_value(counts["suspicious"])
        self.stat_clean.set_value(counts["clean"])
        self.stack.setCurrentIndex(0 if rows else 1)

    def _open(self, index):
        analysis_id = self.proxy.index(index.row(), 0).data()
        if analysis_id is not None:
            self.open_report.emit(int(analysis_id))
