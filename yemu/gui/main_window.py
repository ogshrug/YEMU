from PySide6.QtCore import QSize, Qt
from PySide6.QtGui import QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
                               QStackedWidget, QVBoxLayout, QWidget)

from yemu import __version__
from yemu.gui import theme
from yemu.gui.pages.analyze import AnalyzePage
from yemu.gui.pages.history import HistoryPage
from yemu.gui.pages.report import ReportPage
from yemu.gui.pages.rules import RulesPage
from yemu.gui.pages.settings import SettingsPage
from yemu.gui.pages.vms import VMsPage

NAV = [("analyze", "Analyze"), ("history", "History"), ("vms", "VMs"), ("rules", "YARA rules"), ("settings", "Settings")]


def _nav_icon(name, colors):
    ic = QIcon()
    for mode, color in ((QIcon.Normal, colors["sidebar_text"]), (QIcon.Selected, "#ffffff")):
        ic.addPixmap(theme.icon(name, color, 18).pixmap(QSize(18, 18)), mode)
    return ic


class MainWindow(QMainWindow):
    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle("YEMU")
        self.resize(1320, 860)
        self.setMinimumSize(1040, 680)
        self.colors = theme.colors(ctx.config["ui"]["theme"])

        central = QWidget()
        self.setCentralWidget(central)
        row = QHBoxLayout(central)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        # sidebar
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(220)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(12, 22, 12, 16)
        sl.setSpacing(4)
        brand = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(theme.icon("shield", "#7b73ff", 26).pixmap(QSize(26, 26)))
        brand.addWidget(logo)
        name = QVBoxLayout()
        name.setSpacing(0)
        title = QLabel("YEMU")
        title.setObjectName("Brand")
        sub = QLabel("Malware analysis sandbox")
        sub.setObjectName("BrandSub")
        name.addWidget(title)
        name.addWidget(sub)
        brand.addLayout(name, 1)
        sl.addLayout(brand)
        sl.addSpacing(18)
        self.nav = QListWidget()
        self.nav.setObjectName("Nav")
        self.nav.setIconSize(QSize(18, 18))
        self.nav.setFocusPolicy(Qt.NoFocus)
        for key, text in NAV:
            item = QListWidgetItem(_nav_icon(key, self.colors), f"  {text}")
            item.setData(Qt.UserRole, key)
            item.setSizeHint(QSize(0, 40))
            self.nav.addItem(item)
        sl.addWidget(self.nav, 1)
        self.footer = QLabel()
        self.footer.setObjectName("SidebarFooter")
        self.footer.setWordWrap(True)
        sl.addWidget(self.footer)
        row.addWidget(side)

        # pages
        self.stack = QStackedWidget()
        row.addWidget(self.stack, 1)
        self.pages = {
            "analyze": AnalyzePage(ctx),
            "history": HistoryPage(ctx),
            "vms": VMsPage(ctx),
            "rules": RulesPage(ctx),
            "settings": SettingsPage(ctx),
            "report": ReportPage(ctx),
        }
        for page in self.pages.values():
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(lambda r: self.show_page(NAV[r][0]))
        self.pages["analyze"].open_report.connect(self.open_report)
        self.pages["history"].open_report.connect(self.open_report)
        self.pages["report"].back.connect(self._report_back)
        self._report_origin = "history"

        self.backend_status = QLabel()
        self.statusBar().addPermanentWidget(self.backend_status)
        ctx.backend_changed.connect(self._update_status)
        ctx.config_changed.connect(self._apply_theme)
        ctx.log.message.connect(self._on_log)

        QShortcut(QKeySequence.Open, self, activated=lambda: (self.show_page("analyze"), self.pages["analyze"].browse()))
        for i in range(len(NAV)):
            QShortcut(QKeySequence(f"Ctrl+{i + 1}"), self, activated=lambda i=i: self.nav.setCurrentRow(i))

        self.nav.setCurrentRow(0)
        self._update_status()

    def show_page(self, key):
        self.stack.setCurrentWidget(self.pages[key])
        if key == "history":
            self.pages["history"].refresh()
        elif key == "rules":
            self.pages["rules"].refresh()

    def open_report(self, analysis_id):
        self._report_origin = NAV[self.nav.currentRow()][0] if self.nav.currentRow() >= 0 else "history"
        self.pages["report"].load(analysis_id)
        self.stack.setCurrentWidget(self.pages["report"])

    def _report_back(self):
        self.show_page(self._report_origin)

    def _update_status(self):
        label = self.ctx.backend_label()
        dot = "#16a34a" if self.ctx.backend.name != "mock" else "#d97706"
        self.backend_status.setText(f"<span style='color:{dot}'>●</span> Backend: {label}   ")
        self.footer.setText(f"v{__version__} · {label}")

    def _apply_theme(self):
        from PySide6.QtWidgets import QApplication
        self.colors = theme.apply(QApplication.instance(), self.ctx.config["ui"]["theme"])
        for i, (key, _) in enumerate(NAV):
            self.nav.item(i).setIcon(_nav_icon(key, self.colors))

    def _on_log(self, msg, severity):
        if severity == "CRITICAL":
            self.statusBar().showMessage(msg, 8000)

    def closeEvent(self, event):
        if self.ctx.analysis_running and QMessageBox.question(
                self, "Analysis running", "An analysis is still running. Quit anyway? The VM will be left running.") != QMessageBox.Yes:
            event.ignore()
            return
        self.ctx.shutdown()
        event.accept()
