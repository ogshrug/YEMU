from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QApplication, QDialog, QHBoxLayout, QMessageBox, QPlainTextEdit, QProgressBar, QVBoxLayout

from yemu import __version__
from yemu.core import updates
from yemu.gui.widgets import button, label, page_header


class UpdateDialog(QDialog):
    """Offers a newer YEMU release; downloads and verifies it only when the user asks."""

    def __init__(self, ctx, release, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.release = release
        self.kind = updates.install_kind()
        self.asset = updates.pick_asset(release, self.kind)
        self.setWindowTitle("YEMU update")
        self.setMinimumWidth(560)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)
        published = (release.get("published") or "")[:10]
        lay.addLayout(
            page_header(f"YEMU {release['version']} is available", f"You have {__version__}. Released {published}.")
        )
        notes = QPlainTextEdit(release.get("notes") or "No release notes.")
        notes.setObjectName("Code")
        notes.setReadOnly(True)
        notes.setMinimumHeight(200)
        lay.addWidget(notes, 1)

        self.hint = label("", "Muted", wrap=True, selectable=True)
        lay.addWidget(self.hint)
        self.bar = QProgressBar()
        self.bar.setFixedHeight(8)
        self.bar.hide()
        lay.addWidget(self.bar)

        row = QHBoxLayout()
        skip = button("Skip this version")
        skip.clicked.connect(self._skip)
        page = button("Release page")
        page.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(release["url"])))
        later = button("Later")
        later.clicked.connect(self.reject)
        row.addWidget(skip)
        row.addStretch(1)
        row.addWidget(page)
        row.addWidget(later)

        # always created; hidden when there is nothing to do but visit the release page
        self.primary = button("Download", "download", "Primary")
        self.primary.clicked.connect(self._primary)
        if self.kind == "installer" and self.asset:
            self.primary.setText("Download and install")
            self.hint.setText(
                "The installer is verified against the release checksums, then YEMU closes so it can "
                "update. Your analyses, VMs and settings are kept."
            )
        elif self.kind == "portable-windows" and self.asset:
            self.hint.setText("Downloads the portable zip (checksum-verified). Unzip it over your current YEMU folder.")
        else:
            cmd = updates.manual_update_hint(release, self.kind)
            self.hint.setText(cmd)
            self.primary.setText("Copy command")
            self.primary.setVisible(cmd.startswith("pip "))
        row.addWidget(self.primary)
        lay.addLayout(row)

    def _skip(self):
        updates.save_state(skipped_version=self.release["version"])
        self.reject()

    def _primary(self):
        if self.kind not in ("installer", "portable-windows"):
            QGuiApplication.clipboard().setText(self.hint.text())
            self.primary.setText("Copied")
            return
        self.primary.setEnabled(False)
        self.bar.show()
        self.bar.setRange(0, 0)

        def progress(done, total):
            def show():
                if total:
                    self.bar.setRange(0, total)
                    self.bar.setValue(done)

            self.ctx.bridge.post(show)

        self.ctx.bridge.call_sync(
            updates.download_update,
            self.release,
            self.asset,
            None,
            progress,
            on_result=self._downloaded,
            on_error=self._failed,
        )

    def _downloaded(self, path):
        self.bar.hide()
        if self.kind == "portable-windows":
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent)))
            self.hint.setText(f"Saved and verified: {path}")
            self.primary.setText("Downloaded")
            return
        if self.ctx.analysis_running:
            QMessageBox.information(
                self, "YEMU", f"The installer is ready at {path}. Run it when the current analysis has finished."
            )
            self.accept()
            return
        updates.launch_installer(path)
        QApplication.quit()

    def _failed(self, error):
        self.bar.hide()
        self.primary.setEnabled(True)
        QMessageBox.warning(self, "YEMU", f"Update failed: {error}")
