import logging
import os
import sys
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from yemu.gui import theme
from yemu.gui.context import AppContext
from yemu.gui.main_window import MainWindow

ICON = Path(__file__).resolve().parent / "assets" / "yemu.png"


def create_window(app=None, db_path=None):
    ctx = AppContext(db_path=db_path)
    theme.apply(app or QApplication.instance(), ctx.config["ui"]["theme"])
    window = MainWindow(ctx)
    ctx.connect_db(on_ready=window.pages["history"].refresh)
    return ctx, window


def main(argv=None):
    from yemu.logging_setup import setup_logging

    setup_logging(console_level=logging.INFO)
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("YEMU")
    app.setOrganizationName("YEMU")
    app.setDesktopFileName("io.github.ogshrug.YEMU")
    if ICON.is_file():
        app.setWindowIcon(QIcon(str(ICON)))
    ctx, window = create_window(app)
    window.show()
    if os.environ.get("YEMU_SMOKE_TEST"):
        # packaged-build check: start, let the DB and backend come up, then exit cleanly
        def finish():
            ok = ctx.db_ready
            window.close()
            app.exit(0 if ok else 1)

        QTimer.singleShot(3000, finish)
    return app.exec()
