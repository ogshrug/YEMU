import logging
import sys

from PySide6.QtWidgets import QApplication

from yemu.gui import theme
from yemu.gui.context import AppContext
from yemu.gui.main_window import MainWindow


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
    _, window = create_window(app)
    window.show()
    return app.exec()
