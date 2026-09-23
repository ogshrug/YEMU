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
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(name)s: %(message)s")
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("YEMU")
    app.setOrganizationName("YEMU")
    app.setDesktopFileName("io.github.ogshrug.YEMU")
    _, window = create_window(app)
    window.show()
    return app.exec()
