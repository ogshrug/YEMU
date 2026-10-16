import logging
import os
import sys
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMessageBox

from yemu import config as yemu_config
from yemu import paths
from yemu.gui import theme
from yemu.gui.context import AppContext
from yemu.gui.main_window import MainWindow

ICON = Path(__file__).resolve().parent / "assets" / "yemu.png"

logger = logging.getLogger(__name__)


def report_exception(exc_type, exc, tb):
    """sys.excepthook: errors in Qt slots would otherwise only reach stderr, which the windowed build lacks."""
    from yemu.logging_setup import log_file

    logger.error("Uncaught exception", exc_info=(exc_type, exc, tb))
    if os.environ.get("YEMU_SMOKE_TEST"):
        QApplication.exit(1)
        return
    QMessageBox.critical(None, "YEMU error", f"{exc_type.__name__}: {exc}\n\nDetails are in {log_file()}")


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
    sys.excepthook = report_exception
    try:
        ctx, window = create_window(app)
    except yemu_config.ConfigError as e:
        # stop before anything can save the defaults over the user's file
        logger.error(f"Config error: {e}")
        if not os.environ.get("YEMU_SMOKE_TEST"):
            QMessageBox.critical(
                None,
                "YEMU configuration error",
                f"{e}\n\nFix {paths.config_file()}, or reset it to the defaults with:\n    yemu config --init --force",
            )
        return 2
    window.show()
    if not os.environ.get("YEMU_SMOKE_TEST") and not os.environ.get("YEMU_NO_UPDATE_CHECK"):
        # after the window is up, so a slow network never delays startup
        QTimer.singleShot(2000, ctx.run_background_updates)
    if os.environ.get("YEMU_SMOKE_TEST"):
        # packaged-build check: start, let the DB and backend come up, then exit cleanly
        def finish():
            ok = ctx.db_ready
            window.close()
            app.exit(0 if ok else 1)

        QTimer.singleShot(3000, finish)
    return app.exec()
