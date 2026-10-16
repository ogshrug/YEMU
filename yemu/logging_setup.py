"""Console + rotating file logging shared by the CLI and the desktop app."""

import logging
import logging.handlers

from yemu import paths

FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
# extra= for records the user has already been shown in a shorter form: they go to the file only
FILE_ONLY = {"file_only": True}


def log_file():
    return paths.logs_dir() / "yemu.log"


def setup_logging(console_level=logging.WARNING, file_level=logging.INFO):
    """Log to stderr and to <data>/logs/yemu.log (5 MB x 5 files). Safe to call more than once."""
    root = logging.getLogger()
    root.setLevel(min(console_level, file_level))
    for h in list(root.handlers):
        if (h.get_name() or "").startswith("yemu-"):
            root.removeHandler(h)

    console = logging.StreamHandler()
    console.setLevel(console_level)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    # analysis progress is already shown by the CLI/GUI; keep it in the file log only
    console.addFilter(
        lambda record: not record.name.startswith("yemu.analysis") and not getattr(record, "file_only", False)
    )
    console.set_name("yemu-console")
    root.addHandler(console)

    path = log_file()
    try:
        fh = logging.handlers.RotatingFileHandler(path, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setLevel(file_level)
        fh.setFormatter(logging.Formatter(FORMAT))
        fh.set_name("yemu-file")
        root.addHandler(fh)
    except OSError as e:
        logging.getLogger(__name__).warning(f"File logging disabled ({path}): {e}")
    return path
