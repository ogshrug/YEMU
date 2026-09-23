"""Console + rotating file logging shared by the CLI and the desktop app."""
import logging
import logging.handlers

from yemu import paths

FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"


def setup_logging(console_level=logging.WARNING, file_level=logging.INFO):
    """Log to stderr and to <data>/logs/yemu.log (5 MB x 5 files). Safe to call more than once."""
    root = logging.getLogger()
    root.setLevel(min(console_level, file_level))
    for h in list(root.handlers):
        if getattr(h, "_yemu", False):
            root.removeHandler(h)

    console = logging.StreamHandler()
    console.setLevel(console_level)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    # analysis progress is already shown by the CLI/GUI; keep it in the file log only
    console.addFilter(lambda record: not record.name.startswith("yemu.analysis"))
    console._yemu = True
    root.addHandler(console)

    log_file = paths.logs_dir() / "yemu.log"
    try:
        fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        fh.setLevel(file_level)
        fh.setFormatter(logging.Formatter(FORMAT))
        fh._yemu = True
        root.addHandler(fh)
    except OSError as e:
        logging.getLogger(__name__).warning(f"File logging disabled ({log_file}): {e}")
    return log_file
