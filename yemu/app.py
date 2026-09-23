"""Desktop app launcher (`yemu gui`, `yemu-gui`, `python main.py`)."""

import sys


def main(argv=None):
    try:
        from yemu.gui.app import main as qt_main
    except ImportError as e:
        print(
            f"The YEMU desktop app needs PySide6 ({e}). Install it with:  pip install \"yemu[gui]\"  "
            "(or pip install PySide6)",
            file=sys.stderr,
        )
        return 1
    return qt_main(argv)


if __name__ == "__main__":
    sys.exit(main())
