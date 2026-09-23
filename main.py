# Backwards-compatible launcher: `python main.py` still opens the GUI.
import sys

from yemu.app import main

if __name__ == "__main__":
    sys.exit(main())
