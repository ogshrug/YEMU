# PyInstaller spec: one folder with `yemu` (CLI, console) and `yemu-gui` (desktop app, windowed).
# Build with:  pyinstaller packaging/yemu.spec --noconfirm   (or python scripts/build.py)
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent
ICON = str(ROOT / "yemu" / "gui" / "assets" / ("yemu.ico" if sys.platform == "win32" else "yemu.png"))

datas = [
    (str(ROOT / "yemu" / "rules" / "default.yar"), "yemu/rules"),
    (str(ROOT / "yemu" / "gui" / "assets"), "yemu/gui/assets"),
]
datas += collect_data_files("reportlab")
hiddenimports = collect_submodules("yemu") + collect_submodules("scapy.layers") + ["pycdlib", "aiosqlite"]
# Qt modules YEMU never uses; keeps the bundle a lot smaller
excludes = [
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick", "PySide6.Qt3DCore",
    "PySide6.Qt3DRender", "PySide6.QtMultimedia", "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtCharts",
    "PySide6.QtDataVisualization", "PySide6.QtPdf", "PySide6.QtBluetooth", "PySide6.QtLocation",
    "PySide6.QtPositioning", "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtWebSockets",
    "tkinter", "matplotlib", "IPython", "numpy.tests", "pytest",
]


def analysis(script):
    return Analysis([str(ROOT / "packaging" / script)], pathex=[str(ROOT)], datas=datas,
                    hiddenimports=hiddenimports, excludes=excludes, noarchive=False)


cli = analysis("entry_cli.py")
gui = analysis("entry_gui.py")

cli_exe = EXE(PYZ(cli.pure), cli.scripts, [], exclude_binaries=True, name="yemu", console=True, icon=ICON)
gui_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="yemu-gui", console=False, icon=ICON)

COLLECT(cli_exe, cli.binaries, cli.datas, gui_exe, gui.binaries, gui.datas, name="YEMU")
