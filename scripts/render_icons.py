"""Render yemu/gui/assets/yemu.svg to the PNG/ICO files used by the app and installers."""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QByteArray, Qt  # noqa: E402
from PySide6.QtGui import QGuiApplication, QImage, QPainter  # noqa: E402
from PySide6.QtSvg import QSvgRenderer  # noqa: E402

ASSETS = Path(__file__).resolve().parent.parent / "yemu" / "gui" / "assets"


def render(size):
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    painter = QPainter(img)
    QSvgRenderer(QByteArray((ASSETS / "yemu.svg").read_bytes())).render(painter)
    painter.end()
    return img


def write_ico(path, sizes=(16, 24, 32, 48, 64, 128, 256)):
    """ICO with PNG-compressed frames (supported since Windows Vista)."""
    import struct
    from PySide6.QtCore import QBuffer, QIODevice

    frames = []
    for s in sizes:
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        render(s).save(buf, "PNG")
        frames.append((s, bytes(buf.data())))
    header = struct.pack("<HHH", 0, 1, len(frames))
    offset = 6 + 16 * len(frames)
    entries, blobs = b"", b""
    for s, data in frames:
        dim = 0 if s >= 256 else s
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset + len(blobs))
        blobs += data
    path.write_bytes(header + entries + blobs)


if __name__ == "__main__":
    app = QGuiApplication(sys.argv)
    render(256).save(str(ASSETS / "yemu.png"))
    render(512).save(str(ASSETS / "yemu-512.png"))
    write_ico(ASSETS / "yemu.ico")
    print("wrote", *sorted(p.name for p in ASSETS.iterdir()))
