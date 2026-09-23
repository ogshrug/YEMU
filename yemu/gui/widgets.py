from datetime import datetime

from PySide6.QtCore import QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from yemu.gui import theme


def card(parent=None, margins=16, spacing=10, horizontal=False):
    frame = QFrame(parent)
    frame.setObjectName("Card")
    layout = (QHBoxLayout if horizontal else QVBoxLayout)(frame)
    layout.setContentsMargins(margins, margins, margins, margins)
    layout.setSpacing(spacing)
    return frame, layout


def label(text="", object_name=None, wrap=False, selectable=False):
    lbl = QLabel(text)
    if object_name:
        lbl.setObjectName(object_name)
    lbl.setWordWrap(wrap)
    if selectable:
        lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lbl


def button(text, icon_name=None, object_name=None, color=None):
    btn = QPushButton(text)
    if icon_name:
        btn.setIcon(theme.icon(icon_name, color or ("#ffffff" if object_name == "Primary" else "#8a94a6"), 16))
    if object_name:
        btn.setObjectName(object_name)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    return btn


def show_status(widget, message, timeout=5000):
    """Show a message in the status bar of the widget's main window, if it has one."""
    from PySide6.QtWidgets import QMainWindow

    win = widget.window()
    if isinstance(win, QMainWindow):
        win.statusBar().showMessage(message, timeout)


def page_header(title, subtitle=""):
    box = QVBoxLayout()
    box.setSpacing(2)
    box.addWidget(label(title, "PageTitle"))
    if subtitle:
        box.addWidget(label(subtitle, "PageSubtitle", wrap=True))
    return box


def human_size(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def human_time(value):
    if not value:
        return "-"
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return str(value)


class VerdictBadge(QLabel):
    def __init__(self, verdict="unknown", parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_verdict(verdict)

    def set_verdict(self, verdict):
        verdict = (verdict or "unknown").lower()
        c = QColor(theme.VERDICT_COLORS.get(verdict, theme.VERDICT_COLORS["unknown"]))
        rgb = f"{c.red()},{c.green()},{c.blue()}"
        self.setText(verdict.upper())
        # rgba(): Qt reads 8-digit hex as #AARRGGBB, not #RRGGBBAA
        self.setStyleSheet(
            f"QLabel {{ color: rgb({rgb}); background: rgba({rgb},0.12); border: 1px solid rgba({rgb},0.45);"
            f" border-radius: 10px; padding: 3px 10px; font-weight: 700; font-size: 11px; letter-spacing: 1px; }}"
        )


class ScoreGauge(QWidget):
    """Circular 0-100 gauge coloured by verdict."""

    def __init__(self, size=120, parent=None):
        super().__init__(parent)
        self._score = 0
        self._verdict = "unknown"
        self._size = size
        self.setFixedSize(size, size)

    def set_score(self, score, verdict):
        self._score = max(0, min(100, int(score or 0)))
        self._verdict = verdict or "unknown"
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen_w = self._size * 0.09
        rect = QRectF(pen_w / 2 + 2, pen_w / 2 + 2, self._size - pen_w - 4, self._size - pen_w - 4)
        track = QColor(self.palette().color(self.foregroundRole()))
        track.setAlpha(28)
        p.setPen(QPen(track, pen_w, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(rect, 225 * 16, -270 * 16)
        color = QColor(theme.VERDICT_COLORS.get(self._verdict, theme.VERDICT_COLORS["unknown"]))
        p.setPen(QPen(color, pen_w, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        p.drawArc(rect, 225 * 16, int(-270 * 16 * self._score / 100))
        p.setPen(self.palette().color(self.foregroundRole()))
        f = QFont(self.font())
        f.setPixelSize(int(self._size * 0.26))
        f.setBold(True)
        p.setFont(f)
        p.drawText(
            self.rect().adjusted(0, -int(self._size * 0.06), 0, 0), Qt.AlignmentFlag.AlignCenter, str(self._score)
        )
        f.setPixelSize(max(9, int(self._size * 0.09)))
        f.setBold(False)
        p.setFont(f)
        muted = QColor(self.palette().color(self.foregroundRole()))
        muted.setAlpha(140)
        p.setPen(muted)
        p.drawText(self.rect().adjusted(0, int(self._size * 0.32), 0, 0), Qt.AlignmentFlag.AlignCenter, "/ 100")


class StatCard(QFrame):
    def __init__(self, title, value="0", accent=None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(2)
        self.value = label(str(value), "StatValue")
        if accent:
            self.value.setStyleSheet(f"color: {accent};")
        lay.addWidget(label(title, "StatLabel"))
        lay.addWidget(self.value)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_value(self, value):
        self.value.setText(str(value))


class DropZone(QFrame):
    """Dashed drop target that also opens a file picker when clicked."""

    file_selected = Signal(str)
    browse_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(170)
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(6)
        self.icon = QLabel()
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon.setPixmap(theme.icon("analyze", "#7b73ff", 36).pixmap(QSize(36, 36)))
        self.title = label("Drop a sample here", "SectionTitle")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hint = label(
            "or click to browse. Any file type; it is copied into the VM, never run on this host.", "Muted", wrap=True
        )
        self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for w in (self.icon, self.title, self.hint):
            lay.addWidget(w)
        self._set_active(False)

    def _set_active(self, active):
        c = "#7b73ff" if active else "rgba(128,128,140,0.45)"
        bg = "rgba(123,115,255,0.08)" if active else "transparent"
        self.setStyleSheet(f"DropZone {{ border: 2px dashed {c}; border-radius: 12px; background: {bg}; }}")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.browse_requested.emit()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and any(u.isLocalFile() for u in event.mimeData().urls()):
            event.acceptProposedAction()
            self._set_active(True)

    def dragLeaveEvent(self, _):
        self._set_active(False)

    def dropEvent(self, event):
        self._set_active(False)
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.file_selected.emit(url.toLocalFile())
                break


class StageTracker(QWidget):
    """Vertical list of pipeline stages: pending, active, done, warned or failed."""

    SYMBOLS = {"pending": "○", "active": "◉", "done": "✓", "warn": "!", "failed": "✕", "skipped": "–"}
    COLORS = {
        "pending": None,
        "active": "#7b73ff",
        "done": "#16a34a",
        "warn": "#d97706",
        "failed": "#dc2626",
        "skipped": None,
    }

    def __init__(self, stages, parent=None):
        super().__init__(parent)
        self.stages = stages
        self.rows = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        for key, title in stages:
            row = QHBoxLayout()
            mark = QLabel()
            mark.setFixedWidth(18)
            mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
            text = QLabel(title)
            row.addWidget(mark)
            row.addWidget(text, 1)
            lay.addLayout(row)
            self.rows[key] = (mark, text)
        self.reset()

    def reset(self):
        for key in self.rows:
            self.set_state(key, "pending")

    def set_state(self, key, state):
        if key not in self.rows:
            return
        mark, text = self.rows[key]
        color = self.COLORS.get(state)
        mark.setText(self.SYMBOLS[state])
        style = f"color: {color};" if color else "color: palette(mid);"
        mark.setStyleSheet(style + "font-weight: 700;")
        text.setStyleSheet(
            "font-weight: 600;"
            if state == "active"
            else ("color: palette(mid);" if state in ("pending", "skipped") else "")
        )
        self.states = getattr(self, "states", {})
        self.states[key] = state

    def state(self, key):
        return getattr(self, "states", {}).get(key)


class LogView(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Log")
        self.setReadOnly(True)
        self.setMaximumBlockCount(5000)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)

    def append_line(self, msg, severity="INFO"):
        fmt = QTextCharFormat()
        color = theme.SEVERITY_COLORS.get(severity)
        if color:
            fmt.setForeground(QColor(color))
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        stamp = datetime.now().strftime("%H:%M:%S")
        cursor.insertText(f"{stamp}  {msg}\n", fmt)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()


class EmptyState(QWidget):
    def __init__(self, icon_name, title, hint, parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ic = QLabel()
        ic.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ic.setPixmap(theme.icon(icon_name, "#98a2b3", 40).pixmap(QSize(40, 40)))
        t = label(title, "SectionTitle")
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        h = label(hint, "Muted", wrap=True)
        h.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for w in (ic, t, h):
            lay.addWidget(w)
