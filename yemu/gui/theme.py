"""Colours, stylesheet and line icons for the YEMU desktop app."""
from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QColor, QGuiApplication, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer

LIGHT = {
    "bg": "#f5f6f8", "surface": "#ffffff", "surface_alt": "#f0f2f5", "border": "#e2e5ea",
    "text": "#1b2230", "muted": "#687385", "accent": "#4f46e5", "accent_text": "#ffffff",
    "accent_soft": "#eceafd", "sidebar": "#111827", "sidebar_text": "#c9cfda",
    "sidebar_active": "#1f2937", "code_bg": "#fbfbfc",
}
DARK = {
    "bg": "#0e1015", "surface": "#161a21", "surface_alt": "#1c212a", "border": "#262c37",
    "text": "#e6e8ee", "muted": "#98a2b3", "accent": "#7b73ff", "accent_text": "#ffffff",
    "accent_soft": "#25234a", "sidebar": "#0a0c10", "sidebar_text": "#aeb6c4",
    "sidebar_active": "#1a1f29", "code_bg": "#12151b",
}

VERDICT_COLORS = {
    "clean": "#16a34a",
    "suspicious": "#d97706",
    "malicious": "#dc2626",
    "manual": "#2563eb",
    "unknown": "#6b7280",
}
SEVERITY_COLORS = {"INFO": None, "WARN": "#d97706", "CRITICAL": "#dc2626"}

# Minimal 24px line icons (feather-style); "currentColor" is replaced at render time
_ICONS = {
    "analyze": '<path d="M12 3v12M7 8l5-5 5 5"/><path d="M5 15v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4"/>',
    "history": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "rules": '<path d="M4 4h16v16H4z"/><path d="M8 9h8M8 13h8M8 17h5"/>',
    "vms": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>',
    "file": '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/>',
    "play": '<path d="M7 4l13 8-13 8z"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="1"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "refresh": '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>',
    "trash": '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    "monitor": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8"/>',
    "save": '<path d="M5 3h11l5 5v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z"/><path d="M7 3v5h8M7 21v-7h10v7"/>',
    "check": '<path d="M5 12l5 5L20 7"/>',
    "download": '<path d="M12 4v12M7 11l5 5 5-5"/><path d="M5 20h14"/>',
    "back": '<path d="M15 5l-7 7 7 7"/>',
    "folder": '<path d="M3 6a2 2 0 0 1 2-2h4l2 3h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "shield": '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
    "copy": '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
}


def icon(name, color="#8a94a6", size=20):
    body = _ICONS.get(name, _ICONS["file"])
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" '
           f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{body}</svg>')
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    ratio = 2
    pix = QPixmap(size * ratio, size * ratio)
    pix.fill(Qt.transparent)
    painter = QPainter(pix)
    renderer.render(painter)
    painter.end()
    pix.setDevicePixelRatio(ratio)
    return QIcon(pix)


def is_dark(preference="system"):
    if preference in ("light", "dark"):
        return preference == "dark"
    hints = QGuiApplication.styleHints()
    if hasattr(hints, "colorScheme"):
        return hints.colorScheme() == Qt.ColorScheme.Dark
    return QGuiApplication.palette().color(QPalette.Window).lightness() < 128


def colors(preference="system"):
    return DARK if is_dark(preference) else LIGHT


def _check_image():
    """Qt stylesheets need a file for indicator images; write a white checkmark once."""
    from yemu import paths
    path = paths.cache_dir() / "ui" / "check.svg"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#ffffff" '
                        'stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12l5 5L20 7"/></svg>',
                        encoding="utf-8")
    return path.as_posix()


def stylesheet(c):
    check = _check_image()
    return f"""
    * {{ font-family: "Segoe UI", "Inter", "Cantarell", "Noto Sans", "Ubuntu", "Helvetica Neue", Arial, sans-serif; font-size: 13px; }}
    QMainWindow, QWidget#Page, QDialog {{ background: {c['bg']}; color: {c['text']}; }}
    QWidget {{ color: {c['text']}; }}
    QLabel#Muted, QLabel[muted="true"] {{ color: {c['muted']}; }}
    QLabel#PageTitle {{ font-size: 22px; font-weight: 600; }}
    QLabel#PageSubtitle {{ color: {c['muted']}; font-size: 13px; }}
    QLabel#SectionTitle {{ font-size: 14px; font-weight: 600; }}
    QLabel#StatValue {{ font-size: 24px; font-weight: 600; }}
    QLabel#StatLabel {{ color: {c['muted']}; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}

    QFrame#Card {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 10px; }}
    QFrame#Banner {{ background: {c['accent_soft']}; border-radius: 8px; }}
    QFrame#WarnBanner {{ background: rgba(217,119,6,0.12); border: 1px solid rgba(217,119,6,0.35); border-radius: 8px; }}

    QWidget#Sidebar {{ background: {c['sidebar']}; }}
    QLabel#Brand {{ color: #ffffff; font-size: 18px; font-weight: 700; letter-spacing: 2px; }}
    QLabel#BrandSub {{ color: {c['sidebar_text']}; font-size: 11px; }}
    QListWidget#Nav {{ background: transparent; border: none; outline: none; }}
    QListWidget#Nav::item {{ color: {c['sidebar_text']}; padding: 10px 12px; margin: 2px 8px; border-radius: 8px; }}
    QListWidget#Nav::item:hover {{ background: {c['sidebar_active']}; }}
    QListWidget#Nav::item:selected {{ background: {c['accent']}; color: #ffffff; }}
    QLabel#SidebarFooter {{ color: {c['sidebar_text']}; font-size: 11px; }}

    QPushButton {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 7px; padding: 7px 14px; }}
    QPushButton:hover {{ border-color: {c['accent']}; }}
    QPushButton:disabled {{ color: {c['muted']}; background: {c['surface_alt']}; }}
    QPushButton#Primary {{ background: {c['accent']}; color: {c['accent_text']}; border: none; font-weight: 600; }}
    QPushButton#Primary:hover {{ background: {c['accent']}; }}
    QPushButton#Primary:disabled {{ background: {c['border']}; color: {c['muted']}; }}
    QPushButton#Danger {{ color: #dc2626; }}
    QPushButton#Flat {{ background: transparent; border: none; padding: 4px 8px; }}

    QSpinBox {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 7px; padding: 5px 4px 5px 8px; min-height: 20px; }}
    QSpinBox:focus {{ border-color: {c['accent']}; }}
    QLineEdit, QComboBox, QPlainTextEdit, QTextEdit {{
        background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 7px; padding: 6px 8px;
        selection-background-color: {c['accent']}; selection-color: #ffffff; }}
    QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {{ border-color: {c['accent']}; }}
    QComboBox::drop-down {{ border: none; width: 22px; }}
    QComboBox QAbstractItemView {{ background: {c['surface']}; border: 1px solid {c['border']}; selection-background-color: {c['accent_soft']}; selection-color: {c['text']}; }}
    QPlainTextEdit#Code, QPlainTextEdit#Log, QTextEdit#Code {{ background: {c['code_bg']}; font-family: "Cascadia Mono", "JetBrains Mono", "DejaVu Sans Mono", Consolas, monospace; font-size: 12px; }}

    QCheckBox {{ spacing: 8px; }}
    QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {c['muted']}; border-radius: 4px; background: {c['surface']}; }}
    QCheckBox::indicator:hover {{ border-color: {c['accent']}; }}
    QCheckBox::indicator:checked {{ background: {c['accent']}; border-color: {c['accent']}; image: url({check}); }}
    QTableView, QTreeWidget, QListWidget#Plain {{ background: {c['surface']}; border: 1px solid {c['border']}; border-radius: 8px;
        gridline-color: {c['border']}; alternate-background-color: {c['surface_alt']};
        selection-background-color: {c['accent_soft']}; selection-color: {c['text']}; }}
    QHeaderView::section {{ background: {c['surface_alt']}; color: {c['muted']}; border: none; border-bottom: 1px solid {c['border']};
        padding: 6px 8px; font-weight: 600; font-size: 11px; }}
    QTabWidget::pane {{ border: 1px solid {c['border']}; border-radius: 8px; background: {c['surface']}; top: -1px; }}
    QTabBar::tab {{ background: transparent; color: {c['muted']}; padding: 8px 14px; border: none; border-bottom: 2px solid transparent; }}
    QTabBar::tab:selected {{ color: {c['text']}; border-bottom: 2px solid {c['accent']}; }}
    QProgressBar {{ background: {c['surface_alt']}; border: none; border-radius: 4px; height: 8px; text-align: center; color: transparent; }}
    QProgressBar::chunk {{ background: {c['accent']}; border-radius: 4px; }}
    QStatusBar {{ background: {c['surface']}; border-top: 1px solid {c['border']}; color: {c['muted']}; }}
    QScrollArea {{ border: none; background: transparent; }}
    QSplitter::handle {{ background: {c['border']}; }}
    QToolTip {{ background: {c['surface']}; color: {c['text']}; border: 1px solid {c['border']}; padding: 4px; }}
    """


def apply(app, preference="system"):
    c = colors(preference)
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(c["bg"]))
    pal.setColor(QPalette.WindowText, QColor(c["text"]))
    pal.setColor(QPalette.Base, QColor(c["surface"]))
    pal.setColor(QPalette.AlternateBase, QColor(c["surface_alt"]))
    pal.setColor(QPalette.Text, QColor(c["text"]))
    pal.setColor(QPalette.Button, QColor(c["surface"]))
    pal.setColor(QPalette.ButtonText, QColor(c["text"]))
    pal.setColor(QPalette.Highlight, QColor(c["accent"]))
    pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.PlaceholderText, QColor(c["muted"]))
    pal.setColor(QPalette.ToolTipBase, QColor(c["surface"]))
    pal.setColor(QPalette.ToolTipText, QColor(c["text"]))
    app.setPalette(pal)
    app.setStyleSheet(stylesheet(c))
    return c
