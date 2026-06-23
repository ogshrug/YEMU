import sys
import os
import gi
import logging

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, Gdk

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("main")

def load_css():
    css = """
.sidebar {
    background-color: @sidebar_bg_color;
    border-right: 1px solid @borders;
    padding: 10px;
}
.card {
    background-color: @card_bg_color;
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 2px 6px rgba(0,0,0,0.1);
}
.h1 { font-size: 32px; font-weight: bold; }
.h2 { font-size: 18px; font-weight: bold; }
.caption { font-size: 10px; opacity: 0.7; text-transform: uppercase; letter-spacing: 1px; }
.terminal { font-family: monospace; font-size: 11px; background-color: @theme_bg_color; }
"""
    try:
        style_provider = Gtk.CssProvider()
        style_provider.load_from_string(css)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            style_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
    except Exception as e:
        logger.warning(f"Could not load CSS: {e}")

class MalwareSandboxApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(application_id='com.jules.malwaresandbox',
                         flags=Gio.ApplicationFlags.FLAGS_NONE,
                         **kwargs)

    def do_activate(self):
        from ui.main_window import MainWindow

        load_css()

        win = MainWindow(application=self)
        win.present()

if __name__ == "__main__":
    app = MalwareSandboxApp()
    sys.exit(app.run(sys.argv))
