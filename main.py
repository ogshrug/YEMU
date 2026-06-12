import sys
import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, Adw, Gio, Gdk

class MalwareSandboxApp(Adw.Application):
    def __init__(self, **kwargs):
        super().__init__(application_id='com.jules.malwaresandbox',
                         flags=Gio.ApplicationFlags.FLAGS_NONE,
                         **kwargs)

    def do_activate(self):
        from ui.main_window import MainWindow

        # Load CSS
        style_provider = Gtk.CssProvider()
        style_provider.load_from_path('assets/style.css')
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            style_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        win = MainWindow(application=self)
        win.present()

if __name__ == "__main__":
    app = MalwareSandboxApp()
    sys.exit(app.run(sys.argv))
