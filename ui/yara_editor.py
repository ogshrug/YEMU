from gi.repository import Gtk

class YaraEditor(Gtk.Box):
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, **kwargs)
        self.set_margin_all(20)

        # Header
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.append(header)

        label = Gtk.Label(label="YARA Rule Editor")
        label.add_css_class("h2")
        header.append(label)

        save_btn = Gtk.Button(label="Save Rule")
        save_btn.set_halign(Gtk.Align.END)
        save_btn.set_hexpand(True)
        header.append(save_btn)

        # Editor (Simplified - GtkSourceView would be better if available)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        self.append(scrolled)

        self.text_view = Gtk.TextView()
        self.text_view.set_monospace(True)
        scrolled.set_child(self.text_view)

        # Status
        self.status_label = Gtk.Label(label="Ready")
        self.append(self.status_label)
