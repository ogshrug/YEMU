from gi.repository import Gtk, Adw

class ReportView(Gtk.Box):
    def __init__(self, **kwargs):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10, **kwargs)
        self.set_margin_all(20)

        self.append(Gtk.Label(label="Analysis Report Details"))

        # IOC Table
        self.ioc_list = Gtk.ListBox()
        self.ioc_list.set_selection_mode(Gtk.SelectionMode.NONE)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_child(self.ioc_list)
        self.append(scrolled)

        export_btn = Gtk.Button(label="Export to PDF")
        self.append(export_btn)

    def add_ioc(self, ioc_type, value):
        row = Adw.ActionRow(title=value, subtitle=ioc_type)
        self.ioc_list.append(row)
